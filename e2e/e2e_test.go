// Package e2e drives the real binary the way a person does: with a sandboxed
// HOME, an allow-listed environment, and captured machine state instead of the
// machine, so the same run happens on any computer.
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binary string

func TestMain(m *testing.M) {
	if b := os.Getenv("DNSWHY_BIN"); b != "" {
		binary = b
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "dnswhy-e2e")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "dnswhy")
	build := exec.Command("go", "build", "-o", binary, "../cmd/dnswhy")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

// runIn runs the binary with nothing of the caller's environment except a
// sandboxed HOME and a PATH, so no personal setting can change the output.
func runIn(t *testing.T, args ...string) result {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"NO_COLOR=1",
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func fixtures(name string) []string {
	return []string{
		"--scutil-file", filepath.Join("..", "testdata", name),
		"--resolver-dir", filepath.Join("..", "testdata", "resolver-dir"),
		"--hosts-file", filepath.Join("..", "testdata", "hosts"),
		"--offline",
	}
}

func explain(t *testing.T, name string, extra ...string) result {
	t.Helper()
	return runIn(t, append(append([]string{name}, fixtures("vpn.scutil")...), extra...)...)
}

func TestExplainScopedName(t *testing.T) {
	got := explain(t, "files.corp.internal")
	if got.code != 0 {
		t.Fatalf("exit %d, stderr: %s", got.code, got.stderr)
	}
	for _, want := range []string{
		"Question  files.corp.internal",
		"resolver #3  corp.internal",
		"wins",
		"nameserver 198.51.100.53",
		"dig @198.51.100.53 files.corp.internal",
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("output is missing %q:\n%s", want, got.stdout)
		}
	}
}

func TestExplainIsQuietWhenOffline(t *testing.T) {
	got := explain(t, "files.corp.internal")
	if strings.Contains(got.stdout, "Answers") {
		t.Errorf("--offline must ask nothing:\n%s", got.stdout)
	}
}

func TestExplainHostsPin(t *testing.T) {
	got := explain(t, "pinned.corp.internal")
	if !strings.Contains(got.stdout, "line 6: 198.51.100.9") {
		t.Errorf("the hosts entry and its line must be shown:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "No nameserver is asked at all") {
		t.Errorf("the verdict must explain that no nameserver is asked:\n%s", got.stdout)
	}
}

func TestExplainBonjourName(t *testing.T) {
	got := explain(t, "printer.local")
	if !strings.Contains(got.stdout, "multicast DNS (Bonjour)") {
		t.Errorf("a .local name must be explained as Bonjour:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "dns-sd -G v4 printer.local") {
		t.Errorf("the verdict must offer the Bonjour command:\n%s", got.stdout)
	}
}

func TestExplainJSONIsValidAndComplete(t *testing.T) {
	got := explain(t, "build.dev.corp.internal", "--json")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	var doc struct {
		Result struct {
			Query  string `json:"query"`
			Winner struct {
				Index  int    `json:"index"`
				Domain string `json:"domain"`
			} `json:"winner"`
			Mechanism string `json:"mechanism"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, got.stdout)
	}
	if doc.Result.Query != "build.dev.corp.internal" {
		t.Errorf("query = %q", doc.Result.Query)
	}
	if doc.Result.Winner.Domain != "dev.corp.internal" || doc.Result.Winner.Index != 4 {
		t.Errorf("winner = %+v, want the dev.corp.internal scope", doc.Result.Winner)
	}
	if doc.Result.Mechanism != "unicast" {
		t.Errorf("mechanism = %q", doc.Result.Mechanism)
	}
}

func TestFlagsMayFollowTheName(t *testing.T) {
	a := explain(t, "files.corp.internal", "--json")
	b := runIn(t, append([]string{"--json"}, append(fixtures("vpn.scutil"), "files.corp.internal")...)...)
	if a.stdout != b.stdout {
		t.Errorf("a flag after the name must behave like one before it:\n%s\n---\n%s", a.stdout, b.stdout)
	}
}

func TestDoctorExitsOneWhenSomethingIsWorthFixing(t *testing.T) {
	got := runIn(t, append([]string{"doctor"}, fixtures("vpn.scutil")...)...)
	if got.code != 1 {
		t.Errorf("exit = %d, want 1 when there are warnings:\n%s", got.code, got.stdout)
	}
	if !strings.Contains(got.stdout, "worth fixing") {
		t.Errorf("doctor must summarise:\n%s", got.stdout)
	}
}

func TestDoctorExitsZeroOnACleanConfiguration(t *testing.T) {
	got := runIn(t, "doctor",
		"--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--resolver-dir", filepath.Join(t.TempDir(), "empty"),
		"--hosts-file", filepath.Join(t.TempDir(), "none"),
	)
	if got.code != 0 {
		t.Errorf("exit = %d on a clean configuration:\n%s", got.code, got.stdout)
	}
}

func TestDoctorJSON(t *testing.T) {
	got := runIn(t, append([]string{"doctor", "--json"}, fixtures("vpn.scutil")...)...)
	var doc struct {
		Findings []struct {
			Level string `json:"level"`
			Title string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, got.stdout)
	}
	if len(doc.Findings) == 0 {
		t.Fatal("no findings in the JSON")
	}
	for _, f := range doc.Findings {
		switch f.Level {
		case "ok", "note", "warn":
		default:
			t.Errorf("finding %q has level %q", f.Title, f.Level)
		}
	}
}

func TestHelpForEveryCommand(t *testing.T) {
	top := runIn(t, "--help")
	if top.code != 0 || !strings.Contains(top.stdout, "dnswhy <name>") {
		t.Errorf("--help: exit %d\n%s", top.code, top.stdout)
	}
	for _, cmd := range []string{"explain", "doctor", "version"} {
		got := runIn(t, "help", cmd)
		if got.code != 0 || len(got.stdout) < 40 {
			t.Errorf("help %s: exit %d, output %q", cmd, got.code, got.stdout)
		}
	}
	if got := runIn(t, "doctor", "--help"); got.code != 0 || !strings.Contains(got.stdout+got.stderr, "dnswhy doctor") {
		t.Errorf("doctor --help: exit %d\n%s%s", got.code, got.stdout, got.stderr)
	}
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	got := runIn(t)
	if got.code != 2 {
		t.Errorf("exit = %d, want 2", got.code)
	}
	if !strings.Contains(got.stdout, "Usage:") {
		t.Errorf("usage should be printed:\n%s", got.stdout)
	}
}

func TestUnreadableScutilFileIsAClearError(t *testing.T) {
	got := runIn(t, "example.com", "--scutil-file", filepath.Join(t.TempDir(), "missing"))
	if got.code != 1 {
		t.Errorf("exit = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "dnswhy:") {
		t.Errorf("stderr should name the tool and the problem: %q", got.stderr)
	}
}

func TestVersionIsPrinted(t *testing.T) {
	got := runIn(t, "version")
	if got.code != 0 || !strings.HasPrefix(got.stdout, "dnswhy ") {
		t.Errorf("version: exit %d, %q", got.code, got.stdout)
	}
}

// Nothing the tool prints may leak the environment it ran in.
func TestOutputCarriesNoEnvironment(t *testing.T) {
	got := explain(t, "files.corp.internal")
	for _, bad := range []string{os.Getenv("USER"), "/Users/"} {
		if bad != "" && strings.Contains(got.stdout, bad) {
			t.Errorf("output mentions %q:\n%s", bad, got.stdout)
		}
	}
}

// A hostname is the only thing the tool accepts: control characters would be
// replayed into the terminal, and shell metacharacters would end up inside the
// dig command the tool tells the reader to copy.
func TestHostileNamesAreRejected(t *testing.T) {
	for _, name := range []string{
		"evil\x1b[2Jexample.com",
		"$(id).local",
		"a b.example",
		"example..com",
		"-e; rm -rf /",
	} {
		got := explain(t, name)
		if got.code != 2 {
			t.Errorf("%q: exit = %d, want 2\n%s%s", name, got.code, got.stdout, got.stderr)
		}
		if strings.Contains(got.stdout, "\x1b[2J") {
			t.Errorf("%q: a control sequence reached stdout", name)
		}
	}
}

func TestDoctorJSONStillExitsOne(t *testing.T) {
	got := runIn(t, append([]string{"doctor", "--json"}, fixtures("vpn.scutil")...)...)
	if got.code != 1 {
		t.Errorf("exit = %d, want 1: the format must not change the status", got.code)
	}
}

func TestNonPositiveTimeoutIsRejected(t *testing.T) {
	got := explain(t, "example.com", "--timeout", "0s")
	if got.code != 2 {
		t.Errorf("exit = %d, want 2", got.code)
	}
}

// A resolver directory is only ever read: a symlink there would print whatever
// it points at, and a fifo would block forever.
func TestResolverDirectoryReadsOnlyOrdinaryFiles(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("password hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvers := filepath.Join(dir, "resolver")
	if err := os.Mkdir(resolvers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(resolvers, "corp.internal")); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "doctor", "--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--resolver-dir", resolvers, "--hosts-file", filepath.Join(dir, "no-hosts"))
	if strings.Contains(got.stdout, "hunter2") || strings.Contains(got.stdout, "password") {
		t.Errorf("the contents of a linked file were printed:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "symbolic link") {
		t.Errorf("the link should be reported as not read:\n%s", got.stdout)
	}
}

// An unrecognised line in a resolver file may be anything at all, so only its
// first word is ever shown.
func TestUnknownResolverLinesAreNotEchoed(t *testing.T) {
	dir := t.TempDir()
	resolvers := filepath.Join(dir, "resolver")
	if err := os.Mkdir(resolvers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolvers, "corp.internal"), []byte("token abcd-secret-value\nnameserver 198.51.100.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "doctor", "--scutil-file", filepath.Join("..", "testdata", "vpn.scutil"),
		"--resolver-dir", resolvers, "--hosts-file", filepath.Join(dir, "no-hosts"))
	if strings.Contains(got.stdout, "abcd-secret-value") {
		t.Errorf("the rest of an unknown line was printed:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "token") {
		t.Errorf("the unknown keyword should still be named:\n%s", got.stdout)
	}
}

// A hosts line that does not start with an address is ignored by the system
// resolver, so it must not be reported as the answer.
func TestInvalidHostsLineIsNotAnAnswer(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("not-an-address example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "example.com", "--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--hosts-file", hosts, "--resolver-dir", filepath.Join(dir, "none"), "--offline")
	if strings.Contains(got.stdout, "Answered from") {
		t.Errorf("an invalid hosts line was treated as an answer:\n%s", got.stdout)
	}
	doc := runIn(t, "doctor", "--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--hosts-file", hosts, "--resolver-dir", filepath.Join(dir, "none"))
	if !strings.Contains(doc.stdout, "does not start with an address") {
		t.Errorf("doctor should report the line:\n%s", doc.stdout)
	}
}

// After a hosts file answers, nothing about the resolver that would otherwise
// have been asked belongs in the verdict.
func TestHostsAnswerDoesNotDragInScopeWarnings(t *testing.T) {
	got := explain(t, "pinned.corp.internal")
	if strings.Contains(got.stdout, "does not fall back") {
		t.Errorf("a hosts answer cannot also fail in a scope:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "No nameserver is asked at all") {
		t.Errorf("the hosts verdict is missing:\n%s", got.stdout)
	}
}

// A file the tool is pointed at must be an ordinary file of a sane size:
// /dev/zero would otherwise be read until memory ran out.
func TestEndlessFilesAreRefused(t *testing.T) {
	sane := filepath.Join("..", "testdata", "simple.scutil")
	for _, flag := range []string{"--scutil-file", "--hosts-file"} {
		args := []string{"example.com", flag, "/dev/zero", "--offline"}
		if flag != "--scutil-file" {
			args = append(args, "--scutil-file", sane)
		}
		got := runIn(t, args...)
		if got.code != 1 {
			t.Errorf("%s /dev/zero: exit = %d, want 1", flag, got.code)
		}
		if !strings.Contains(got.stderr, "ordinary file") {
			t.Errorf("%s /dev/zero: stderr = %q", flag, got.stderr)
		}
	}
}

// A scope that claims the name but lists no nameserver must be explained, not
// left as a half-finished sentence.
func TestScopeWithoutANameserverIsExplained(t *testing.T) {
	got := explain(t, "foo.search.only")
	out := got.stdout
	if strings.Contains(out, "To ask what your\n") && !strings.Contains(out, "name the server yourself") {
		t.Errorf("the verdict stops mid-sentence:\n%s", out)
	}
	if strings.Contains(out, "there is no default nameserver") {
		t.Errorf("there is a default nameserver in this fixture:\n%s", out)
	}
	if !strings.Contains(out, "cannot answer") {
		t.Errorf("the scope that cannot answer should be named:\n%s", out)
	}
}

// A hosts file can hold anything: whatever is in it is shown, never executed
// by the reader's terminal.
func TestTerminalEscapesFromAFileAreShownNotExecuted(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	line := "203.0.113.1 \x1b[2J\x1b[Hevil.example\n203.0.113.2 \x1b[2J\x1b[Hevil.example\n"
	if err := os.WriteFile(hosts, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "doctor", "--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--hosts-file", hosts, "--resolver-dir", filepath.Join(dir, "none"))
	if strings.Contains(got.stdout, "\x1b[2J") {
		t.Errorf("an escape sequence from a file reached the terminal:\n%q", got.stdout)
	}
	if !strings.Contains(got.stdout, `\x1b`) {
		t.Errorf("the escape should be shown as text:\n%s", got.stdout)
	}
}

// A file in the resolver directory is read only if it could be a resolver file.
func TestOversizedResolverFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	resolvers := filepath.Join(dir, "resolver")
	if err := os.Mkdir(resolvers, 0o700); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(resolvers, "corp.internal"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "doctor", "--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--resolver-dir", resolvers, "--hosts-file", filepath.Join(dir, "none"))
	if !strings.Contains(got.stdout, "not a resolver file") {
		t.Errorf("an oversized file should be refused and reported:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "xxxxxxxx") {
		t.Errorf("its contents were printed:\n%s", got.stdout[:200])
	}
}

// A hosts file too large to be one is refused rather than read in part: a
// truncated hosts file answers different names than the real one.
func TestOversizedHostsFileIsRefusedNotTruncated(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	f, err := os.Create(hosts)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(9 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got := runIn(t, "example.com", "--scutil-file", filepath.Join("..", "testdata", "simple.scutil"),
		"--hosts-file", hosts, "--resolver-dir", filepath.Join(dir, "none"), "--offline")
	if got.code != 1 || !strings.Contains(got.stderr, "not a hosts file") {
		t.Errorf("exit %d, stderr %q", got.code, got.stderr)
	}
}
