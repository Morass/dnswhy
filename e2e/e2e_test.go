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
