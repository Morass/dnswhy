package e2e

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeNameserver answers every A question with one address and counts the
// questions it was asked, so a test can prove which servers dnswhy talked to.
type fakeNameserver struct {
	addr    string
	asked   atomic.Int32
	answers chan string
}

func startNameserver(t *testing.T, address string) *fakeNameserver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	ns := &fakeNameserver{addr: pc.LocalAddr().String(), answers: make(chan string, 16)}
	// An empty address means the server answers "this name does not exist".
	var ip net.IP
	if address != "" {
		ip = net.ParseIP(address).To4()
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := make([]byte, n)
			copy(q, buf[:n])
			ns.asked.Add(1)
			if len(q) < 13 {
				continue
			}
			// id, response + recursion, one question, one answer
			reply := []byte{q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
			reply = append(reply, q[12:]...)
			qtype := q[len(q)-4]<<0 | q[len(q)-3]
			switch {
			case ip == nil:
				reply[3] = 0x83 // NXDOMAIN
				reply[7] = 0
			case qtype == 1: // A
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				reply = append(reply, ip...)
			default:
				reply[7] = 0 // no answers for anything else
			}
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return ns
}

// A name that a private scope claims must not be sent to the default
// nameserver, which is usually a public one: that would hand an internal
// hostname to a stranger. --compare is the way to ask anyway.
func TestPrivateNamesAreNotSentToTheDefaultNameserver(t *testing.T) {
	def := startNameserver(t, "203.0.113.1")
	scope := startNameserver(t, "198.51.100.9")
	dump := filepath.Join(t.TempDir(), "state.txt")
	content := fmt.Sprintf(`DNS configuration

resolver #1
  nameserver[0] : %s
  reach : 0x00000002 (Reachable)

resolver #2
  domain : corp.internal
  nameserver[0] : %s
  reach : 0x00000002 (Reachable)
  order : 200000
`, def.addr, scope.addr)
	if err := os.WriteFile(dump, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	args := []string{"host.corp.internal", "--scutil-file", dump,
		"--resolver-dir", filepath.Join(empty, "resolver"), "--hosts-file", filepath.Join(empty, "hosts"),
		"--timeout", "2s", "--live"}

	got := runIn(t, args...)
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if n := scope.asked.Load(); n == 0 {
		t.Error("the scope that claims the name should have been asked")
	}
	if n := def.asked.Load(); n != 0 {
		t.Errorf("the default nameserver was asked %d times about a private name:\n%s", n, got.stdout)
	}

	before := def.asked.Load()
	got = runIn(t, append(args, "--compare")...)
	if def.asked.Load() <= before {
		t.Errorf("--compare must ask the default nameserver as well:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "198.51.100.9") {
		t.Errorf("the scope's answer should be shown:\n%s", got.stdout)
	}
}

// A name answered from the hosts file reaches no nameserver at all, so dnswhy
// must not send it anywhere either.
func TestHostsPinnedNamesAreNotSentAnywhere(t *testing.T) {
	def := startNameserver(t, "203.0.113.1")
	dir := t.TempDir()
	dump := filepath.Join(dir, "state.txt")
	content := fmt.Sprintf("DNS configuration\n\nresolver #1\n  nameserver[0] : %s\n  reach : 0x00000002 (Reachable)\n", def.addr)
	if err := os.WriteFile(dump, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("203.0.113.50 pinned.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "pinned.example", "--scutil-file", dump, "--hosts-file", hosts,
		"--resolver-dir", filepath.Join(dir, "none"), "--timeout", "2s", "--live")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if n := def.asked.Load(); n != 0 {
		t.Errorf("a pinned name was sent to a nameserver %d times:\n%s", n, got.stdout)
	}
}

// A configuration read from a file describes another machine, so nothing is
// asked unless --live says to.
func TestReplayedConfigurationAsksNothing(t *testing.T) {
	ns := startNameserver(t, "203.0.113.1")
	dir := t.TempDir()
	dump := filepath.Join(dir, "state.txt")
	content := fmt.Sprintf("DNS configuration\n\nresolver #1\n  nameserver[0] : %s\n  reach : 0x00000002 (Reachable)\n", ns.addr)
	if err := os.WriteFile(dump, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "example.com", "--scutil-file", dump, "--timeout", "2s")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if n := ns.asked.Load(); n != 0 {
		t.Errorf("a replayed configuration asked %d question(s):\n%s", n, got.stdout)
	}
	if strings.Contains(got.stdout, "Answers") {
		t.Errorf("nothing was asked, so there is nothing to report:\n%s", got.stdout)
	}
	live := runIn(t, "example.com", "--scutil-file", dump, "--timeout", "2s", "--live")
	if ns.asked.Load() == 0 {
		t.Errorf("--live must resolve for real:\n%s", live.stdout)
	}
}

// --compare asks the default nameserver, but only for a name a nameserver
// would ever have been asked about.
func TestCompareStillRespectsHostsAndBonjour(t *testing.T) {
	def := startNameserver(t, "203.0.113.1")
	dir := t.TempDir()
	dump := filepath.Join(dir, "state.txt")
	content := fmt.Sprintf(`DNS configuration

resolver #1
  nameserver[0] : %s
  reach : 0x00000002 (Reachable)

resolver #2
  domain : local
  options : mdns
  order : 300000
`, def.addr)
	if err := os.WriteFile(dump, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("203.0.113.50 pinned.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"printer.local", "pinned.example"} {
		got := runIn(t, name, "--scutil-file", dump, "--hosts-file", hosts,
			"--resolver-dir", filepath.Join(dir, "none"), "--timeout", "2s", "--live", "--compare")
		if n := def.asked.Load(); n != 0 {
			t.Errorf("--compare sent %q to a nameserver %d time(s):\n%s", name, n, got.stdout)
		}
	}
}

// macOS stops at the first search-domain expansion that answers, so dnswhy
// must not hand the later ones to nameservers that would never have seen them.
func TestExpansionsStopAtTheFirstAnswer(t *testing.T) {
	first := startNameserver(t, "198.51.100.9")
	second := startNameserver(t, "203.0.113.9")
	dir := t.TempDir()
	dump := filepath.Join(dir, "state.txt")
	content := fmt.Sprintf(`DNS configuration

resolver #1
  nameserver[0] : %s
  search domain[0] : first.example
  search domain[1] : second.example
  reach : 0x00000002 (Reachable)

resolver #2
  domain : first.example
  nameserver[0] : %s
  reach : 0x00000002 (Reachable)
  order : 200000

resolver #3
  domain : second.example
  nameserver[0] : %s
  reach : 0x00000002 (Reachable)
  order : 200100
`, first.addr, first.addr, second.addr)
	if err := os.WriteFile(dump, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "build", "--scutil-file", dump, "--hosts-file", filepath.Join(dir, "none"),
		"--resolver-dir", filepath.Join(dir, "none"), "--timeout", "2s", "--live")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if second.asked.Load() != 0 {
		t.Errorf("the second expansion was asked although the first answered:\n%s", got.stdout)
	}
	if first.asked.Load() == 0 {
		t.Errorf("the first expansion should have been asked:\n%s", got.stdout)
	}
}

// A nameserver that says the name does not exist has answered; the next one in
// the list is not asked for a second opinion the resolver would not seek.
func TestANegativeAnswerEndsTheQuestion(t *testing.T) {
	saysNo := startNameserver(t, "")
	backup := startNameserver(t, "203.0.113.2")
	dir := t.TempDir()
	dump := filepath.Join(dir, "state.txt")
	content := fmt.Sprintf(`DNS configuration

resolver #1
  nameserver[0] : %s
  nameserver[1] : %s
  reach : 0x00000002 (Reachable)
`, saysNo.addr, backup.addr)
	if err := os.WriteFile(dump, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, "absent.example", "--scutil-file", dump, "--hosts-file", filepath.Join(dir, "none"),
		"--resolver-dir", filepath.Join(dir, "none"), "--timeout", "2s", "--live")
	if saysNo.asked.Load() == 0 {
		t.Fatalf("the first nameserver was never asked:\n%s", got.stdout)
	}
	if backup.asked.Load() != 0 {
		t.Errorf("the second nameserver was asked after the first answered:\n%s", got.stdout)
	}
}
