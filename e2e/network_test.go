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
	ip := net.ParseIP(address).To4()
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
			if qtype == 1 { // A
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				reply = append(reply, ip...)
			} else {
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
		"--timeout", "2s"}

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
		"--resolver-dir", filepath.Join(dir, "none"), "--timeout", "2s")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if n := def.asked.Load(); n != 0 {
		t.Errorf("a pinned name was sent to a nameserver %d times:\n%s", n, got.stdout)
	}
}
