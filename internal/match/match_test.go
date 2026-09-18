package match

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/hostsfile"
)

func fixture(t *testing.T, name string) dnsconf.Config {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return dnsconf.Parse(string(b))
}

func hosts(t *testing.T) hostsfile.File {
	t.Helper()
	f, err := hostsfile.Load(filepath.Join("..", "..", "testdata", "hosts"))
	if err != nil {
		t.Fatalf("reading hosts: %v", err)
	}
	return f
}

func TestWinnerPerName(t *testing.T) {
	cfg := fixture(t, "vpn.scutil")
	none := hostsfile.File{Path: "/etc/hosts"}
	cases := []struct {
		name      string
		wantIndex int
		wantMech  Mechanism
	}{
		{"example.com", 1, Unicast},                    // nothing claims it: the default
		{"files.corp.internal", 3, Unicast},            // the scope claims it
		{"corp.internal", 3, Unicast},                  // the domain itself
		{"build.dev.corp.internal", 4, Unicast},        // the more specific scope wins
		{"printer.local", 2, Multicast},                // Bonjour
		{"notcorp.internal", 1, Unicast},               // a suffix that is not on a label boundary
		{"corp.internal.example.com", 1, Unicast},      // the domain in the middle claims nothing
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Explain(cfg, none, c.name)
			if got.Winner == nil {
				t.Fatalf("no winner for %s", c.name)
			}
			if got.Winner.Index != c.wantIndex {
				t.Errorf("winner = resolver #%d, want #%d", got.Winner.Index, c.wantIndex)
			}
			if got.Mechanism != c.wantMech {
				t.Errorf("mechanism = %q, want %q", got.Mechanism, c.wantMech)
			}
		})
	}
}

func TestLowerOrderWinsAtEqualSpecificity(t *testing.T) {
	cfg := fixture(t, "conflict.scutil")
	got := Explain(cfg, hostsfile.File{}, "host.shared.example")
	if got.Winner == nil || got.Winner.Index != 3 {
		t.Fatalf("winner = %v, want resolver #3 (order 101000 beats 150000)", got.Winner)
	}
	if !got.Candidates[0].Wins {
		t.Error("the winner must be displayed first")
	}
}

func TestHostsEndsTheLookup(t *testing.T) {
	cfg := fixture(t, "vpn.scutil")
	got := Explain(cfg, hosts(t), "pinned.corp.internal")
	if got.Mechanism != FromHosts {
		t.Fatalf("mechanism = %q, want %q", got.Mechanism, FromHosts)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].Address != "198.51.100.9" {
		t.Errorf("hosts entries = %+v", got.Hosts)
	}
	// The scope still matches; it is simply never reached, and the output says so.
	if got.Winner == nil || got.Winner.Index != 3 {
		t.Errorf("winner = %v, want the corp.internal scope", got.Winner)
	}
}

func TestSingleLabelUsesSearchDomains(t *testing.T) {
	cfg := fixture(t, "vpn.scutil")
	got := Explain(cfg, hostsfile.File{}, "build")
	if !got.SingleLabel {
		t.Fatal("a name with no dot is a single label")
	}
	if len(got.Qualified) != 1 || got.Qualified[0] != "build.corp.internal" {
		t.Errorf("qualified = %v, want [build.corp.internal]", got.Qualified)
	}
}

func TestInterfaceScopedResolversNeverWin(t *testing.T) {
	cfg := fixture(t, "simple.scutil")
	got := Explain(cfg, hostsfile.File{}, "example.com")
	if got.Winner == nil || got.Winner.InterfaceScoped {
		t.Fatalf("winner = %v, want an ordinary resolver", got.Winner)
	}
	if len(got.Ignored) != 1 {
		t.Errorf("ignored = %d, want the one interface-bound resolver", len(got.Ignored))
	}
	for _, c := range got.Candidates {
		if c.Resolver.InterfaceScoped {
			t.Error("interface-bound resolvers must not appear as candidates")
		}
	}
}

func TestTrailingDotAndCaseAreNormalised(t *testing.T) {
	cfg := fixture(t, "vpn.scutil")
	a := Explain(cfg, hostsfile.File{}, "Files.CORP.Internal.")
	if a.Query != "files.corp.internal" {
		t.Errorf("query = %q, want it lowered with no trailing dot", a.Query)
	}
	if a.Winner == nil || a.Winner.Index != 3 {
		t.Errorf("winner = %v, want the corp.internal scope", a.Winner)
	}
}

func TestNoResolverAtAll(t *testing.T) {
	got := Explain(dnsconf.Config{}, hostsfile.File{}, "example.com")
	if got.Winner != nil {
		t.Errorf("winner = %v, want none", got.Winner)
	}
	if got.Mechanism != NoResolver {
		t.Errorf("mechanism = %q, want %q", got.Mechanism, NoResolver)
	}
}

func TestSearchDomainsAreDeduped(t *testing.T) {
	cfg := dnsconf.Parse(`DNS configuration

resolver #1
  search domain[0] : corp.internal
  search domain[1] : corp.internal
  nameserver[0] : 192.0.2.53

resolver #2
  domain : other.example
  search domain[0] : corp.internal
`)
	if got := SearchDomains(cfg); len(got) != 1 {
		t.Errorf("search domains = %v, want one", got)
	}
}

// A single-label name is tried with each search domain first, and those
// expansions can be claimed by a scope the bare name is not.
func TestSearchExpansionsGetTheirOwnWinner(t *testing.T) {
	cfg := fixture(t, "vpn.scutil")
	got := Explain(cfg, hostsfile.File{}, "build")
	if len(got.Attempts) != 2 {
		t.Fatalf("attempts = %+v, want the expansion and the bare name", got.Attempts)
	}
	first := got.Attempts[0]
	if first.Name != "build.corp.internal" || first.WinnerIndex != 3 {
		t.Errorf("first attempt = %+v, want build.corp.internal on resolver #3", first)
	}
	if last := got.Attempts[1]; last.Name != "build" || last.WinnerIndex != 1 {
		t.Errorf("last attempt = %+v, want the bare name on the default resolver", last)
	}
}

func TestAbsoluteNamesSkipSearchDomains(t *testing.T) {
	cfg := fixture(t, "vpn.scutil")
	got := Explain(cfg, hostsfile.File{}, "build.")
	if got.SingleLabel || len(got.Attempts) != 0 || len(got.Qualified) != 0 {
		t.Errorf("a trailing dot means the name is absolute: %+v", got)
	}
	if !got.Absolute {
		t.Error("the result must record that the name was absolute")
	}
	if got.Query != "build" {
		t.Errorf("query = %q, want the name without the dot", got.Query)
	}
}
