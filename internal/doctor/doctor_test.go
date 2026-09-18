package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/hostsfile"
	"github.com/morass/dnswhy/internal/resolverdir"
)

func load(t *testing.T, scutil string) (dnsconf.Config, resolverdir.Dir, hostsfile.File) {
	t.Helper()
	base := filepath.Join("..", "..", "testdata")
	b, err := os.ReadFile(filepath.Join(base, scutil))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := resolverdir.Load(filepath.Join(base, "resolver-dir"))
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := hostsfile.Load(filepath.Join(base, "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	return dnsconf.Parse(string(b)), dir, hosts
}

func titles(r Report, level Level) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Level == level {
			out = append(out, f.Title)
		}
	}
	return out
}

func hasTitle(r Report, substr string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

func TestUnreachableScopeIsAWarning(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	if !hasTitle(rep, `Scope "corp.internal" points at an unreachable nameserver`) {
		t.Errorf("findings = %v", titles(rep, Warn))
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Title, "corp.internal") && f.Level == Warn {
			if !strings.Contains(strings.Join(f.Detail, " "), "instead of falling back") {
				t.Error("the finding must say the lookup does not fall back to the default nameservers")
			}
		}
	}
}

func TestResolverFileNotInEffect(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	if !hasTitle(rep, "stale.example is not in the live configuration") {
		t.Errorf("a resolver file with no matching scope must be reported: %v", titles(rep, Warn))
	}
}

func TestUnparseableResolverLine(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	if !hasTitle(rep, "typo.example has lines macOS does not understand") {
		t.Errorf("warnings = %v", titles(rep, Warn))
	}
}

func TestTwoScopesClaimingOneDomain(t *testing.T) {
	cfg, dir, hosts := load(t, "conflict.scutil")
	rep := Run(cfg, dir, hosts)
	if !hasTitle(rep, `Two resolvers claim "shared.example"`) {
		t.Errorf("warnings = %v", titles(rep, Warn))
	}
}

// A name with one IPv4 and one IPv6 address in /etc/hosts is ordinary; only two
// addresses of the same family are a conflict.
func TestHostsIPv4AndIPv6IsNotAConflict(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	for _, f := range rep.Findings {
		if strings.Contains(f.Title, "localhost") {
			t.Errorf("localhost with a v4 and a v6 address must not be reported: %q", f.Title)
		}
	}
	if !hasTitle(rep, "doubled.example has more than one IPv4 address") {
		t.Errorf("two IPv4 addresses for one name must be reported: %v", titles(rep, Warn))
	}
}

func TestHostsEntryShadowingAScope(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	if !hasTitle(rep, `pinned.corp.internal in`) {
		t.Errorf("notes = %v", titles(rep, Note))
	}
}

func TestNoDefaultNameserver(t *testing.T) {
	cfg := dnsconf.Parse("DNS configuration\n\nresolver #1\n  domain : corp.internal\n  nameserver[0] : 198.51.100.53\n  reach : 0x00000002 (Reachable)\n")
	rep := Run(cfg, resolverdir.Dir{}, hostsfile.File{})
	if !hasTitle(rep, "No default nameserver") {
		t.Errorf("findings = %+v", rep.Findings)
	}
}

func TestSearchDomainReportedOnce(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	n := 0
	for _, f := range rep.Findings {
		if strings.Contains(f.Title, "adds a search domain") || strings.Contains(f.Title, `Scope "search.only"`) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("a search-only resolver file must be reported once, got %d findings", n)
	}
}

// A file whose content is one typo should produce one finding, not two.
func TestUnusableFileGivesOneFinding(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	n := 0
	for _, f := range rep.Findings {
		if strings.Contains(f.Title, "typo.example") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("typo.example produced %d findings, want 1", n)
	}
}

func TestCountsAddUp(t *testing.T) {
	cfg, dir, hosts := load(t, "vpn.scutil")
	rep := Run(cfg, dir, hosts)
	ok, note, warn := rep.Counts()
	if ok+note+warn != len(rep.Findings) {
		t.Errorf("counts %d+%d+%d do not add up to %d findings", ok, note, warn, len(rep.Findings))
	}
}
