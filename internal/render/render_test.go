package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/doctor"
	"github.com/morass/dnswhy/internal/hostsfile"
	"github.com/morass/dnswhy/internal/lookup"
	"github.com/morass/dnswhy/internal/match"
)

func config() dnsconf.Config {
	return dnsconf.Parse(`DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53
  reach : 0x00000002 (Reachable)

resolver #2
  domain : local
  options : mdns
  order : 300000

resolver #3
  domain : corp.internal
  nameserver[0] : 198.51.100.53
  reach : 0x00000002 (Reachable)
  order : 200000

resolver #4
  domain : other.example
  nameserver[0] : 203.0.113.53
  reach : 0x00000002 (Reachable)
  order : 200100
`)
}

func explainText(t *testing.T, name string, hosts hostsfile.File, st Style) string {
	t.Helper()
	cfg := config()
	res := match.Explain(cfg, hosts, name)
	var buf bytes.Buffer
	Explain(&buf, Explanation{Result: res, HostsPath: hosts.Path, Default: match.DefaultResolver(cfg)}, st)
	return buf.String()
}

func TestExplainMarksTheWinner(t *testing.T) {
	out := explainText(t, "files.corp.internal", hostsfile.File{Path: "/etc/hosts"}, Style{})
	if !strings.Contains(out, "resolver #3  corp.internal") {
		t.Errorf("the winning resolver must be named:\n%s", out)
	}
	line := lineContaining(t, out, "resolver #3  corp.internal")
	if !strings.Contains(line, "wins") {
		t.Errorf("the winning line must say it wins:\n%s", line)
	}
}

func TestExplainShowsHostsFirst(t *testing.T) {
	hosts := hostsfile.File{Path: "/etc/hosts", Entries: []hostsfile.Entry{{Name: "files.corp.internal", Address: "203.0.113.9", Line: 4}}}
	out := explainText(t, "files.corp.internal", hosts, Style{})
	hostsAt := strings.Index(out, "/etc/hosts")
	scopeAt := strings.Index(out, "corp.internal ")
	if hostsAt < 0 || scopeAt < 0 || hostsAt > scopeAt {
		t.Errorf("/etc/hosts must be shown before the scopes:\n%s", out)
	}
	if !strings.Contains(out, "not reached") {
		t.Errorf("a scope that is never asked must say so:\n%s", out)
	}
}

func TestExplainSummarisesTheScopesItSkips(t *testing.T) {
	out := explainText(t, "files.corp.internal", hostsfile.File{Path: "/etc/hosts"}, Style{})
	if !strings.Contains(out, "other scope(s) claim names this one does not end in") {
		t.Errorf("the scopes left out must be counted:\n%s", out)
	}
	if !strings.Contains(out, "other.example") {
		t.Errorf("the skipped scopes should be named:\n%s", out)
	}
}

func TestColourIsOptional(t *testing.T) {
	plain := explainText(t, "example.com", hostsfile.File{Path: "/etc/hosts"}, Style{})
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("no escape sequences may appear with colour off:\n%q", plain)
	}
	coloured := explainText(t, "example.com", hostsfile.File{Path: "/etc/hosts"}, Style{Colour: true})
	if !strings.Contains(coloured, "\x1b[") {
		t.Error("colour on should emit escape sequences")
	}
}

func TestAnswersAndVerdictAreShown(t *testing.T) {
	cfg := config()
	res := match.Explain(cfg, hostsfile.File{Path: "/etc/hosts"}, "files.corp.internal")
	sys := lookup.Answer{Via: "system", Addresses: []string{"198.51.100.9"}}
	direct := lookup.Answer{Via: "192.0.2.53", Status: "NXDOMAIN", Detail: "the nameserver says this name does not exist"}
	var buf bytes.Buffer
	Explain(&buf, Explanation{
		Result: res, HostsPath: "/etc/hosts", System: &sys, Direct: []lookup.Answer{direct},
		Verdict: []string{"a closing sentence"},
	}, Style{})
	out := buf.String()
	for _, want := range []string{"system  (every application)", "198.51.100.9", "asked 192.0.2.53 directly", "NXDOMAIN", "a closing sentence"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestSingleLabelShowsTheSearchDomains(t *testing.T) {
	cfg := dnsconf.Parse("DNS configuration\n\nresolver #1\n  nameserver[0] : 192.0.2.53\n  search domain[0] : corp.internal\n")
	res := match.Explain(cfg, hostsfile.File{Path: "/etc/hosts"}, "build")
	var buf bytes.Buffer
	Explain(&buf, Explanation{Result: res, HostsPath: "/etc/hosts"}, Style{})
	out := buf.String()
	if !strings.Contains(out, "build.corp.internal") || !strings.Contains(out, "then as build") {
		t.Errorf("a single-label name must show what it is tried as, in order:\n%s", out)
	}
}

func TestDoctorCountsAndLevels(t *testing.T) {
	rep := doctor.Report{Findings: []doctor.Finding{
		{Level: doctor.OK, Title: "fine"},
		{Level: doctor.Note, Title: "worth knowing", Detail: []string{"detail line"}},
		{Level: doctor.Warn, Title: "worth fixing"},
	}}
	var buf bytes.Buffer
	Doctor(&buf, rep, Style{})
	out := buf.String()
	for _, want := range []string{"ok  ", "note", "warn", "detail line", "1 in order, 1 worth knowing, 1 worth fixing"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output is missing %q:\n%s", want, out)
		}
	}
}

func lineContaining(t *testing.T, out, substr string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	t.Fatalf("no line contains %q in:\n%s", substr, out)
	return ""
}

func TestLongDetailLinesAreWrapped(t *testing.T) {
	long := strings.Repeat("word ", 40)
	rep := doctor.Report{Findings: []doctor.Finding{{Level: doctor.Warn, Title: "t", Detail: []string{long}}}}
	var buf bytes.Buffer
	Doctor(&buf, rep, Style{})
	for _, line := range strings.Split(buf.String(), "\n") {
		if len([]rune(line)) > wrapWidth {
			t.Errorf("line of %d runes is wider than %d:\n%s", len([]rune(line)), wrapWidth, line)
		}
	}
}

func TestWrapKeepsLongWordsWhole(t *testing.T) {
	word := strings.Repeat("x", 120)
	got := wrap("short "+word, 20)
	if len(got) != 2 || got[1] != word {
		t.Errorf("wrap = %q", got)
	}
}

// The attempt list must not claim an order between the hosts file and the
// search domains that the tool cannot actually observe.
func TestSingleLabelHeadingClaimsNoOrderItCannotSee(t *testing.T) {
	cfg := dnsconf.Parse("DNS configuration\n\nresolver #1\n  nameserver[0] : 192.0.2.53\n  search domain[0] : corp.internal\n")
	hosts := hostsfile.File{Path: "/etc/hosts", Entries: []hostsfile.Entry{{Name: "build", Address: "203.0.113.9", Line: 2}}}
	res := match.Explain(cfg, hosts, "build")
	var buf bytes.Buffer
	Explain(&buf, Explanation{Result: res, HostsPath: "/etc/hosts"}, Style{})
	if strings.Contains(buf.String(), "answers first") {
		t.Errorf("the heading must not order hosts against the search domains:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "an entry in the hosts file") {
		t.Errorf("the attempt that the hosts file covers should still say so:\n%s", buf.String())
	}
}
