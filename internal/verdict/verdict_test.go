package verdict

import (
	"strings"
	"testing"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/hostsfile"
	"github.com/morass/dnswhy/internal/lookup"
	"github.com/morass/dnswhy/internal/match"
)

func text(in Input) string { return strings.Join(Lines(in), " ") }

func scoped() *dnsconf.Resolver {
	return &dnsconf.Resolver{Index: 3, Domain: "corp.internal", Nameservers: []string{"198.51.100.53"}, Reachable: true}
}

func defaultResolver() *dnsconf.Resolver {
	return &dnsconf.Resolver{Index: 1, Nameservers: []string{"192.0.2.53"}, Reachable: true}
}

func TestScopedNameNamesTheServerToAsk(t *testing.T) {
	got := text(Input{
		Result:  match.Result{Query: "files.corp.internal", Mechanism: match.Unicast, Winner: scoped()},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "dig @198.51.100.53 files.corp.internal") {
		t.Errorf("verdict must give the command that reproduces what applications do:\n%s", got)
	}
	if !strings.Contains(got, "192.0.2.53") {
		t.Errorf("verdict must say which server plain dig would ask:\n%s", got)
	}
}

func TestSystemResolvesWhileDirectDoesNot(t *testing.T) {
	sys := lookup.Answer{Via: "system", Addresses: []string{"198.51.100.9"}}
	direct := lookup.Answer{Via: "192.0.2.53", Status: "no such name"}
	got := text(Input{
		Result:  match.Result{Query: "files.corp.internal", Mechanism: match.Unicast, Winner: scoped()},
		System:  &sys,
		Direct:  []lookup.Answer{direct},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "Applications are getting an answer") {
		t.Errorf("verdict should say the applications are fine, without inventing a cause:\n%s", got)
	}
	if strings.Contains(got, "wrong place") {
		t.Errorf("verdict must not assert a cause it cannot see:\n%s", got)
	}
}

func TestDirectResolvesWhileSystemDoesNot(t *testing.T) {
	sys := lookup.Answer{Via: "system", Status: "no answer"}
	direct := lookup.Answer{Via: "192.0.2.53", Addresses: []string{"203.0.113.5"}}
	got := text(Input{
		Result:    match.Result{Query: "example.com", Mechanism: match.Unicast, Winner: defaultResolver()},
		System:    &sys,
		Direct:    []lookup.Answer{direct},
		Default:   defaultResolver(),
		HostsPath: "/etc/hosts",
	})
	if !strings.Contains(got, "in the way") || !strings.Contains(got, "/etc/hosts") {
		t.Errorf("verdict should point at what could be in the way:\n%s", got)
	}
	if strings.Contains(got, "no nameserver was") {
		t.Errorf("a nameserver was asked and answered; the verdict must not say otherwise:\n%s", got)
	}
}

func TestAgreementIsStated(t *testing.T) {
	sys := lookup.Answer{Via: "system", Addresses: []string{"203.0.113.5"}}
	direct := lookup.Answer{Via: "192.0.2.53", Addresses: []string{"203.0.113.5"}}
	got := text(Input{
		Result:  match.Result{Query: "example.com", Mechanism: match.Unicast, Winner: defaultResolver()},
		System:  &sys,
		Direct:  []lookup.Answer{direct},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "Both paths give the same answer") {
		t.Errorf("agreement should be stated plainly:\n%s", got)
	}
}

func TestDifferentAddressesAreCalledOut(t *testing.T) {
	sys := lookup.Answer{Via: "system", Addresses: []string{"203.0.113.5"}}
	direct := lookup.Answer{Via: "192.0.2.53", Addresses: []string{"203.0.113.6"}}
	got := text(Input{
		Result:  match.Result{Query: "example.com", Mechanism: match.Unicast, Winner: defaultResolver()},
		System:  &sys,
		Direct:  []lookup.Answer{direct},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "203.0.113.6") || strings.Contains(got, "Both paths give the same answer") {
		t.Errorf("a disagreement must not read as agreement:\n%s", got)
	}
}

func TestHostsVerdict(t *testing.T) {
	got := text(Input{
		Result:    match.Result{Query: "pinned.example", Mechanism: match.FromHosts, Hosts: []hostsfile.Entry{{Name: "pinned.example", Address: "203.0.113.9", Line: 3}}},
		HostsPath: "/etc/hosts",
	})
	if !strings.Contains(got, "/etc/hosts") || !strings.Contains(got, "No nameserver is asked") {
		t.Errorf("verdict = %s", got)
	}
}

func TestMulticastVerdictExplainsTheTimeout(t *testing.T) {
	sys := lookup.Answer{Via: "system", Status: "timeout"}
	got := text(Input{
		Result: match.Result{Query: "printer.local", Mechanism: match.Multicast, Winner: &dnsconf.Resolver{Index: 2, Domain: "local", Options: []string{"mdns"}}},
		System: &sys,
	})
	if !strings.Contains(got, "dns-sd -G v4 printer.local") {
		t.Errorf("verdict should offer the Bonjour command:\n%s", got)
	}
	if !strings.Contains(got, "always looks like a timeout") {
		t.Errorf("verdict should explain why a missing Bonjour name times out:\n%s", got)
	}
}

func TestUnreachableScopeIsExplained(t *testing.T) {
	w := scoped()
	w.Reachable = false
	got := text(Input{
		Result:  match.Result{Query: "files.corp.internal", Mechanism: match.Unicast, Winner: w},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "rather than falling back") {
		t.Errorf("verdict should say the lookup does not fall back:\n%s", got)
	}
}

func TestNoResolverAtAll(t *testing.T) {
	got := text(Input{Result: match.Result{Query: "example.com", Mechanism: match.NoResolver}})
	if !strings.Contains(got, "no default nameserver") {
		t.Errorf("verdict = %s", got)
	}
}

// A name that resolves to nothing must say what that means, which is the case
// people most often run the tool for.
func TestNothingResolvedIsExplained(t *testing.T) {
	sys := lookup.Answer{Via: "system", Status: "no answer"}
	cases := []struct {
		name   string
		direct lookup.Answer
		want   string
	}{
		{"no such name", lookup.Answer{Via: "192.0.2.53", Status: "no such name"}, "does not exist"},
		{"no address", lookup.Answer{Via: "192.0.2.53", Status: "no address"}, "no IPv4 or IPv6 address"},
		{"timeout", lookup.Answer{Via: "192.0.2.53", Status: "timeout"}, "did not answer in time"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := text(Input{
				Result:  match.Result{Query: "nope.example", Mechanism: match.Unicast, Winner: defaultResolver()},
				System:  &sys,
				Direct:  []lookup.Answer{c.direct},
				Default: defaultResolver(),
			})
			if !strings.Contains(got, c.want) {
				t.Errorf("verdict is missing %q:\n%s", c.want, got)
			}
		})
	}
}

func TestSingleLabelFailureExplainsTheBareWord(t *testing.T) {
	sys := lookup.Answer{Via: "system", Status: "no answer"}
	got := text(Input{
		Result:         match.Result{Query: "google", SingleLabel: true, Mechanism: match.Unicast, Winner: defaultResolver()},
		System:         &sys,
		Direct:         []lookup.Answer{{Via: "192.0.2.53", Status: "no address"}},
		AttemptAnswers: []lookup.Answer{{Via: "198.51.100.53", Status: "no such name"}},
		Default:        defaultResolver(),
	})
	if !strings.Contains(got, "not a domain name") || !strings.Contains(got, "write it in full") {
		t.Errorf("a bare word that fails should be explained:\n%s", got)
	}
}

// A name answered from the hosts file has resolved; the "nothing resolved"
// paragraph must not appear beside it.
func TestHostsAnswerIsNotCalledAFailure(t *testing.T) {
	sys := lookup.Answer{Via: "system", Status: "no answer"}
	got := text(Input{
		Result:    match.Result{Query: "pinned.example", Mechanism: match.FromHosts},
		System:    &sys,
		HostsPath: "/etc/hosts",
	})
	if strings.Contains(got, "Nothing here is broken") || strings.Contains(got, "no nameserver was asked") {
		t.Errorf("a hosts answer is not a failure:\n%s", got)
	}
}

// A scope flagged unreachable that nonetheless answered must not be described
// as failing: an answer beats a flag.
func TestUnreachableScopeThatAnsweredIsNotCalledAFailure(t *testing.T) {
	w := scoped()
	w.Reachable = false
	sys := lookup.Answer{Via: "system", Addresses: []string{"198.51.100.9"}}
	direct := lookup.Answer{Via: "198.51.100.53", Addresses: []string{"198.51.100.9"}}
	got := text(Input{
		Result:  match.Result{Query: "files.corp.internal", Mechanism: match.Unicast, Winner: w},
		System:  &sys,
		Direct:  []lookup.Answer{direct},
		Default: defaultResolver(),
	})
	if strings.Contains(got, "this name fails") || strings.Contains(got, "rather than falling back") {
		t.Errorf("the name resolved; the verdict must not call it a failure:\n%s", got)
	}
}

// The command offered to the reader has to name the port the resolver uses.
func TestDigCommandCarriesThePort(t *testing.T) {
	w := scoped()
	w.Port = 5353
	got := text(Input{
		Result:  match.Result{Query: "files.corp.internal", Mechanism: match.Unicast, Winner: w},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "dig -p 5353 @198.51.100.53 files.corp.internal") {
		t.Errorf("verdict = %s", got)
	}
}

// A nameserver that is not an address cannot become part of a command.
func TestDigCommandRefusesNonAddresses(t *testing.T) {
	w := scoped()
	w.Nameservers = []string{"198.51.100.53;id;#"}
	got := text(Input{
		Result:  match.Result{Query: "files.corp.internal", Mechanism: match.Unicast, Winner: w},
		Default: defaultResolver(),
	})
	if strings.Contains(got, "id;") || strings.Contains(got, "dig @") {
		t.Errorf("a command was built from something that is not an address:\n%s", got)
	}
}

// One question answering "nothing here" and the other not answering at all is
// not proof that a name has no address.
func TestIncompleteAnswerIsNotCalledAbsence(t *testing.T) {
	sys := lookup.Answer{Via: "system", Status: "no answer"}
	direct := lookup.Answer{Via: "192.0.2.53", Status: "incomplete", ByType: map[string]string{"A": "no address", "AAAA": "timeout"}}
	got := text(Input{
		Result:  match.Result{Query: "half.example", Mechanism: match.Unicast, Winner: defaultResolver()},
		System:  &sys,
		Direct:  []lookup.Answer{direct},
		Default: defaultResolver(),
	})
	if !strings.Contains(got, "not proof") {
		t.Errorf("an incomplete answer must be described as incomplete:\n%s", got)
	}
}
