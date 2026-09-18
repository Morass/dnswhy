// Package verdict turns the facts into the sentences a person needs: which
// path answered, why a direct query disagrees, and what to type instead.
package verdict

import (
	"fmt"
	"strings"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/lookup"
	"github.com/morass/dnswhy/internal/match"
)

// Input is everything the verdict is drawn from.
type Input struct {
	Result match.Result
	System *lookup.Answer
	Direct []lookup.Answer // in the order they were asked
	// AttemptAnswers are the replies for the search-domain expansions of a
	// single-label name.
	AttemptAnswers []lookup.Answer
	Default   *dnsconf.Resolver
	HostsPath string
}

// Lines returns the closing paragraph, one string per line, already in plain
// words. It never invents an explanation it cannot support from the facts.
func Lines(in Input) []string {
	var out []string
	r := in.Result
	name := r.Query

	switch r.Mechanism {
	case match.FromHosts:
		out = append(out, fmt.Sprintf("Answered from %s. No nameserver is asked at all, so dig and nslookup", in.HostsPath))
		out = append(out, "will show whatever the internet says instead - that is not a contradiction.")
	case match.Multicast:
		out = append(out, "Resolved by multicast DNS (Bonjour): the question is shouted on the local")
		out = append(out, "network, not asked of a nameserver. dig and nslookup always fail on these")
		out = append(out, "names; that is normal. Use  dns-sd -G v4 "+name+"  to watch it work.")
		if in.System != nil && in.System.Status == "timeout" {
			out = append(out, "Nothing on the network answered in time. Bonjour has no \"does not exist\"")
			out = append(out, "reply, so a name that is simply not there always looks like a timeout.")
		}
	case match.NoResolver:
		out = append(out, "No resolver claims this name and there is no default nameserver, so the")
		out = append(out, "lookup cannot go anywhere. Check that a network interface is up.")
	}

	// A scope can claim the name and still have nothing to ask.
	for _, c := range r.Candidates {
		if c.Matched && c.CannotAnswer {
			out = append(out, fmt.Sprintf("A resolver claims %s but lists no nameserver, so it only contributes a", c.Resolver.Domain))
			out = append(out, "search domain. The answer comes from the resolver marked as the winner above.")
			break
		}
	}

	winner := r.Winner
	scoped := winner != nil && winner.Domain != "" && !winner.IsMulticast()
	if scoped && in.Default != nil && winner.Index != in.Default.Index && r.Mechanism != match.FromHosts {
		out = append(out, fmt.Sprintf("%s is answered by the %s scope, which dig knows nothing about:", name, winner.Domain))
		out = append(out, fmt.Sprintf("dig reads /etc/resolv.conf and would ask %s. To ask what your", strings.Join(in.Default.Nameservers, " or ")))
		if len(winner.Nameservers) > 0 {
			out = append(out, fmt.Sprintf("applications ask, name the server yourself:  dig @%s %s", winner.Nameservers[0], name))
		}
	}

	if in.System != nil && len(in.Direct) > 0 {
		sys := *in.System
		for _, d := range in.Direct {
			switch {
			case sys.OK() && !d.OK():
				out = append(out, fmt.Sprintf("Your applications resolve this name (%s) while a direct question to %s", strings.Join(sys.Addresses, ", "), d.Via))
				out = append(out, fmt.Sprintf("returns %s. The machine is fine; the tool you are testing with is looking", strings.ToLower(orNoAnswer(d.Status))))
				out = append(out, "in the wrong place.")
			case !sys.OK() && d.OK():
				out = append(out, fmt.Sprintf("%s answers this name (%s) but your applications do not see it.", d.Via, strings.Join(d.Addresses, ", ")))
				out = append(out, "Something on this Mac is shadowing it: check the winning scope above and")
				out = append(out, fmt.Sprintf("%s.", in.HostsPath))
			case sys.OK() && d.OK() && !sameAddrs(sys.Addresses, d.Addresses):
				out = append(out, fmt.Sprintf("Your applications get %s while %s says %s.", strings.Join(sys.Addresses, ", "), d.Via, strings.Join(d.Addresses, ", ")))
				out = append(out, "Two answers for one name: either they came from different nameservers, or")
				out = append(out, "one of them is a cached copy of an older answer. Which it is, this tool")
				out = append(out, "cannot see from here.")
			}
		}
	}

	if in.System != nil && len(in.Direct) > 0 && in.System.OK() {
		agreed := true
		for _, d := range in.Direct {
			if !d.OK() || !sameAddrs(in.System.Addresses, d.Addresses) {
				agreed = false
			}
		}
		if agreed {
			out = append(out, "Both paths give the same answer, so nothing on this Mac is redirecting")
			out = append(out, "this name.")
		}
	}

	// A name answered from /etc/hosts never reaches a resolver, so nothing
	// about the resolver that would have answered belongs in the verdict.
	// Nothing resolved at all. This is the most common thing a person types
	// dnswhy for, and saying only "no answer" twice helps nobody.
	if in.System != nil && !in.System.OK() && r.Mechanism != match.FromHosts {
		out = append(out, nothingResolved(in)...)
	}

	if winner != nil && scoped && !winner.Reachable && r.Mechanism != match.FromHosts {
		out = append(out, fmt.Sprintf("The %s scope is marked not reachable, so this name fails while the", winner.Domain))
		out = append(out, "connection that provides it (a VPN, a container, a local dnsmasq) is down -")
		out = append(out, "it does not fall back to the default nameservers.")
	}

	return out
}

// nothingResolved explains a name that produced no address, using the statuses
// that actually came back rather than a guess.
func nothingResolved(in Input) []string {
	var out []string
	statuses := map[string]string{} // status -> the server that said it
	for _, d := range in.Direct {
		if !d.OK() && d.Status != "" {
			statuses[d.Status] = d.Via
		}
	}
	for _, a := range in.AttemptAnswers {
		if !a.OK() && a.Status != "" {
			statuses[a.Status] = a.Via
		}
	}

	name := in.Result.Query
	switch {
	case len(statuses) == 0:
		out = append(out, fmt.Sprintf("Nothing resolved %s, and no nameserver was asked to say why.", name))
		out = append(out, "Run it again without --offline to see what the nameserver answers.")
	case statuses["no address"] != "":
		out = append(out, fmt.Sprintf("%s exists in DNS but has no IPv4 or IPv6 address, so there is nothing", name))
		out = append(out, "to connect to. A name can exist and carry only mail or text records.")
	case statuses["no such name"] != "":
		out = append(out, fmt.Sprintf("Nothing here is broken: %s says this name does not exist, which", statuses["no such name"]))
		out = append(out, "is an answer, not a failure. Check the spelling, or whether the name only")
		out = append(out, "exists on a network this Mac is not on right now.")
	case statuses["timeout"] != "" || statuses["unreachable"] != "":
		server := statuses["timeout"]
		if server == "" {
			server = statuses["unreachable"]
		}
		out = append(out, fmt.Sprintf("%s did not answer in time, so this is a connection problem rather", server))
		out = append(out, "than a naming one: the nameserver, or the link to it, is down.")
	default:
		for status, via := range statuses {
			out = append(out, fmt.Sprintf("%s answered %q and gave no address.", via, status))
			break
		}
	}

	if in.Result.SingleLabel {
		out = append(out, "A word with no dot is not a domain name: macOS tries it with each search")
		out = append(out, "domain first, as listed above, and then on its own. If you meant a name on")
		out = append(out, "the internet, write it in full.")
	}
	return out
}

func orNoAnswer(s string) string {
	if s == "" {
		return "no answer"
	}
	return s
}

func sameAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}
