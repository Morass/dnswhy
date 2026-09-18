// Package verdict turns the facts into the sentences a person needs: which
// path answered, why a direct query disagrees, and what to type instead.
package verdict

import (
	"fmt"
	"net"
	"strconv"
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
		if cmd := digCommand(*winner, name); cmd != "" {
			out = append(out, "applications ask, name the server yourself:  "+cmd)
		}
	}

	if in.System != nil && len(in.Direct) > 0 {
		sys := *in.System
		for _, d := range in.Direct {
			switch {
			case sys.OK() && !d.OK():
				out = append(out, fmt.Sprintf("Your applications resolve this name (%s) while a direct question to %s", strings.Join(sys.Addresses, ", "), d.Via))
				out = append(out, fmt.Sprintf("returned %s. Applications are getting an answer, so whatever you are", strings.ToLower(orNoAnswer(d.Status))))
				out = append(out, "testing with is asking something else - or the system answer is a cached one.")
			case !sys.OK() && d.OK():
				out = append(out, fmt.Sprintf("%s answers this name (%s) but your applications did not get it", d.Via, strings.Join(d.Addresses, ", ")))
				out = append(out, fmt.Sprintf("(%s). Something between them is in the way: the scope that wins above,", orNoAnswer(sys.Status)))
				out = append(out, fmt.Sprintf("%s, or a cached negative answer.", in.HostsPath))
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
			if !d.OK() || d.Status == "truncated" || !sameAddrs(in.System.Addresses, d.Addresses) {
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
	anyDirect := false
	for _, d := range in.Direct {
		if d.OK() {
			anyDirect = true
		}
	}
	if in.System != nil && !in.System.OK() && !anyDirect && r.Mechanism != match.FromHosts {
		out = append(out, nothingResolved(in)...)
	}

	// A scope marked unreachable is worth saying only when nothing answered:
	// the flag is a hint from the system configuration, and an answer beats it.
	resolved := in.System != nil && in.System.OK()
	for _, d := range in.Direct {
		if d.OK() {
			resolved = true
		}
	}
	if winner != nil && scoped && !winner.Reachable && r.Mechanism != match.FromHosts && !resolved {
		out = append(out, fmt.Sprintf("The %s scope is marked not reachable, so while the connection that", winner.Domain))
		out = append(out, "provides it (a VPN, a container, a local dnsmasq) is down this name fails")
		out = append(out, "rather than falling back to the default nameservers.")
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
	case len(statuses) == 0 && in.System == nil:
		out = append(out, fmt.Sprintf("Nothing resolved %s, and no nameserver was asked to say why.", name))
		out = append(out, "Run it again without --offline to see what a nameserver answers.")
	case len(statuses) == 0 && in.Result.Mechanism == match.Multicast:
		out = append(out, fmt.Sprintf("Nothing on the local network claimed %s. No nameserver was asked,", name))
		out = append(out, "because a .local name is never a question for one.")
	case len(statuses) == 0:
		out = append(out, fmt.Sprintf("The system resolver returned nothing for %s, and no nameserver was", name))
		out = append(out, "asked directly: nothing in the configuration above would have been given")
		out = append(out, "this name to answer.")
	case statuses["incomplete"] != "":
		out = append(out, fmt.Sprintf("%s produced no address, but the two questions did not agree: one came", name))
		out = append(out, "back empty and the other did not come back at all, so this is not proof")
		out = append(out, "that the name has no address.")
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
		out = append(out, fmt.Sprintf("%s did not answer in time. Nothing here says the name is wrong: an", server))
		out = append(out, "unanswered question usually means the nameserver or the link to it is")
		out = append(out, "unavailable, or that something is dropping DNS on the way.")
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

// digCommand is the command that reproduces what applications get, or nothing
// at all when the configuration does not give a usable address to put in it.
func digCommand(r dnsconf.Resolver, name string) string {
	if len(r.Nameservers) == 0 {
		return ""
	}
	host := strings.Trim(strings.TrimSpace(r.Nameservers[0]), "[]")
	port := r.Port
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(h, "[]")
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	if port != 0 && port != 53 {
		return fmt.Sprintf("dig -p %d @%s %s", port, host, name)
	}
	return fmt.Sprintf("dig @%s %s", host, name)
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
