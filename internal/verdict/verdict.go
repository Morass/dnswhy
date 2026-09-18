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
	Result    match.Result
	System    *lookup.Answer
	Direct    []lookup.Answer // in the order they were asked
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
	if winner != nil && scoped && !winner.Reachable && r.Mechanism != match.FromHosts {
		out = append(out, fmt.Sprintf("The %s scope is marked not reachable, so this name fails while the", winner.Domain))
		out = append(out, "connection that provides it (a VPN, a container, a local dnsmasq) is down -")
		out = append(out, "it does not fall back to the default nameservers.")
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
