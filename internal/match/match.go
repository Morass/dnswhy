// Package match decides which resolver macOS will use for a name, and why.
//
// The rules, as mDNSResponder applies them:
//
//   - /etc/hosts is consulted first; a match there ends the lookup.
//   - Among the resolvers that claim a domain, one whose domain equals the name
//     or is a suffix of it (on a label boundary) can match. The most specific
//     match wins - the one matching the most labels.
//   - Between two matches of equal specificity the lower "order" value wins,
//     and failing that the lower resolver number.
//   - A resolver with no domain answers everything nothing else claimed.
//   - Resolvers printed under "DNS configuration (for scoped queries)" only
//     answer queries a program has bound to that interface, so they never win
//     an ordinary lookup.
//   - A name with no dot is also tried with each search domain appended.
//
// Everything here is a pure function of a parsed configuration, so a captured
// machine state can be replayed in a test.
package match

import (
	"sort"
	"strings"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/hostsfile"
)

// Mechanism is how the name will be answered.
type Mechanism string

const (
	// FromHosts means an entry in /etc/hosts ends the lookup.
	FromHosts Mechanism = "hosts"
	// Multicast means Bonjour: a question shouted on the local network rather
	// than asked of a nameserver.
	Multicast Mechanism = "mdns"
	// Unicast means an ordinary question to a nameserver.
	Unicast Mechanism = "unicast"
	// NoResolver means nothing claimed the name and there is no default.
	NoResolver Mechanism = "none"
)

// Candidate is one resolver considered for a name.
type Candidate struct {
	Resolver dnsconf.Resolver `json:"resolver"`
	Matched  bool             `json:"matched"`
	Wins     bool             `json:"wins"`
	// Labels is how many labels of the name the resolver's domain matched;
	// -1 for the catch-all resolver, which matches nothing specific.
	Labels int    `json:"labels"`
	Why    string `json:"why"`
}

// Result is the whole explanation for one name.
type Result struct {
	Query       string             `json:"query"`
	SingleLabel bool               `json:"single_label"`
	Qualified   []string           `json:"qualified,omitempty"`
	Hosts       []hostsfile.Entry  `json:"hosts,omitempty"`
	Candidates  []Candidate        `json:"candidates"`
	Winner      *dnsconf.Resolver  `json:"winner,omitempty"`
	Mechanism   Mechanism          `json:"mechanism"`
	Ignored     []dnsconf.Resolver `json:"interface_scoped,omitempty"`
}

// SearchDomains returns every search domain the configuration offers, in the
// order macOS would try them, without duplicates.
func SearchDomains(cfg dnsconf.Config) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range cfg.Unscoped() {
		for _, s := range r.SearchDomains {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// Explain works out what will answer name.
func Explain(cfg dnsconf.Config, hosts hostsfile.File, name string) Result {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	res := Result{Query: name, Mechanism: NoResolver}

	res.SingleLabel = !strings.Contains(name, ".")
	if res.SingleLabel {
		for _, s := range SearchDomains(cfg) {
			res.Qualified = append(res.Qualified, name+"."+s)
		}
	}

	if got := hosts.Lookup(name); len(got) > 0 {
		res.Hosts = got
		res.Mechanism = FromHosts
	}

	unscoped := cfg.Unscoped()
	best := -1 // index into res.Candidates
	for _, r := range unscoped {
		c := Candidate{Resolver: r, Labels: -1}
		switch {
		case r.Default():
			c.Matched = true
			c.Why = "claims no domain, so it answers whatever nothing else claimed"
		case matches(name, r.Domain):
			c.Matched = true
			c.Labels = len(strings.Split(r.Domain, "."))
			if name == r.Domain {
				c.Why = "claims " + r.Domain + ", which is the name itself"
			} else {
				c.Why = "claims " + r.Domain + ", a suffix of the name"
			}
		default:
			c.Why = "claims " + r.Domain + ", which the name does not end in"
		}
		res.Candidates = append(res.Candidates, c)
	}

	for i, c := range res.Candidates {
		if !c.Matched {
			continue
		}
		if best == -1 || better(c, res.Candidates[best]) {
			best = i
		}
	}
	if best >= 0 {
		res.Candidates[best].Wins = true
		w := res.Candidates[best].Resolver
		res.Winner = &w
		if res.Mechanism != FromHosts {
			if w.IsMulticast() {
				res.Mechanism = Multicast
			} else if len(w.Nameservers) > 0 {
				res.Mechanism = Unicast
			}
		}
	}

	// Display order: the winner first, then the other matches by specificity,
	// then the resolvers that did not match, in configuration order.
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		a, b := res.Candidates[i], res.Candidates[j]
		if a.Matched != b.Matched {
			return a.Matched
		}
		if !a.Matched {
			return a.Resolver.Index < b.Resolver.Index
		}
		return better(a, b)
	})

	res.Ignored = cfg.InterfaceScoped()
	return res
}

// better reports whether a beats b for the same name.
func better(a, b Candidate) bool {
	if a.Labels != b.Labels {
		return a.Labels > b.Labels // the more specific domain wins
	}
	ao, bo := a.Resolver.Order, b.Resolver.Order
	if a.Resolver.HasOrder != b.Resolver.HasOrder {
		return a.Resolver.HasOrder // an explicit order beats none
	}
	if ao != bo {
		return ao < bo // lower order value is preferred
	}
	return a.Resolver.Index < b.Resolver.Index
}

// matches reports whether domain claims name: either the name itself or a
// suffix of it on a label boundary. "example.com" claims "a.example.com" but
// not "notexample.com".
func matches(name, domain string) bool {
	if domain == "" {
		return false
	}
	if name == domain {
		return true
	}
	return strings.HasSuffix(name, "."+domain)
}

// DefaultResolver returns the resolver that answers names nothing else claims.
func DefaultResolver(cfg dnsconf.Config) *dnsconf.Resolver {
	for _, r := range cfg.Unscoped() {
		if r.Default() && len(r.Nameservers) > 0 {
			c := r
			return &c
		}
	}
	return nil
}
