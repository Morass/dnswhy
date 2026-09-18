// Package doctor reviews a whole DNS configuration and reports the parts that
// will bite: unreachable scopes, resolver files that are not in effect, search
// domains that turn typos into answers, hosts entries that shadow a scope.
package doctor

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/hostsfile"
	"github.com/morass/dnswhy/internal/match"
	"github.com/morass/dnswhy/internal/resolverdir"
)

// Level is how much a finding matters.
type Level string

const (
	// OK is a statement that something is in order.
	OK Level = "ok"
	// Note is something worth knowing that is not a fault.
	Note Level = "note"
	// Warn is something that will make a lookup fail or surprise you.
	Warn Level = "warn"
)

// Finding is one observation about the configuration.
type Finding struct {
	Level  Level    `json:"level"`
	Title  string   `json:"title"`
	Detail []string `json:"detail,omitempty"`
}

// Report is the whole review.
type Report struct {
	Findings []Finding `json:"findings"`
}

// Counts returns how many findings of each level the report holds.
func (r Report) Counts() (ok, note, warn int) {
	for _, f := range r.Findings {
		switch f.Level {
		case OK:
			ok++
		case Note:
			note++
		case Warn:
			warn++
		}
	}
	return
}

// Run reviews a configuration. It reads nothing itself, so a captured machine
// state produces the same report anywhere.
func Run(cfg dnsconf.Config, dir resolverdir.Dir, hosts hostsfile.File) Report {
	var r Report
	add := func(l Level, title string, detail ...string) {
		r.Findings = append(r.Findings, Finding{Level: l, Title: title, Detail: detail})
	}

	unscoped := cfg.Unscoped()
	def := match.DefaultResolver(cfg)
	switch {
	case def == nil:
		add(Warn, "No default nameserver",
			"Nothing answers names that no scope claims, so ordinary lookups fail.",
			"This is normal only while every network interface is down.")
	case !def.Reachable:
		add(Warn, fmt.Sprintf("The default nameservers are not reachable: %s", strings.Join(def.Nameservers, ", ")),
			"Every name that no other scope claims will fail or hang until this changes.")
	default:
		add(OK, fmt.Sprintf("Default nameservers reachable: %s", strings.Join(def.Nameservers, ", ")),
			fmt.Sprintf("resolver #%d answers everything no scope claims.", def.Index))
	}

	// Scopes that cannot answer.
	for _, res := range unscoped {
		if res.Domain == "" || res.IsMulticast() {
			continue
		}
		if len(res.Nameservers) == 0 {
			// A resolver file that only adds a search domain is reported once,
			// against the file, further down.
			if _, fromFile := dir.ForDomain(res.Domain); !fromFile {
				add(Note, fmt.Sprintf("Scope %q has no nameserver", res.Domain),
					fmt.Sprintf("resolver #%d only contributes search domains: %s.", res.Index, joinOr(res.SearchDomains, "none")),
					"It cannot answer a name by itself.")
			}
			continue
		}
		if !res.Reachable {
			add(Warn, fmt.Sprintf("Scope %q points at an unreachable nameserver: %s", res.Domain, strings.Join(res.Nameservers, ", ")),
				fmt.Sprintf("Every name under %s fails%s instead of falling back to the default nameservers.", res.Domain, timeoutPhrase(res.Timeout)),
				"That is how a disconnected VPN or a stopped container makes one domain, and only that domain, stop working.")
		}
	}

	// Two scopes claiming the same domain.
	byDomain := map[string][]dnsconf.Resolver{}
	for _, res := range unscoped {
		if res.Domain != "" && !res.IsMulticast() {
			byDomain[res.Domain] = append(byDomain[res.Domain], res)
		}
	}
	for _, domain := range sortedKeys(byDomain) {
		list := byDomain[domain]
		if len(list) < 2 {
			continue
		}
		var parts []string
		for _, res := range list {
			parts = append(parts, fmt.Sprintf("resolver #%d (%s)", res.Index, joinOr(res.Nameservers, "no nameserver")))
		}
		add(Warn, fmt.Sprintf("Two resolvers claim %q", domain),
			strings.Join(parts, " and ")+".",
			"The lower order value wins; the other is never asked.")
	}

	// Resolver files that are not in effect.
	inConfig := map[string]bool{}
	for _, res := range unscoped {
		if res.Domain != "" {
			inConfig[res.Domain] = true
		}
	}
	seenFileDomain := map[string]string{}
	for _, f := range dir.Files {
		if prev, dup := seenFileDomain[f.Domain]; dup {
			add(Warn, fmt.Sprintf("%s and %s both claim %q", prev, f.Name, f.Domain),
				"One of them has no effect. Delete the one you did not mean to keep.")
		}
		seenFileDomain[f.Domain] = f.Name

		if len(f.Nameservers) == 0 && len(f.SearchDomains) > 0 {
			add(Note, fmt.Sprintf("%s adds a search domain and nothing else", f.Path),
				fmt.Sprintf("It appends %s to single-label names; it cannot answer anything itself.", strings.Join(f.SearchDomains, ", ")))
		}
		if len(f.Nameservers) == 0 && len(f.SearchDomains) == 0 {
			add(Warn, fmt.Sprintf("%s has no nameserver line", f.Path),
				"A resolver file without a nameserver does nothing.")
		}
		if len(f.Unknown) > 0 {
			add(Warn, fmt.Sprintf("%s has lines macOS does not understand", f.Path),
				strings.Join(f.Unknown, " / "),
				"Only nameserver, domain, search, port, timeout and search_order are read.")
		}
		if len(f.Nameservers) > 0 && !inConfig[f.Domain] {
			add(Warn, fmt.Sprintf("%s is not in the live configuration", f.Path),
				fmt.Sprintf("scutil --dns shows no resolver for %q, so the file is being ignored.", f.Domain),
				"macOS reads this directory when it changes; a file written as root with odd permissions, or a domain that another scope already claims, can end up ignored.")
		}
	}

	// Search domains.
	if search := match.SearchDomains(cfg); len(search) > 0 {
		detail := []string{
			fmt.Sprintf("A name with no dot is also tried as name.%s.", strings.Join(search, ", name.")),
		}
		if len(search) > 1 {
			detail = append(detail, "They are tried in that order, so the first one that answers wins.")
		}
		detail = append(detail, "This is why a bare word can resolve to a host you did not mean.")
		add(Note, fmt.Sprintf("Search domains in use: %s", strings.Join(search, ", ")), detail...)
	}

	// Hosts entries that shadow a scope, or that disagree with themselves.
	byName := map[string][]hostsfile.Entry{}
	for _, e := range hosts.Entries {
		byName[e.Name] = append(byName[e.Name], e)
	}
	for _, name := range sortedKeys(byName) {
		entries := byName[name]
		// One name with both an IPv4 and an IPv6 address is ordinary and both
		// are used; two addresses of the same family are a conflict, and only
		// the first of them is ever returned.
		families := map[bool]map[string]bool{true: {}, false: {}}
		lines := map[bool][]string{}
		for _, e := range entries {
			v4 := isIPv4(e.Address)
			families[v4][e.Address] = true
			lines[v4] = append(lines[v4], fmt.Sprintf("line %d", e.Line))
		}
		for v4, set := range families {
			if len(set) < 2 {
				continue
			}
			kind := "IPv6"
			if v4 {
				kind = "IPv4"
			}
			add(Warn, fmt.Sprintf("%s has more than one %s address in %s", name, kind, hosts.Path),
				strings.Join(lines[v4], ", ")+".",
				"The first entry wins; the rest are dead weight.")
		}
		for _, res := range unscoped {
			if res.Domain == "" || res.IsMulticast() {
				continue
			}
			if name == res.Domain || strings.HasSuffix(name, "."+res.Domain) {
				add(Note, fmt.Sprintf("%s in %s shadows the %q scope", name, hosts.Path, res.Domain),
					fmt.Sprintf("resolver #%d will never be asked for this name.", res.Index))
				break
			}
		}
	}

	if ifs := cfg.InterfaceScoped(); len(ifs) > 0 {
		var parts []string
		for _, res := range ifs {
			label := res.IfName
			if label == "" {
				label = fmt.Sprintf("if_index %d", res.IfIndex)
			}
			parts = append(parts, fmt.Sprintf("%s -> %s", label, joinOr(res.Nameservers, "no nameserver")))
		}
		add(Note, fmt.Sprintf("%d interface-bound resolver(s)", len(ifs)),
			strings.Join(parts, ", ")+".",
			"They answer only a program that binds its lookup to that interface, so they never win an ordinary one.")
	}

	return r
}

// isIPv4 reports whether the address is an IPv4 literal. Anything unparseable
// counts as IPv4 so a malformed line is still compared with its neighbours.
func isIPv4(addr string) bool {
	ip := net.ParseIP(addr)
	return ip == nil || ip.To4() != nil
}

func timeoutPhrase(t int) string {
	if t <= 0 {
		return ""
	}
	return fmt.Sprintf(", after a %ds wait", t)
}

func joinOr(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	return strings.Join(list, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
