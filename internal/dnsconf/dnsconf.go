// Package dnsconf parses the output of `scutil --dns` into resolver records.
//
// The text format is stable but undocumented. A block looks like:
//
//	resolver #8
//	  domain   : example.internal
//	  nameserver[0] : 198.51.100.53
//	  search domain[0] : corp.example
//	  options  : mdns
//	  timeout  : 5
//	  if_index : 16 (en1)
//	  flags    : Scoped, Request A records
//	  reach    : 0x00000002 (Reachable)
//	  order    : 200300
//
// Blocks before the line "DNS configuration (for scoped queries)" apply to
// ordinary lookups; the ones after it are used only when a query is bound to a
// particular interface.
package dnsconf

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Resolver is one resolver block.
type Resolver struct {
	Index         int      `json:"index"`
	Domain        string   `json:"domain,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Nameservers   []string `json:"nameservers,omitempty"`
	Options       []string `json:"options,omitempty"`
	Flags         []string `json:"flags,omitempty"`
	Order         int      `json:"order,omitempty"`
	HasOrder      bool     `json:"-"`
	Timeout       int      `json:"timeout,omitempty"`
	Port          int      `json:"port,omitempty"`
	Reach         string   `json:"reach,omitempty"`
	Reachable     bool     `json:"reachable"`
	IfIndex       int      `json:"if_index,omitempty"`
	IfName        string   `json:"if_name,omitempty"`
	// InterfaceScoped is true for blocks in the "for scoped queries" section:
	// they answer only queries a program binds to that interface.
	InterfaceScoped bool `json:"interface_scoped"`
}

// Config is a whole `scutil --dns` dump.
type Config struct {
	Resolvers []Resolver `json:"resolvers"`
	// Incomplete is true when the dump could not be read to the end, so
	// anything drawn from it may be missing a resolver.
	Incomplete bool `json:"incomplete,omitempty"`
}

// HasOption reports whether the resolver carries the named option, e.g. "mdns".
func (r Resolver) HasOption(name string) bool {
	for _, o := range r.Options {
		if strings.EqualFold(o, name) {
			return true
		}
	}
	return false
}

// IsMulticast reports whether this resolver answers over multicast DNS
// (Bonjour) rather than by asking a nameserver.
func (r Resolver) IsMulticast() bool { return r.HasOption("mdns") }

// Default reports whether the resolver claims no domain, so it answers
// everything nothing else claimed.
func (r Resolver) Default() bool { return r.Domain == "" && !r.InterfaceScoped }

// Unscoped returns the resolvers that take part in ordinary lookups.
func (c Config) Unscoped() []Resolver {
	var out []Resolver
	for _, r := range c.Resolvers {
		if !r.InterfaceScoped {
			out = append(out, r)
		}
	}
	return out
}

// InterfaceScoped returns the resolvers used only by interface-bound queries.
func (c Config) InterfaceScoped() []Resolver {
	var out []Resolver
	for _, r := range c.Resolvers {
		if r.InterfaceScoped {
			out = append(out, r)
		}
	}
	return out
}

// Run reads the live configuration from scutil. It is given a deadline because
// a wedged configuration daemon must not wedge the tool as well.
func Run(timeout time.Duration) (Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		if ctx.Err() != nil {
			return Config{}, fmt.Errorf("scutil --dns did not answer within %s", timeout)
		}
		return Config{}, err
	}
	return Parse(string(out)), nil
}

// Parse turns `scutil --dns` output into a Config. Unknown keys are ignored so
// a future macOS adding a field cannot break the parse.
func Parse(text string) Config {
	var cfg Config
	var cur *Resolver
	interfaceSection := false

	flush := func() {
		if cur != nil {
			cfg.Resolvers = append(cfg.Resolvers, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "DNS configuration") {
			flush()
			// Anything after this header is interface-scoped. The first header
			// ("DNS configuration") has no suffix; the second says so.
			interfaceSection = strings.Contains(trimmed, "scoped")
			continue
		}
		if strings.HasPrefix(trimmed, "resolver #") {
			flush()
			n, _ := strconv.Atoi(strings.TrimPrefix(trimmed, "resolver #"))
			cur = &Resolver{Index: n, InterfaceScoped: interfaceSection}
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch {
		case key == "domain":
			cur.Domain = strings.TrimSuffix(strings.ToLower(value), ".")
		case strings.HasPrefix(key, "search domain"):
			cur.SearchDomains = append(cur.SearchDomains, strings.TrimSuffix(strings.ToLower(value), "."))
		case strings.HasPrefix(key, "nameserver"):
			cur.Nameservers = append(cur.Nameservers, value)
		case key == "options":
			for _, o := range strings.Split(value, ",") {
				if o = strings.TrimSpace(o); o != "" {
					cur.Options = append(cur.Options, o)
				}
			}
		case key == "flags":
			for _, f := range strings.Split(value, ",") {
				if f = strings.TrimSpace(f); f != "" {
					cur.Flags = append(cur.Flags, f)
				}
			}
		case key == "order":
			cur.Order, _ = strconv.Atoi(value)
			cur.HasOrder = true
		case key == "timeout":
			cur.Timeout, _ = strconv.Atoi(value)
		case key == "port":
			cur.Port, _ = strconv.Atoi(value)
		case key == "reach":
			cur.Reach = value
			cur.Reachable = strings.Contains(value, "Reachable") && !strings.Contains(value, "Not Reachable")
		case key == "if_index":
			// "16 (en1)"
			num, rest, _ := strings.Cut(value, " ")
			cur.IfIndex, _ = strconv.Atoi(num)
			cur.IfName = strings.Trim(rest, "()")
		}
	}
	flush()
	if sc.Err() != nil {
		cfg.Incomplete = true
	}
	return cfg
}
