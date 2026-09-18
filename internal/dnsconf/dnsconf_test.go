package dnsconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) Config {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return Parse(string(b))
}

func TestParseSplitsInterfaceScopedResolvers(t *testing.T) {
	cfg := load(t, "simple.scutil")
	if got, want := len(cfg.Resolvers), 3; got != want {
		t.Fatalf("resolvers = %d, want %d", got, want)
	}
	if got, want := len(cfg.Unscoped()), 2; got != want {
		t.Errorf("unscoped = %d, want %d", got, want)
	}
	ifs := cfg.InterfaceScoped()
	if len(ifs) != 1 {
		t.Fatalf("interface-scoped = %d, want 1", len(ifs))
	}
	if ifs[0].IfName != "en0" || ifs[0].IfIndex != 16 {
		t.Errorf("if_index parsed as %d (%q), want 16 (en0)", ifs[0].IfIndex, ifs[0].IfName)
	}
}

func TestParseResolverFields(t *testing.T) {
	cfg := load(t, "simple.scutil")
	first := cfg.Resolvers[0]
	if got, want := len(first.Nameservers), 2; got != want {
		t.Fatalf("nameservers = %d, want %d", got, want)
	}
	if first.Nameservers[1] != "192.0.2.54" {
		t.Errorf("second nameserver = %q", first.Nameservers[1])
	}
	if !first.Reachable {
		t.Error("resolver #1 should be reachable")
	}
	if !first.Default() {
		t.Error("resolver #1 claims no domain, so it is the default")
	}

	mdns := cfg.Resolvers[1]
	if !mdns.IsMulticast() {
		t.Error("resolver #2 has options mdns")
	}
	if mdns.Reachable {
		t.Error("'Not Reachable' must not parse as reachable")
	}
	if !mdns.HasOrder || mdns.Order != 300000 {
		t.Errorf("order = %d (set %v), want 300000", mdns.Order, mdns.HasOrder)
	}
	if mdns.Timeout != 5 {
		t.Errorf("timeout = %d, want 5", mdns.Timeout)
	}
}

func TestParseIgnoresUnknownKeysAndJunk(t *testing.T) {
	cfg := Parse(`DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53
  brand_new_key : whatever
  a line with no colon
  search domain[0] : example.internal
  flags    : Request A records
`)
	if len(cfg.Resolvers) != 1 {
		t.Fatalf("resolvers = %d, want 1", len(cfg.Resolvers))
	}
	r := cfg.Resolvers[0]
	if len(r.SearchDomains) != 1 || r.SearchDomains[0] != "example.internal" {
		t.Errorf("search domains = %v", r.SearchDomains)
	}
}

func TestParseEmptyInput(t *testing.T) {
	if got := Parse(""); len(got.Resolvers) != 0 {
		t.Errorf("empty input gave %d resolvers", len(got.Resolvers))
	}
}

// A dump that cannot be read to the end must say so rather than quietly drop
// the resolvers it did not reach.
func TestOversizedLineMarksTheConfigurationIncomplete(t *testing.T) {
	huge := "DNS configuration\n\nresolver #1\n  nameserver[0] : " + strings.Repeat("9", 5*1024*1024) + "\n"
	cfg := Parse(huge)
	if !cfg.Incomplete {
		t.Error("a dump that could not be parsed to the end must be marked incomplete")
	}
}
