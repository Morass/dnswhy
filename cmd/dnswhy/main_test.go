package main

import (
	"reflect"
	"testing"

	"github.com/morass/dnswhy/internal/dnsconf"
)

func TestServerAddressUsesTheResolverPort(t *testing.T) {
	cases := []struct {
		name string
		res  dnsconf.Resolver
		want string
	}{
		{"no port", dnsconf.Resolver{Nameservers: []string{"198.51.100.53"}}, "198.51.100.53"},
		{"port 53", dnsconf.Resolver{Nameservers: []string{"198.51.100.53"}, Port: 53}, "198.51.100.53"},
		{"other port", dnsconf.Resolver{Nameservers: []string{"198.51.100.53"}, Port: 5353}, "198.51.100.53:5353"},
		{"IPv6", dnsconf.Resolver{Nameservers: []string{"2001:db8::53"}, Port: 5353}, "[2001:db8::53]:5353"},
		{"already has one", dnsconf.Resolver{Nameservers: []string{"198.51.100.53:5354"}, Port: 5353}, "198.51.100.53:5354"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := serverAddress(c.res, 0); got != c.want {
				t.Errorf("serverAddress = %q, want %q", got, c.want)
			}
		})
	}
}

func TestServerAddressPicksTheNthNameserver(t *testing.T) {
	r := dnsconf.Resolver{Nameservers: []string{"198.51.100.53", "198.51.100.54"}, Port: 5353}
	if got := serverAddress(r, 1); got != "198.51.100.54:5353" {
		t.Errorf("serverAddress = %q", got)
	}
}

func TestReorderMovesFlagsAheadWithTheirValues(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"example.com", "--json"}, []string{"--json", "example.com"}},
		{[]string{"example.com", "--timeout", "5s"}, []string{"--timeout", "5s", "example.com"}},
		{[]string{"example.com", "--timeout=5s"}, []string{"--timeout=5s", "example.com"}},
		{[]string{"--json", "example.com"}, []string{"--json", "example.com"}},
		{[]string{"--", "-weird-name"}, []string{"-weird-name"}},
	}
	for _, c := range cases {
		if got := reorder(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("reorder(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestWantsHelp(t *testing.T) {
	if !wantsHelp([]string{"doctor", "--help"}) {
		t.Error("--help must be recognised")
	}
	if wantsHelp([]string{"example.com", "--json"}) {
		t.Error("no help was asked for")
	}
}
