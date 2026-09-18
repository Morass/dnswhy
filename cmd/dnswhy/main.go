// Command dnswhy explains how this Mac resolves a name: which resolver wins,
// why, and what a direct question to a nameserver says instead.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/doctor"
	"github.com/morass/dnswhy/internal/hostsfile"
	"github.com/morass/dnswhy/internal/lookup"
	"github.com/morass/dnswhy/internal/match"
	"github.com/morass/dnswhy/internal/render"
	"github.com/morass/dnswhy/internal/resolverdir"
	"github.com/morass/dnswhy/internal/verdict"
)

// version is set at build time with -ldflags "-X main.version=..."; a plain
// `go install` falls back to the module version.
var version = ""

const (
	defaultHosts       = "/etc/hosts"
	defaultResolverDir = "/etc/resolver"
)

type options struct {
	json        bool
	compare     bool
	offline     bool
	noColour    bool
	timeout     time.Duration
	scutilFile  string
	hostsFile   string
	resolverDir string
}

func (o *options) register(fs *flag.FlagSet) {
	fs.BoolVar(&o.json, "json", false, "print the findings as JSON")
	fs.BoolVar(&o.compare, "compare", false, "also ask the default nameserver, even for a name a private scope claims")
	fs.BoolVar(&o.offline, "offline", false, "explain the configuration without asking any nameserver")
	fs.BoolVar(&o.noColour, "no-color", false, "never colour the output")
	fs.DurationVar(&o.timeout, "timeout", 3*time.Second, "how long to wait for each answer")
	fs.StringVar(&o.scutilFile, "scutil-file", "", "read a saved `scutil --dns` dump instead of running scutil")
	fs.StringVar(&o.hostsFile, "hosts-file", defaultHosts, "hosts file to read")
	fs.StringVar(&o.resolverDir, "resolver-dir", defaultResolverDir, "resolver directory to read")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, rest = args[0], args[1:]
	}

	switch cmd {
	case "help":
		return help(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, versionString())
		return 0
	case "doctor":
		return doctorCmd(rest, stdout, stderr)
	case "explain":
		return explainCmd(rest, stdout, stderr)
	case "":
		for _, a := range args {
			switch a {
			case "-h", "--help", "-help":
				usage(stdout)
				return 0
			case "-V", "--version":
				fmt.Fprintln(stdout, versionString())
				return 0
			}
		}
		if len(args) == 0 {
			usage(stdout)
			return 2
		}
		// Flags before the name: dnswhy --json example.com
		return explainCmd(args, stdout, stderr)
	default:
		// dnswhy <name> is the common case: no subcommand at all.
		return explainCmd(args, stdout, stderr)
	}
}

func versionString() string {
	if version != "" {
		return "dnswhy " + version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return "dnswhy " + bi.Main.Version
	}
	return "dnswhy (development build)"
}

// reorder puts flags before positional arguments so `dnswhy name --json` works
// the way people expect, which the flag package does not allow on its own.
func reorder(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			// A flag that takes a value and was written with a space needs its
			// value to travel with it.
			if !strings.Contains(a, "=") && needsValue(a) && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func needsValue(flagArg string) bool {
	name := strings.TrimLeft(flagArg, "-")
	switch name {
	case "timeout", "scutil-file", "hosts-file", "resolver-dir":
		return true
	}
	return false
}

// wantsHelp reports whether the user asked for help rather than mistyped a
// flag: asking is not an error, so it prints on stdout and exits 0.
func wantsHelp(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "--help", "-help":
			return true
		}
	}
	return false
}

func newFlagSet(name string, stderr io.Writer, opts *options) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts.register(fs)
	return fs
}

// load reads the three sources every command needs.
func load(o options) (dnsconf.Config, resolverdir.Dir, hostsfile.File, error) {
	var cfg dnsconf.Config
	if o.scutilFile != "" {
		b, err := readAtMost(o.scutilFile, maxFileSize)
		if err != nil {
			return cfg, resolverdir.Dir{}, hostsfile.File{}, err
		}
		cfg = dnsconf.Parse(string(b))
	} else {
		var err error
		cfg, err = dnsconf.Run(o.timeout)
		if err != nil {
			return cfg, resolverdir.Dir{}, hostsfile.File{}, fmt.Errorf("running scutil --dns: %w (dnswhy needs macOS, or --scutil-file)", err)
		}
	}
	dir, err := resolverdir.Load(o.resolverDir)
	if err != nil {
		return cfg, dir, hostsfile.File{}, fmt.Errorf("reading %s: %w", o.resolverDir, err)
	}
	hosts, err := hostsfile.Load(o.hostsFile)
	if err != nil {
		return cfg, dir, hosts, fmt.Errorf("reading %s: %w", o.hostsFile, err)
	}
	return cfg, dir, hosts, nil
}

func explainCmd(args []string, stdout, stderr io.Writer) int {
	if wantsHelp(args) {
		explainUsage(stdout)
		return 0
	}
	var o options
	fs := newFlagSet("explain", stderr, &o)
	fs.Usage = func() { explainUsage(stderr) }
	if err := fs.Parse(reorder(args)); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		explainUsage(stderr)
		return 2
	}
	name := strings.TrimSpace(fs.Arg(0))
	if err := checkName(name); err != nil {
		fmt.Fprintf(stderr, "dnswhy: %v\n", err)
		return 2
	}
	if o.timeout <= 0 {
		fmt.Fprintln(stderr, "dnswhy: --timeout must be longer than zero")
		return 2
	}

	cfg, dir, hosts, err := load(o)
	if err != nil {
		fmt.Fprintf(stderr, "dnswhy: %v\n", err)
		return 1
	}

	result := match.Explain(cfg, hosts, name)
	def := match.DefaultResolver(cfg)
	exp := render.Explanation{Result: result, HostsPath: hosts.Path, Files: dir, Default: def}

	if !o.offline {
		sys := lookup.System(name, o.timeout)
		exp.System = &sys
		asked := map[string]bool{}
		// resolver(5): the resolvers listed for a scope are tried in turn until
		// one answers, so a dead first entry must not be reported as the
		// scope failing.
		ask := func(r dnsconf.Resolver) {
			var failures []lookup.Answer
			for i := range r.Nameservers {
				server := serverAddress(r, i)
				if asked[server] {
					continue
				}
				asked[server] = true
				// name keeps any trailing dot the user typed: it tells the
				// system resolver the name is absolute and must not be
				// expanded with a search domain.
				got := lookup.Direct(server, name, o.timeout)
				if got.OK() {
					exp.Direct = append(exp.Direct, got)
					return
				}
				failures = append(failures, got)
			}
			// Nothing answered: show every server that was asked, so the one
			// that appears is never a mystery.
			exp.Direct = append(exp.Direct, failures...)
		}
		// By default dnswhy asks exactly what this Mac would ask and nothing
		// else: sending a name that a private scope claims to a public
		// nameserver would hand an internal hostname to a stranger. --compare
		// is the way to ask anyway, and says so in the help.
		if result.Mechanism == match.Unicast && result.Winner != nil {
			ask(*result.Winner)
		}
		if o.compare && def != nil {
			ask(*def)
		}

		// A name with no dot is tried as each expansion before it is tried on
		// its own, so say what each of those attempts actually returns: for a
		// name that does not resolve, that is the whole answer. Each question
		// goes only to the resolver that would have been asked for it anyway.
		for _, at := range result.Attempts {
			if at.Name == result.Query || at.InHosts || at.Mechanism != match.Unicast {
				continue
			}
			r, ok := resolverByIndex(cfg, at.WinnerIndex)
			if !ok || len(r.Nameservers) == 0 {
				continue
			}
			got := lookup.Direct(serverAddress(r, 0), at.Name, o.timeout)
			exp.Attempts = append(exp.Attempts, render.AttemptAnswer{Name: at.Name, Answer: got})
		}
	}
	var attemptAnswers []lookup.Answer
	for _, a := range exp.Attempts {
		attemptAnswers = append(attemptAnswers, a.Answer)
	}
	exp.Verdict = verdict.Lines(verdict.Input{
		Result: result, System: exp.System, Direct: exp.Direct, AttemptAnswers: attemptAnswers,
		Default: def, HostsPath: hosts.Path,
	})

	if o.json {
		return writeJSON(stdout, stderr, exp)
	}
	render.Explain(stdout, exp, style(o, stdout))
	return 0
}

// maxFileSize bounds every file the tool is pointed at. A configuration dump is
// a few kilobytes; /dev/zero is not, and neither is a file someone hands you.
const maxFileSize = 8 << 20

// readAtMost reads an ordinary file, and no more of it than it should need.
func readAtMost(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not an ordinary file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB, which is not a DNS configuration", path, limit>>20)
	}
	return b, nil
}

// checkName rejects anything that is not a hostname. It keeps control
// characters out of the terminal, and keeps shell metacharacters out of the
// commands the tool prints for the reader to copy.
func checkName(name string) error {
	if name == "" {
		return errors.New("give me a name to explain")
	}
	if len(name) > 253 {
		return errors.New("a hostname cannot be longer than 253 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return fmt.Errorf("%q is not a hostname: only letters, digits, '-', '_' and '.' are allowed (use punycode for an international name)", name)
		}
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			return fmt.Errorf("%q has an empty label", name)
		}
		if len(label) > 63 {
			return fmt.Errorf("%q has a label longer than 63 characters", name)
		}
	}
	return nil
}

// resolverByIndex finds a resolver by the number scutil printed for it.
func resolverByIndex(cfg dnsconf.Config, index int) (dnsconf.Resolver, bool) {
	for _, r := range cfg.Unscoped() {
		if r.Index == index {
			return r, true
		}
	}
	return dnsconf.Resolver{}, false
}

// serverAddress is the nth nameserver of a resolver, with the resolver's own
// port when it sets one: a local dnsmasq or a container often listens somewhere
// other than 53, and asking port 53 there would answer a different question
// from the one the system asks.
func serverAddress(r dnsconf.Resolver, n int) string {
	ns := r.Nameservers[n]
	if r.Port == 0 || r.Port == 53 {
		return ns
	}
	if _, _, err := net.SplitHostPort(ns); err == nil {
		return ns // the address already carries a port
	}
	return net.JoinHostPort(strings.Trim(ns, "[]"), strconv.Itoa(r.Port))
}

func doctorCmd(args []string, stdout, stderr io.Writer) int {
	if wantsHelp(args) {
		doctorUsage(stdout)
		return 0
	}
	var o options
	fs := newFlagSet("doctor", stderr, &o)
	fs.Usage = func() { doctorUsage(stderr) }
	if err := fs.Parse(reorder(args)); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		doctorUsage(stderr)
		return 2
	}
	cfg, dir, hosts, err := load(o)
	if err != nil {
		fmt.Fprintf(stderr, "dnswhy: %v\n", err)
		return 1
	}
	rep := doctor.Run(cfg, dir, hosts)
	if o.json {
		if code := writeJSON(stdout, stderr, rep); code != 0 {
			return code
		}
	} else {
		render.Doctor(stdout, rep, style(o, stdout))
	}
	// The exit status is part of the interface in both formats.
	if _, _, warn := rep.Counts(); warn > 0 {
		return 1
	}
	return 0
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(stderr, "dnswhy: %v\n", err)
		return 1
	}
	return 0
}

func style(o options, stdout io.Writer) render.Style {
	if o.noColour || os.Getenv("NO_COLOR") != "" {
		return render.Style{}
	}
	f, ok := stdout.(*os.File)
	if !ok {
		return render.Style{}
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return render.Style{}
	}
	return render.Style{Colour: true}
}

func help(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "explain":
		explainUsage(stdout)
	case "doctor":
		doctorUsage(stdout)
	case "version":
		fmt.Fprintln(stdout, "dnswhy version\n\n  Print the version and exit.")
	default:
		fmt.Fprintf(stderr, "dnswhy: no help for %q\n", args[0])
		return 2
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprint(w, `dnswhy - why does this Mac resolve a name that way?

Usage:
  dnswhy <name>        explain how this Mac resolves a name
  dnswhy doctor        review the whole DNS configuration
  dnswhy help [cmd]    help for a command
  dnswhy version       print the version

Examples:
  dnswhy example.com               which resolver answers, and what it says
  dnswhy printer.local             why dig cannot see Bonjour names
  dnswhy myhost --json             the same findings for a script
  dnswhy doctor                    what in this configuration will bite

Common flags (see `+"`dnswhy help explain`"+` for all of them):
  --offline            do not ask any nameserver, only explain the configuration
  --compare            also ask the default nameserver, even for a name a scope claims
  --json               print JSON instead of text
`)
}

func explainUsage(w io.Writer) {
	fmt.Fprint(w, `dnswhy [explain] <name>

  Show which resolver macOS uses for a name and why, then ask for the name
  twice: once through the system resolver, as every application does, and once
  by asking a nameserver directly, as dig does. When those two disagree, the
  reason is printed in plain words.

Examples:
  dnswhy files.corp.internal       a name a VPN or container scope claims
  dnswhy printer.local             a Bonjour name
  dnswhy build                     a single-label name and the search domains
  dnswhy example.com --offline     no lookups, just the rules

  By default it asks only the nameserver this Mac would ask for that name, so a
  name that a VPN or container scope claims is never sent to a public resolver.
  --compare asks the default nameserver as well, which is what a plain dig does.

Flags:
  --compare                 also ask the default nameserver (sends the name outside its scope)
  --offline                 explain the configuration without asking anything
  --json                    print the findings as JSON
  --timeout <duration>      how long to wait for each answer (default 3s)
  --no-color                never colour the output
  --hosts-file <path>       hosts file to read (default /etc/hosts)
  --resolver-dir <path>     resolver directory (default /etc/resolver)
  --scutil-file <path>      read a saved 'scutil --dns' dump instead of running it
`)
}

func doctorUsage(w io.Writer) {
	fmt.Fprint(w, `dnswhy doctor

  Review the whole DNS configuration and report what will bite: scopes whose
  nameserver cannot be reached, resolver files that are not in effect, two
  files claiming one domain, search domains that turn a bare word into an
  answer, and hosts entries that shadow a scope.

  Exits 1 when anything is worth fixing, so it can gate a script.

Examples:
  dnswhy doctor
  dnswhy doctor --json

Flags:
  --json                    print the findings as JSON
  --no-color                never colour the output
  --hosts-file <path>       hosts file to read (default /etc/hosts)
  --resolver-dir <path>     resolver directory (default /etc/resolver)
  --scutil-file <path>      read a saved 'scutil --dns' dump instead of running it
`)
}
