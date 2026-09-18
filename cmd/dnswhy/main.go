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
	"syscall"
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
	live        bool
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
	fs.BoolVar(&o.live, "live", false, "resolve for real even though the configuration came from a file")
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

	// Asking anything at all is only safe when the configuration on screen is
	// this machine's: a dump captured elsewhere describes someone else's
	// resolvers, and a name that is private there would go to whatever this
	// machine uses. A replayed configuration is therefore explained, not
	// resolved, unless --live says otherwise.
	replay := o.scutilFile != "" || o.hostsFile != defaultHosts || o.resolverDir != defaultResolverDir
	switch {
	case o.offline:
	case cfg.Incomplete:
		fmt.Fprintln(stderr, "dnswhy: the configuration could not be read to the end, so nothing was asked; the explanation below may be missing a resolver")
	case replay && !o.live:
		// explained only; --live is the opt-in
	default:
		sys := lookup.System(name, o.timeout)
		exp.System = &sys

		asked := map[string]bool{}
		// ask works through one resolver's nameservers, and then through the
		// resolvers that share its domain, exactly as resolver(5) describes:
		// another server is tried when one does not answer, never when it
		// answers that the name is not there.
		ask := func(chain []dnsconf.Resolver) bool {
			for _, r := range chain {
				for i := range r.Nameservers {
					server, ok := serverAddress(r, i)
					if !ok {
						exp.Direct = append(exp.Direct, lookup.Answer{
							Via:    r.Nameservers[i],
							Status: "unusable",
							Detail: "the configuration gives this as a nameserver, and it is not an address",
						})
						continue
					}
					if asked[server] {
						continue
					}
					asked[server] = true
					// name keeps any trailing dot the user typed: it tells the
					// system resolver the name is absolute and must not be
					// expanded with a search domain.
					got := lookup.Direct(server, name, o.timeout)
					exp.Direct = append(exp.Direct, got)
					if got.OK() || got.Answered() {
						return true
					}
				}
			}
			return false
		}

		// Only a name that a nameserver would be asked about is asked about:
		// a hosts entry and a Bonjour name reach no nameserver at all.
		if result.Mechanism == match.Unicast && len(result.Chain) > 0 {
			ask(result.Chain)
		}
		if o.compare && def != nil && result.Mechanism == match.Unicast {
			ask([]dnsconf.Resolver{*def})
		}

		// A name with no dot is tried as each expansion in turn, and macOS
		// stops at the first that answers - so dnswhy stops there too, rather
		// than handing the later expansions to nameservers that would never
		// have seen them.
		for _, at := range result.Attempts {
			if at.Name == result.Query {
				continue
			}
			if at.InHosts {
				break // the hosts file answers; nothing is asked
			}
			if at.Mechanism != match.Unicast || !at.HasWinner {
				continue
			}
			r, ok := cfg.ByID(at.WinnerID)
			if !ok {
				continue
			}
			sub := match.Explain(cfg, hosts, at.Name)
			chain := sub.Chain
			if len(chain) == 0 {
				chain = []dnsconf.Resolver{r}
			}
			answered := false
			for _, res := range chain {
				for i := range res.Nameservers {
					server, ok := serverAddress(res, i)
					if !ok {
						continue
					}
					got := lookup.Direct(server, at.Name, o.timeout)
					exp.Attempts = append(exp.Attempts, render.AttemptAnswer{Name: at.Name, Answer: got})
					if got.OK() || got.Answered() {
						answered = true
						break
					}
				}
				if answered {
					break
				}
			}
			if answered {
				break // macOS would stop here as well
			}
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
	// Open first and check the descriptor: between a check on the path and the
	// open that follows it, the entry can become a link to something else or a
	// pipe that never returns.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not an ordinary file", path)
	}
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
func serverAddress(r dnsconf.Resolver, n int) (string, bool) {
	ns := strings.TrimSpace(r.Nameservers[n])
	// Whatever produced this text, it has to be an address before anything is
	// sent to it or printed as part of a command.
	host, port := ns, ""
	if h, p, err := net.SplitHostPort(ns); err == nil {
		host, port = h, p
	}
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		return "", false
	}
	if port != "" {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return "", false
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port), true
	}
	if r.Port == 0 || r.Port == 53 {
		return net.JoinHostPort(strings.Trim(host, "[]"), "53"), true
	}
	if r.Port < 1 || r.Port > 65535 {
		return "", false
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(r.Port)), true
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
  name that a VPN or container scope claims is never sent to a public resolver,
  and a name answered from the hosts file or by Bonjour is not sent anywhere.
  --compare asks the default nameserver as well, which is what a plain dig does.

  A configuration read from a file (--scutil-file, --hosts-file, --resolver-dir)
  describes another machine, so it is explained and nothing is asked; --live
  resolves for real against this machine's network anyway.

Flags:
  --compare                 also ask the default nameserver (sends the name outside its scope)
  --live                    resolve for real even though the configuration came from a file
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
