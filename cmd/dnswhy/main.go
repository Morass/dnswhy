// Command dnswhy explains how this Mac resolves a name: which resolver wins,
// why, and what a direct question to a nameserver says instead.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
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
	offline     bool
	noColour    bool
	timeout     time.Duration
	scutilFile  string
	hostsFile   string
	resolverDir string
}

func (o *options) register(fs *flag.FlagSet) {
	fs.BoolVar(&o.json, "json", false, "print the findings as JSON")
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
		fmt.Fprintf(stderr, "dnswhy: unknown flag %q\n", args[0])
		return 2
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
		b, err := os.ReadFile(o.scutilFile)
		if err != nil {
			return cfg, resolverdir.Dir{}, hostsfile.File{}, err
		}
		cfg = dnsconf.Parse(string(b))
	} else {
		var err error
		cfg, err = dnsconf.Run()
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
	name := strings.TrimSuffix(strings.TrimSpace(fs.Arg(0)), ".")
	if name == "" {
		fmt.Fprintln(stderr, "dnswhy: give me a name to explain")
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
		// What a plain `dig` would do: ask the default nameserver.
		if def != nil && len(def.Nameservers) > 0 {
			exp.Direct = append(exp.Direct, lookup.Direct(def.Nameservers[0], name, o.timeout))
			asked[def.Nameservers[0]] = true
		}
		// And what the resolver that actually wins says, when it is another one.
		if w := result.Winner; w != nil && len(w.Nameservers) > 0 && !asked[w.Nameservers[0]] {
			exp.Direct = append(exp.Direct, lookup.Direct(w.Nameservers[0], name, o.timeout))
		}
	}
	exp.Verdict = verdict.Lines(verdict.Input{
		Result: result, System: exp.System, Direct: exp.Direct, Default: def, HostsPath: hosts.Path,
	})

	if o.json {
		return writeJSON(stdout, stderr, exp)
	}
	render.Explain(stdout, exp, style(o, stdout))
	return 0
}

func doctorCmd(args []string, stdout, stderr io.Writer) int {
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
		return writeJSON(stdout, stderr, rep)
	}
	render.Doctor(stdout, rep, style(o, stdout))
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

Flags:
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
