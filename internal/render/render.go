// Package render turns an explanation or a doctor report into the text a
// person reads.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/morass/dnswhy/internal/dnsconf"
	"github.com/morass/dnswhy/internal/doctor"
	"github.com/morass/dnswhy/internal/lookup"
	"github.com/morass/dnswhy/internal/match"
	"github.com/morass/dnswhy/internal/resolverdir"
)

// wrapWidth is the column the long explanatory lines wrap at. It is fixed
// rather than taken from the terminal so the same text appears in a narrow
// window, a wide one and a file.
const wrapWidth = 78

// plural writes "1 scope" and "3 scopes".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// wrap breaks text into lines of at most width runes, on word boundaries. A
// word longer than the width is left alone rather than cut in half.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, w := range words[1:] {
		last := len(lines) - 1
		if len([]rune(lines[last]))+1+len([]rune(w)) <= width {
			lines[last] += " " + w
			continue
		}
		lines = append(lines, w)
	}
	return lines
}

// Style holds the escape sequences to use, or nothing at all when colour is off.
type Style struct{ Colour bool }

func (s Style) wrap(code, text string) string {
	if !s.Colour {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Green(t string) string  { return s.wrap("32", t) }
func (s Style) Yellow(t string) string { return s.wrap("33", t) }
func (s Style) Red(t string) string    { return s.wrap("31", t) }
func (s Style) Cyan(t string) string   { return s.wrap("36", t) }

// AttemptAnswer is what one search-domain expansion actually returned.
type AttemptAnswer struct {
	Name   string        `json:"name"`
	Answer lookup.Answer `json:"answer"`
}

// Explanation is everything the explain command found out.
type Explanation struct {
	Result    match.Result      `json:"result"`
	Attempts  []AttemptAnswer   `json:"attempt_answers,omitempty"`
	HostsPath string            `json:"hosts_path"`
	Files     resolverdir.Dir   `json:"resolver_files"`
	System    *lookup.Answer    `json:"system,omitempty"`
	Direct    []lookup.Answer   `json:"direct,omitempty"`
	Default   *dnsconf.Resolver `json:"default_resolver,omitempty"`
	Verdict   []string          `json:"verdict,omitempty"`
}

// Explain writes the human-readable explanation.
func Explain(w io.Writer, e Explanation, st Style) {
	r := e.Result
	fmt.Fprintf(w, "%s  %s\n\n", st.Bold("Question"), st.Bold(r.Query))

	if len(r.Attempts) > 0 {
		fmt.Fprintf(w, "%s\n", st.Bold("A name with no dot, so it is tried with each search domain first"))
		for i, a := range r.Attempts {
			lead := "  then as"
			if i == 0 {
				lead = "  first  "
			}
			line := fmt.Sprintf("%s %-34s %s", lead, a.Name, st.Dim("-> "+attemptTarget(a)))
			if got, ok := e.attemptAnswer(a.Name); ok {
				line += "   " + answerText(got, st)
			}
			fmt.Fprintln(w, line)
		}
		fmt.Fprintf(w, "  %s\n\n", st.Dim("the first of these that answers is the one you get; the rules below are for "+r.Query))
	}

	fmt.Fprintf(w, "%s\n", st.Bold("How macOS picks a resolver, in order"))
	step := 1
	// /etc/hosts always comes first.
	if len(r.Hosts) > 0 {
		fmt.Fprintf(w, "  %d  %-34s %s\n", step, e.HostsPath, st.Green("MATCH")+" "+st.Bold("<- wins"))
		for _, h := range r.Hosts {
			fmt.Fprintf(w, "       line %d: %s\n", h.Line, st.Cyan(h.Address))
		}
		fmt.Fprintf(w, "       %s\n", st.Dim("an entry here ends the lookup; no nameserver is asked"))
	} else {
		fmt.Fprintf(w, "  %d  %-34s %s\n", step, e.HostsPath, st.Dim("no entry"))
	}
	step++

	shown := 0
	var skipped []string
	bonjour := 0
	for _, c := range r.Candidates {
		if !c.Matched && shown >= 1 && !c.Wins {
			// The resolvers that claim some other domain are noise here, but
			// say how many there were so the list is not silently short. The
			// Bonjour reverse zones every Mac carries are counted, not named:
			// six of them in a row tell the reader nothing.
			if c.Resolver.IsMulticast() {
				bonjour++
			} else {
				skipped = append(skipped, c.Resolver.Domain)
			}
			continue
		}
		label := resolverLabel(c.Resolver)
		status := st.Dim("does not claim this name")
		switch {
		case c.Wins && len(r.Hosts) > 0:
			status = st.Yellow("MATCH") + st.Dim(" (not reached: /etc/hosts answered)")
		case c.Wins:
			status = st.Green("MATCH") + " " + st.Bold("<- wins")
		case c.Matched && c.Resolver.Default():
			status = st.Dim("would answer, but a scope claims this name first")
		case c.Matched && c.CannotAnswer:
			status = st.Yellow("claims it, but cannot answer")
		case c.Matched:
			status = st.Dim("matches, but a more specific scope wins")
		}
		fmt.Fprintf(w, "  %d  %-34s %s\n", step, label, status)
		for _, line := range resolverDetail(c, e.Files, st) {
			fmt.Fprintf(w, "       %s\n", line)
		}
		step++
		shown++
	}
	if n := len(skipped) + bonjour; n > 0 {
		var text string
		switch {
		case len(skipped) == 0:
			text = fmt.Sprintf("(%s claim names this one does not end in)", plural(bonjour, "Bonjour scope"))
		case bonjour == 0:
			text = fmt.Sprintf("(%s claim names this one does not end in: %s)", plural(n, "other scope"), strings.Join(skipped, ", "))
		default:
			text = fmt.Sprintf("(%s claim names this one does not end in: %s, and %s)",
				plural(n, "other scope"), strings.Join(skipped, ", "), plural(bonjour, "Bonjour scope"))
		}
		for _, line := range wrap(text, wrapWidth-2) {
			fmt.Fprintf(w, "  %s\n", st.Dim(line))
		}
	}
	if n := len(r.Ignored); n > 0 {
		fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("(%s not shown: they answer only interface-bound queries)", plural(n, "interface-bound resolver"))))
	}

	if e.System != nil || len(e.Direct) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("Answers"))
		if e.System != nil {
			fmt.Fprintf(w, "  %-30s %s\n", "system  (every application)", answerText(*e.System, st))
		}
		for _, d := range e.Direct {
			fmt.Fprintf(w, "  %-30s %s\n", "asked "+d.Via+" directly", answerText(d, st))
		}
	}

	if len(e.Verdict) > 0 {
		fmt.Fprintln(w)
		for _, line := range e.Verdict {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

// attemptAnswer finds what one expansion returned, if it was asked.
func (e Explanation) attemptAnswer(name string) (lookup.Answer, bool) {
	for _, a := range e.Attempts {
		if a.Name == name {
			return a.Answer, true
		}
	}
	return lookup.Answer{}, false
}

// attemptTarget names what would answer one search-domain expansion.
func attemptTarget(a match.Attempt) string {
	switch {
	case a.InHosts:
		return "an entry in the hosts file"
	case a.Mechanism == match.Multicast:
		return "multicast DNS (Bonjour)"
	case a.WinnerIndex == 0:
		return "nothing: no resolver claims it"
	case a.WinnerDomain == "":
		return fmt.Sprintf("resolver #%d (default)", a.WinnerIndex)
	default:
		return fmt.Sprintf("resolver #%d %s", a.WinnerIndex, a.WinnerDomain)
	}
}

func answerText(a lookup.Answer, st Style) string {
	if a.OK() {
		return st.Cyan(strings.Join(a.Addresses, ", "))
	}
	if a.Status == "" {
		return st.Dim("no answer")
	}
	text := st.Yellow(a.Status)
	if a.Detail != "" {
		text += st.Dim("  " + a.Detail)
	}
	return text
}

func resolverLabel(r dnsconf.Resolver) string {
	if r.Domain == "" {
		return fmt.Sprintf("resolver #%-2d (default)", r.Index)
	}
	return fmt.Sprintf("resolver #%-2d %s", r.Index, r.Domain)
}

func resolverDetail(c match.Candidate, files resolverdir.Dir, st Style) []string {
	r := c.Resolver
	var out []string
	if r.Domain != "" {
		if f, ok := files.ForDomain(r.Domain); ok {
			out = append(out, st.Dim("from "+f.Path))
		}
	}
	var bits []string
	switch {
	case r.IsMulticast():
		bits = append(bits, "multicast DNS (Bonjour)")
	case len(r.Nameservers) > 0:
		bits = append(bits, "nameserver "+strings.Join(r.Nameservers, ", "))
	default:
		bits = append(bits, "no nameserver")
	}
	if r.HasOrder {
		bits = append(bits, fmt.Sprintf("order %d", r.Order))
	}
	if r.Timeout > 0 {
		bits = append(bits, fmt.Sprintf("timeout %ds", r.Timeout))
	}
	if len(r.Nameservers) > 0 {
		if r.Reachable {
			bits = append(bits, st.Green("reachable"))
		} else {
			bits = append(bits, st.Red("not reachable"))
		}
	}
	out = append(out, strings.Join(bits, "   "))
	if c.Why != "" && (c.Wins || c.Matched) {
		out = append(out, st.Dim(c.Why))
	}
	return out
}

// Doctor writes a configuration review.
func Doctor(w io.Writer, rep doctor.Report, st Style) {
	for _, f := range rep.Findings {
		var mark string
		switch f.Level {
		case doctor.OK:
			mark = st.Green("ok  ")
		case doctor.Note:
			mark = st.Cyan("note")
		default:
			mark = st.Yellow("warn")
		}
		fmt.Fprintf(w, "%s  %s\n", mark, st.Bold(f.Title))
		for _, d := range f.Detail {
			for _, line := range wrap(d, wrapWidth-6) {
				fmt.Fprintf(w, "      %s\n", st.Dim(line))
			}
		}
	}
	ok, note, warn := rep.Counts()
	fmt.Fprintf(w, "\n%s\n", st.Dim(fmt.Sprintf("%d in order, %d worth knowing, %d worth fixing", ok, note, warn)))
}
