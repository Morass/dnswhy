// Package lookup asks for a name twice: once the way every application does,
// and once directly of a nameserver, the way dig does. The two paths disagree
// often enough on macOS that seeing them side by side is the point of the tool.
package lookup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Answer is one attempt to resolve a name.
type Answer struct {
	// Via is "system" for the resolver every application uses, or the address
	// of the nameserver that was asked directly.
	Via       string   `json:"via"`
	Addresses []string `json:"addresses,omitempty"`
	CNAMEs    []string `json:"cnames,omitempty"`
	// Status is empty on success, otherwise a short machine-readable word such
	// as "NXDOMAIN", "timeout" or "refused".
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// OK reports whether the answer carries addresses.
func (a Answer) OK() bool { return len(a.Addresses) > 0 }

// Summary is a one-line description of the outcome.
func (a Answer) Summary() string {
	switch {
	case a.OK():
		return strings.Join(a.Addresses, ", ")
	case a.Status != "":
		if a.Detail != "" {
			return a.Status + " (" + a.Detail + ")"
		}
		return a.Status
	default:
		return "no answer"
	}
}

// System resolves the way applications do, through mDNSResponder. It shells out
// to dscacheutil, which asks the system resolver exactly as getaddrinfo would,
// and falls back to the Go resolver where dscacheutil does not exist.
func System(name string, timeout time.Duration) Answer {
	a := Answer{Via: "system"}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if _, err := exec.LookPath("dscacheutil"); err == nil {
		out, err := exec.CommandContext(ctx, "dscacheutil", "-q", "host", "-a", "name", name).Output()
		if err == nil {
			a.Addresses = parseDSCacheUtil(string(out))
			if len(a.Addresses) == 0 {
				a.Status = "no answer"
				a.Detail = "nothing your applications can connect to"
			}
			return a
		}
		if ctx.Err() != nil {
			a.Status = "timeout"
			a.Detail = fmt.Sprintf("dscacheutil did not answer within %s", timeout)
			return a
		}
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		a.Status = "no answer"
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound {
				a.Status = "NXDOMAIN"
			} else if dnsErr.IsTimeout {
				a.Status = "timeout"
			}
			a.Detail = dnsErr.Err
		} else {
			a.Detail = err.Error()
		}
		return a
	}
	a.Addresses = addrs
	return a
}

// parseDSCacheUtil pulls the addresses out of dscacheutil's record output.
func parseDSCacheUtil(out string) []string {
	var addrs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" || (key != "ip_address" && key != "ipv6_address") {
			continue
		}
		if !seen[value] {
			seen[value] = true
			addrs = append(addrs, value)
		}
	}
	return addrs
}

// Direct asks one nameserver over UDP, the way dig does: no /etc/hosts, no
// scoped resolvers, no Bonjour.
func Direct(server, name string, timeout time.Duration) Answer {
	a := Answer{Via: server}
	addr := server
	if !strings.Contains(server, "]") && strings.Count(server, ":") > 1 {
		addr = "[" + server + "]" // bare IPv6
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}

	for _, qtype := range []uint16{typeA, typeAAAA} {
		addrs, cnames, status, detail := query(addr, name, qtype, timeout)
		a.Addresses = append(a.Addresses, addrs...)
		a.CNAMEs = append(a.CNAMEs, cnames...)
		if status != "" && a.Status == "" {
			a.Status, a.Detail = status, detail
		}
	}
	if len(a.Addresses) > 0 {
		if a.Status != "truncated" {
			a.Status, a.Detail = "", ""
		}
		sort.Strings(a.Addresses)
	}
	a.CNAMEs = dedupe(a.CNAMEs)
	return a
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

const (
	typeA     uint16 = 1
	typeAAAA  uint16 = 28
	typeCNAME uint16 = 5
	classIN   uint16 = 1
)

// query sends one question and reads one reply. It is deliberately minimal: a
// single UDP exchange with no retries, because the caller is diagnosing, not
// resolving.
func query(server, name string, qtype uint16, timeout time.Duration) (addrs, cnames []string, status, detail string) {
	msg, err := buildQuery(name, qtype)
	if err != nil {
		return nil, nil, "bad name", err.Error()
	}
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, nil, "unreachable", err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return nil, nil, "unreachable", err.Error()
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, nil, "timeout", fmt.Sprintf("no reply within %s", timeout)
		}
		return nil, nil, "no reply", err.Error()
	}
	return parseReply(buf[:n], msg)
}

func buildQuery(name string, qtype uint16) ([]byte, error) {
	var b []byte
	id := uint16(rand.Intn(1 << 16)) //nolint:gosec // a diagnostic query, not a resolver
	b = append(b, byte(id>>8), byte(id))
	b = append(b, 0x01, 0x00) // recursion desired
	b = append(b, 0x00, 0x01) // one question
	b = append(b, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%q is not a usable name", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, byte(qtype>>8), byte(qtype))
	b = append(b, 0x00, 0x01) // class IN
	return b, nil
}

// parseReply reads a reply and accepts only what actually answers the question
// that was asked: the same transaction id, a response bit, the identical
// question section, and address records whose owner name is the question or a
// name the reply itself pointed at with a CNAME.
func parseReply(msg []byte, question []byte) (addrs, cnames []string, status, detail string) {
	if len(question) < 13 {
		return nil, nil, "bad reply", "the question was not a DNS message"
	}
	if len(msg) < 12 {
		return nil, nil, "bad reply", "the reply was too short to be DNS"
	}
	if msg[0] != question[0] || msg[1] != question[1] {
		return nil, nil, "bad reply", "the reply did not match the question"
	}
	if msg[2]&0x80 == 0 {
		return nil, nil, "bad reply", "the packet was a question, not an answer"
	}
	truncated := msg[2]&0x02 != 0
	switch rcode := msg[3] & 0x0f; rcode {
	case 0:
	case 2:
		return nil, nil, "SERVFAIL", "the nameserver failed to answer"
	case 3:
		return nil, nil, "no such name", "the nameserver says this name does not exist (NXDOMAIN)"
	case 5:
		return nil, nil, "refused", "the nameserver refused the question"
	default:
		return nil, nil, fmt.Sprintf("rcode %d", rcode), ""
	}

	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	if qd != 1 {
		return nil, nil, "bad reply", "the reply did not echo exactly one question"
	}
	// The question section must be the one that was sent, byte for byte.
	qname, off, err := readName(msg, 12)
	if err != nil {
		return nil, nil, "bad reply", err.Error()
	}
	if off+4 > len(msg) || !bytes.Equal(msg[12:off+4], question[12:]) {
		return nil, nil, "bad reply", "the reply answered a different question"
	}
	off += 4

	// Only records owned by the question, or by a name a CNAME in this reply
	// pointed at, are an answer to it.
	owners := map[string]bool{strings.ToLower(qname): true}
	for i := 0; i < an && off < len(msg); i++ {
		owner, next, err := readName(msg, off)
		if err != nil {
			return nil, nil, "bad reply", err.Error()
		}
		off = next
		if off+10 > len(msg) {
			return nil, nil, "bad reply", "a record ran past the end of the reply"
		}
		rtype := uint16(msg[off])<<8 | uint16(msg[off+1])
		rclass := uint16(msg[off+2])<<8 | uint16(msg[off+3])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdlen > len(msg) {
			return nil, nil, "bad reply", "a record ran past the end of the reply"
		}
		known := owners[strings.ToLower(owner)]
		switch {
		case rclass != classIN || !known:
			// Not an answer to this question: an unrelated record riding along.
		case rtype == typeA && rdlen == 4:
			addrs = append(addrs, net.IP(msg[off:off+4]).String())
		case rtype == typeAAAA && rdlen == 16:
			addrs = append(addrs, net.IP(msg[off:off+16]).String())
		case rtype == typeCNAME:
			if n, _, err := readName(msg, off); err == nil {
				cnames = append(cnames, n)
				owners[strings.ToLower(n)] = true
			}
		}
		off += rdlen
	}
	if truncated && len(addrs) > 0 {
		return addrs, cnames, "truncated", "the reply did not fit in a UDP packet, so this may be part of the answer"
	}
	if len(addrs) == 0 {
		if truncated {
			return nil, cnames, "truncated", "the reply did not fit in a UDP packet"
		}
		return nil, cnames, "no address", "the name exists, but it has no address record of this kind"
	}
	return addrs, cnames, "", ""
}

func skipName(msg []byte, off int) (int, error) {
	_, next, err := readName(msg, off)
	return next, err
}

// readName decodes a possibly compressed name and returns the offset just past
// it in the message.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	start := off
	jumped := false
	for hops := 0; ; hops++ {
		if hops > 64 {
			return "", 0, errors.New("a compressed name pointed at itself")
		}
		if off >= len(msg) {
			return "", 0, errors.New("a name ran past the end of the reply")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			off++
			if !jumped {
				start = off
			}
			return strings.Join(labels, "."), start, nil
		case l&0xc0 == 0x40, l&0xc0 == 0x80:
			// Reserved label types (RFC 6891). Nothing sends them, and reading
			// the byte as a length would walk off into the rest of the packet.
			return "", 0, errors.New("the reply used a label type that is not defined")
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("a name ran past the end of the reply")
			}
			ptr := (l&0x3f)<<8 | int(msg[off+1])
			if !jumped {
				start = off + 2
				jumped = true
			}
			off = ptr
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("a name ran past the end of the reply")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}
