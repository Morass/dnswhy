package lookup

import (
	"net"
	"strings"
	"testing"
	"time"
)

// reply builds a DNS answer for the question in q, with the given rcode and
// answer records already encoded.
func reply(q []byte, rcode byte, flags byte, answers [][]byte) []byte {
	msg := []byte{q[0], q[1], 0x81 | flags, 0x80 | rcode, 0, 1, byte(len(answers) >> 8), byte(len(answers)), 0, 0, 0, 0}
	msg = append(msg, q[12:]...) // the question section, verbatim
	for _, a := range answers {
		msg = append(msg, a...)
	}
	return msg
}

// aRecord is an answer that points its name back at the question with a
// compression pointer, the way every real nameserver does.
func aRecord(ip net.IP) []byte {
	rec := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	return append(rec, ip.To4()...)
}

func startServer(t *testing.T, handle func(q []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := make([]byte, n)
			copy(q, buf[:n])
			if out := handle(q); out != nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestDirectReadsAnAnswer(t *testing.T) {
	server := startServer(t, func(q []byte) []byte {
		if q[len(q)-3] == 28 { // AAAA: answer with nothing
			return reply(q, 0, 0, nil)
		}
		return reply(q, 0, 0, [][]byte{aRecord(net.ParseIP("198.51.100.20"))})
	})
	got := Direct(server, "host.corp.internal", time.Second)
	if !got.OK() || got.Addresses[0] != "198.51.100.20" {
		t.Fatalf("answer = %+v", got)
	}
	if got.Status != "" {
		t.Errorf("a successful answer must carry no status, got %q", got.Status)
	}
}

func TestDirectReportsNXDOMAIN(t *testing.T) {
	server := startServer(t, func(q []byte) []byte { return reply(q, 3, 0, nil) })
	got := Direct(server, "absent.example", time.Second)
	if got.Status != "NXDOMAIN" {
		t.Errorf("status = %q, want NXDOMAIN", got.Status)
	}
	if got.OK() {
		t.Error("NXDOMAIN carries no addresses")
	}
}

func TestDirectReportsRefusedAndServfail(t *testing.T) {
	for rcode, want := range map[byte]string{2: "SERVFAIL", 5: "refused"} {
		server := startServer(t, func(q []byte) []byte { return reply(q, rcode, 0, nil) })
		if got := Direct(server, "example.com", time.Second); got.Status != want {
			t.Errorf("rcode %d gave %q, want %q", rcode, got.Status, want)
		}
	}
}

func TestDirectTimesOutWithoutHanging(t *testing.T) {
	server := startServer(t, func(q []byte) []byte { return nil }) // never answers
	start := time.Now()
	got := Direct(server, "example.com", 200*time.Millisecond)
	if got.Status != "timeout" {
		t.Errorf("status = %q, want timeout", got.Status)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Direct took %s, the timeout must bound both questions", elapsed)
	}
}

func TestDirectIgnoresAReplyWithTheWrongID(t *testing.T) {
	server := startServer(t, func(q []byte) []byte {
		r := reply(q, 0, 0, [][]byte{aRecord(net.ParseIP("203.0.113.1"))})
		r[0] ^= 0xff // a different transaction
		return r
	})
	got := Direct(server, "example.com", 500*time.Millisecond)
	if got.OK() {
		t.Errorf("a mismatched reply must not be believed: %+v", got)
	}
}

// A nameserver on a hostile network can send anything at all; none of it may
// crash the tool.
func TestParseReplySurvivesMalformedMessages(t *testing.T) {
	q, err := buildQuery("example.com", typeA)
	if err != nil {
		t.Fatal(err)
	}
	good := reply(q, 0, 0, [][]byte{aRecord(net.ParseIP("198.51.100.30"))})
	cases := map[string][]byte{
		"empty":               {},
		"header only":         good[:12],
		"cut in the question": good[:20],
		"cut in the record":   good[:len(good)-2],
		"self-pointing name":  append(append([]byte{}, good[:12]...), 0xc0, 0x0c),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			addrs, _, status, _ := parseReply(msg, q[0:2])
			if len(addrs) != 0 {
				t.Errorf("malformed message yielded addresses: %v", addrs)
			}
			if status == "" {
				t.Error("a malformed message must report a status")
			}
		})
	}
}

func TestParseReplyRejectsOversizedRecordLength(t *testing.T) {
	q, _ := buildQuery("example.com", typeA)
	rec := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0xff, 0xff}
	msg := reply(q, 0, 0, [][]byte{rec})
	_, _, status, _ := parseReply(msg, q[0:2])
	if status != "bad reply" {
		t.Errorf("status = %q, want 'bad reply'", status)
	}
}

func TestParseReplyReportsTruncation(t *testing.T) {
	q, _ := buildQuery("example.com", typeA)
	msg := reply(q, 0, 0x02, nil) // TC set, no answers
	_, _, status, _ := parseReply(msg, q[0:2])
	if status != "truncated" {
		t.Errorf("status = %q, want truncated", status)
	}
}

func TestBuildQueryRejectsUnusableNames(t *testing.T) {
	for _, name := range []string{"", "a..b", strings.Repeat("x", 64) + ".example"} {
		if _, err := buildQuery(name, typeA); err == nil {
			t.Errorf("buildQuery(%q) should fail", name)
		}
	}
}

func TestParseDSCacheUtil(t *testing.T) {
	out := `name: host.corp.internal
ip_address: 198.51.100.9
ipv6_address: 2001:db8::1

name: host.corp.internal
ip_address: 198.51.100.9
`
	got := parseDSCacheUtil(out)
	if len(got) != 2 || got[0] != "198.51.100.9" || got[1] != "2001:db8::1" {
		t.Errorf("addresses = %v", got)
	}
}

func TestAnswerSummary(t *testing.T) {
	if got := (Answer{Addresses: []string{"198.51.100.1"}}).Summary(); got != "198.51.100.1" {
		t.Errorf("summary = %q", got)
	}
	if got := (Answer{Status: "NXDOMAIN", Detail: "no such name"}).Summary(); got != "NXDOMAIN (no such name)" {
		t.Errorf("summary = %q", got)
	}
	if got := (Answer{}).Summary(); got != "no answer" {
		t.Errorf("summary = %q", got)
	}
}
