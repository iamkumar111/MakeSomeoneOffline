package discovery

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildMDNSResponse crafts a minimal mDNS response: optional question plus
// answer RRs of (ownerName, qtype, rdataIP).
func buildMDNSResponse(question string, answers []struct {
	name  string
	typ   uint16
	rdata net.IP
}) []byte {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[2:4], 0x8400) // response, authoritative
	qd := 0
	if question != "" {
		qd = 1
	}
	binary.BigEndian.PutUint16(pkt[4:6], uint16(qd))
	binary.BigEndian.PutUint16(pkt[6:8], uint16(len(answers)))
	if question != "" {
		pkt = appendDNSName(pkt, question)
		pkt = append(pkt, 0, 28, 0, 1) // QTYPE AAAA, QCLASS IN
	}
	for _, a := range answers {
		pkt = appendDNSName(pkt, a.name)
		typ := make([]byte, 2)
		binary.BigEndian.PutUint16(typ, a.typ)
		pkt = append(pkt, typ...)
		pkt = append(pkt, 0, 1) // CLASS IN
		ttl := make([]byte, 4)
		binary.BigEndian.PutUint32(ttl, 120)
		pkt = append(pkt, ttl...)
		if a.typ == 1 {
			pkt = append(pkt, 0, 4)
			pkt = append(pkt, a.rdata.To4()...)
		} else if a.typ == 28 {
			pkt = append(pkt, 0, 16)
			pkt = append(pkt, a.rdata.To16()...)
		} else {
			// PTR-style rdata (encoded name)
			rd := []byte{}
			rd = appendDNSName(rd, a.rdata.String())
			l := make([]byte, 2)
			binary.BigEndian.PutUint16(l, uint16(len(rd)))
			pkt = append(pkt, l...)
			pkt = append(pkt, rd...)
		}
	}
	return pkt
}

func appendDNSName(pkt []byte, name string) []byte {
	for _, label := range splitLabels(name) {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	return append(pkt, 0)
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestExtractMDNSSelfAnnouncement(t *testing.T) {
	ip := net.ParseIP("192.168.1.50")
	pkt := buildMDNSResponse("", []struct {
		name  string
		typ   uint16
		rdata net.IP
	}{{"android-xyz.local", 1, ip}})
	if got := extractMDNSHostname(pkt, "192.168.1.50"); got != "android-xyz" {
		t.Fatalf("expected android-xyz, got %q", got)
	}
}

func TestExtractMDNSIgnoresOtherHostsAnswers(t *testing.T) {
	// Answer about a DIFFERENT host must not rename the sender.
	ip := net.ParseIP("192.168.1.99")
	pkt := buildMDNSResponse("", []struct {
		name  string
		typ   uint16
		rdata net.IP
	}{{"android-xyz.local", 1, ip}})
	if got := extractMDNSHostname(pkt, "192.168.1.18"); got != "" {
		t.Fatalf("expected empty (answer is about .99, sender is .18), got %q", got)
	}
}

func TestExtractMDNSIgnoresQueries(t *testing.T) {
	// A Windows host asking "who is Android-xyz.local" must not be renamed.
	pkt := buildMDNSResponse("Android-xyz.local", nil)
	if got := extractMDNSHostname(pkt, "192.168.1.18"); got != "" {
		t.Fatalf("expected empty for query-only packet, got %q", got)
	}
}

func TestExtractMDNSIgnoresPTRRecords(t *testing.T) {
	// Service-enumeration PTR answers are not hostnames.
	pkt := buildMDNSResponse("", []struct {
		name  string
		typ   uint16
		rdata net.IP
	}{{"_services._dns-sd._udp.local", 12, net.ParseIP("192.168.1.18")}})
	if got := extractMDNSHostname(pkt, "192.168.1.18"); got != "" {
		t.Fatalf("expected empty for PTR answer, got %q", got)
	}
}

func TestExtractMDNSAAAAAnnouncement(t *testing.T) {
	ip := net.ParseIP("fe80::1234")
	pkt := buildMDNSResponse("", []struct {
		name  string
		typ   uint16
		rdata net.IP
	}{{"myphone.local", 28, ip}})
	if got := extractMDNSHostname(pkt, "fe80::1234"); got != "myphone" {
		t.Fatalf("expected myphone, got %q", got)
	}
}

func TestReadDNSNameCompression(t *testing.T) {
	// pkt: "foo.local" at 12, then pointer to 12.
	pkt := make([]byte, 12)
	pkt = appendDNSName(pkt, "foo.local")
	ptrOff := len(pkt)
	pkt = append(pkt, 0xC0, 12)
	name, next, ok := readDNSName(pkt, ptrOff)
	if !ok || name != "foo.local" || next != ptrOff+2 {
		t.Fatalf("got %q %d %v", name, next, ok)
	}
}
