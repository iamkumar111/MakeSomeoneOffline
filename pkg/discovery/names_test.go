package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// buildDHCPCapture crafts Ethernet/IPv4/UDP/BOOTP bytes for a DHCP REQUEST.
func buildDHCPCapture(t *testing.T, chaddr net.HardwareAddr, hostname, reqIP, serverIP string) []byte {
	t.Helper()
	frame := make([]byte, 14+20+8+240+128)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	frame[14+9] = 17 // UDP
	binary.BigEndian.PutUint16(frame[14+20:14+22], 68)
	binary.BigEndian.PutUint16(frame[14+22:14+24], 67)
	bootp := frame[14+20+8:]
	bootp[0] = 1 // BOOTREQUEST
	bootp[1] = 1 // Ethernet
	bootp[2] = 6
	copy(bootp[28:34], chaddr)
	binary.BigEndian.PutUint32(bootp[236:240], 0x63825363)
	opts := []byte{53, 1, 3} // REQUEST
	if hostname != "" {
		opts = append(opts, 12, byte(len(hostname)))
		opts = append(opts, hostname...)
	}
	if reqIP != "" {
		opts = append(opts, 50, 4)
		opts = append(opts, net.ParseIP(reqIP).To4()...)
	}
	if serverIP != "" {
		opts = append(opts, 54, 4)
		opts = append(opts, net.ParseIP(serverIP).To4()...)
	}
	opts = append(opts, 255)
	copy(bootp[240:], opts)
	return frame[:14+20+8+240+len(opts)]
}

func TestParseDHCPCapture(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	f := buildDHCPCapture(t, mac, "KJ-SST", "192.168.1.18", "192.168.1.1")
	gotMAC, gotIP, gotHost, gotSrv, ok := parseDHCPPacket(f)
	if !ok {
		t.Fatal("expected packet to parse")
	}
	if gotMAC != "aa:bb:cc:dd:ee:ff" || gotIP != "192.168.1.18" || gotHost != "KJ-SST" || gotSrv != "192.168.1.1" {
		t.Fatalf("got %q %q %q %q", gotMAC, gotIP, gotHost, gotSrv)
	}
}

func TestParseDHCPCaptureRejects(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	f := buildDHCPCapture(t, mac, "host", "192.168.1.5", "")
	f[14+9] = 6 // TCP, not UDP
	if _, _, _, _, ok := parseDHCPPacket(f); ok {
		t.Fatal("expected TCP to be rejected")
	}
	f2 := buildDHCPCapture(t, mac, "host", "192.168.1.5", "")
	f2[14+20+8+236] = 0 // corrupt magic
	if _, _, _, _, ok := parseDHCPPacket(f2); ok {
		t.Fatal("expected bad magic to be rejected")
	}
	// Binary garbage hostname is dropped, but MAC+IP still returned.
	f3 := buildDHCPCapture(t, mac, "A\xffC", "192.168.1.5", "")
	if _, _, host, _, ok := parseDHCPPacket(f3); !ok || host != "" {
		t.Fatalf("expected ok with empty hostname, got %v %q", ok, host)
	}
}

func TestSnoopFeedsFusionWithRealNames(t *testing.T) {
	engine := NewIdentityFusionEngine("test-site", events.NewEventBus())
	defer engine.Stop()
	// Device known by ARP first (no name).
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.18",
	})
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	f := buildDHCPCapture(t, mac, "KJ-SST", "192.168.1.18", "192.168.1.1")
	gotMAC, gotIP, gotHost, _, ok := parseDHCPPacket(f)
	if !ok {
		t.Fatal("parse failed")
	}
	dev := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "dhcp",
		MAC: gotMAC, IP: gotIP, Hostname: gotHost,
	})
	if dev == nil || dev.DisplayName != "KJ-SST" {
		t.Fatalf("expected KJ-SST via DHCP snoop path, got %+v", dev)
	}
}

// buildServicePacket crafts an mDNS response with a PTR + SRV answer pair.
func buildServicePacket(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[2:4], 0x8400)
	binary.BigEndian.PutUint16(pkt[6:8], 2) // AN=2
	// Answer 1: PTR _http._tcp.local -> MyPrinter._http._tcp.local
	pkt = appendDNSName(pkt, "_http._tcp.local")
	pkt = append(pkt, 0, 12, 0, 1, 0, 0, 0, 120)
	rdata := []byte{}
	rdata = appendDNSName(rdata, "MyPrinter._http._tcp.local")
	ln := make([]byte, 2)
	binary.BigEndian.PutUint16(ln, uint16(len(rdata)))
	pkt = append(pkt, ln...)
	pkt = append(pkt, rdata...)
	// Answer 2: SRV MyPrinter._http._tcp.local -> printer.local port 80
	pkt = appendDNSName(pkt, "MyPrinter._http._tcp.local")
	pkt = append(pkt, 0, 33, 0, 1, 0, 0, 0, 120)
	srv := []byte{0, 0, 0, 0, 0, 80}
	srv = appendDNSName(srv, "printer.local")
	ln2 := make([]byte, 2)
	binary.BigEndian.PutUint16(ln2, uint16(len(srv)))
	pkt = append(pkt, ln2...)
	pkt = append(pkt, srv...)
	return pkt
}

func TestExtractMDNSServiceIdentity(t *testing.T) {
	pkt := buildServicePacket(t)
	host, inst := extractMDNSIdentity(pkt, "192.168.1.60")
	if host != "printer" {
		t.Fatalf("expected SRV target host 'printer', got %q (inst %q)", host, inst)
	}
	if inst != "MyPrinter" {
		t.Fatalf("expected instance 'MyPrinter', got %q", inst)
	}
}

func TestExtractMDNSIgnoresServiceEnumeration(t *testing.T) {
	// _services enumeration PTR -> service type name: not an identity.
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[2:4], 0x8400)
	binary.BigEndian.PutUint16(pkt[6:8], 1)
	pkt = appendDNSName(pkt, "_services._dns-sd._udp.local")
	pkt = append(pkt, 0, 12, 0, 1, 0, 0, 0, 120)
	rdata := appendDNSName([]byte{}, "_googlecast._tcp.local")
	ln := make([]byte, 2)
	binary.BigEndian.PutUint16(ln, uint16(len(rdata)))
	pkt = append(pkt, ln...)
	pkt = append(pkt, rdata...)
	if host, inst := extractMDNSIdentity(pkt, "192.168.1.60"); host != "" || inst != "" {
		t.Fatalf("expected empty for service enumeration, got %q %q", host, inst)
	}
}

func TestUPnPFriendlyNameAdopted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<root><device><friendlyName>Living Room TV</friendlyName><modelName>QLED 55</modelName></device></root>`)
	}))
	defer srv.Close()
	engine := NewIdentityFusionEngine("test-site", events.NewEventBus())
	defer engine.Stop()
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:70", IP: "127.0.0.1",
	})
	l := &ServiceDiscoveryListener{fusionEngine: engine, stopCh: make(chan struct{})}
	l.fetchUPnPFriendlyName(srv.URL+"/desc.xml", "127.0.0.1")
	devs := engine.ListDevices()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].DisplayName != "Living Room TV" {
		t.Fatalf("expected UPnP friendlyName, got %q (meta %v)", devs[0].DisplayName, devs[0].Metadata)
	}
}

func TestUPnPRejectsForeignLocation(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()
	engine := NewIdentityFusionEngine("test-site", events.NewEventBus())
	defer engine.Stop()
	l := &ServiceDiscoveryListener{fusionEngine: engine, stopCh: make(chan struct{})}
	// LOCATION points at someone else: must not be fetched.
	l.fetchUPnPFriendlyName(srv.URL+"/desc.xml", "192.168.99.99")
	if hit {
		t.Fatal("must not fetch LOCATION whose host differs from sender")
	}
	if len(engine.ListDevices()) != 0 {
		t.Fatal("must not create devices from UPnP")
	}
}

func TestExtractHTMLTitle(t *testing.T) {
	cases := map[string]string{
		`<html><head><title>RT-AC68U - Login</title></head>`: "RT-AC68U",
		`<TITLE>HP LaserJet Pro | Home</TITLE>`:              "HP LaserJet Pro",
		`<title>Login</title>`:                               "",
		`<title>192.168.1.1</title>`:                         "",
		`<title>ab</title>`:                                  "",
		`no title here`:                                      "",
		`<title>   </title>`:                                 "",
	}
	for body, want := range cases {
		if got := extractHTMLTitle(body); got != want {
			t.Errorf("body %q: got %q want %q", body, got, want)
		}
	}
}
