package discovery

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// ServiceDiscoveryListener listens for multicast mDNS and SSDP announcements.
type ServiceDiscoveryListener struct {
	fusionEngine *IdentityFusionEngine
	mu           sync.Mutex
	stopCh       chan struct{}
}

// NewServiceDiscoveryListener creates an instance of the service discovery listener.
func NewServiceDiscoveryListener(fusion *IdentityFusionEngine) *ServiceDiscoveryListener {
	return &ServiceDiscoveryListener{
		fusionEngine: fusion,
		stopCh:       make(chan struct{}),
	}
}

// Start begins passive mDNS and SSDP multicast listening in the background.
func (l *ServiceDiscoveryListener) Start(ctx context.Context) {
	go l.listenSSDP(ctx)
	go l.probeSSDP(ctx)
	go l.listenMDNS(ctx)
}

// Stop terminates listeners.
func (l *ServiceDiscoveryListener) Stop() {
	close(l.stopCh)
}

// listenSSDP listens for UPnP NOTIFY multicasts on 239.255.255.250:1900.
func (l *ServiceDiscoveryListener) listenSSDP(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		// Port may be occupied or no multicast permission; degrade gracefully
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			l.parseSSDPPacket(string(buf[:n]), src.IP.String())
		}
	}
}

// probeSSDP sends an M-SEARCH SSDP discovery broadcast to discover smart TVs, printers, and IoT devices.
func (l *ServiceDiscoveryListener) probeSSDP(ctx context.Context) {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	query := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		case <-ticker.C:
			dst, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
			if err != nil {
				continue
			}
			conn, err := net.DialUDP("udp4", nil, dst)
			if err == nil {
				_, _ = conn.Write([]byte(query))
				_ = conn.Close()
			}
		}
	}
}

func (l *ServiceDiscoveryListener) parseSSDPPacket(raw, srcIP string) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	headers := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
	}

	server := headers["server"]
	st := headers["st"]
	if st == "" {
		st = headers["nt"]
	}
	location := headers["location"]

	if strings.HasPrefix(srcIP, "127.") || strings.HasPrefix(srcIP, "172.17.") || strings.HasPrefix(srcIP, "172.18.") || strings.HasPrefix(srcIP, "172.19.") {
		return
	}

	// UPnP device descriptions carry a real friendlyName ("Living Room TV",
	// "Hikvision Camera") — fetch it. Host must equal the sender (SSRF guard).
	if location != "" {
		go l.fetchUPnPFriendlyName(location, srcIP)
	}

	if friendlyName := firstNonEmpty(server, st); friendlyName != "" || st != "" {
		l.fusionEngine.IngestObservation(models.Observation{
			Timestamp: time.Now().UTC(),
			Source:    "ssdp",
			IP:        srcIP,
			Attributes: map[string]interface{}{
				"ssdp_server":   server,
				"service_name":  st,
				"service_proto": "ssdp",
				"service_port":  1900,
			},
		})
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// fetchUPnPFriendlyName downloads a UPnP device description and adopts its
// friendlyName (rank 2, "upnp" source) plus modelName for context.
func (l *ServiceDiscoveryListener) fetchUPnPFriendlyName(location, srcIP string) {
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	host := u.Hostname()
	if host == "" || host != strings.TrimSpace(srcIP) {
		return // LOCATION must point back at the sender
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if err != nil || len(body) == 0 {
		return
	}
	var desc struct {
		Device struct {
			FriendlyName string `xml:"friendlyName"`
			ModelName    string `xml:"modelName"`
		} `xml:"device"`
	}
	if err := xml.Unmarshal(body, &desc); err != nil {
		return
	}
	attrs := map[string]interface{}{"service_proto": "upnp"}
	if strings.TrimSpace(desc.Device.ModelName) != "" {
		attrs["upnp_model"] = strings.TrimSpace(desc.Device.ModelName)
	}
	name := strings.TrimSpace(desc.Device.FriendlyName)
	var obs models.Observation
	if name != "" {
		obs = models.Observation{
			Timestamp:  time.Now().UTC(),
			Source:     "upnp",
			IP:         srcIP,
			Hostname:   name,
			Attributes: attrs,
		}
	} else if attrs["upnp_model"] != nil {
		obs = models.Observation{
			Timestamp:  time.Now().UTC(),
			Source:     "upnp",
			IP:         srcIP,
			Attributes: attrs,
		}
	} else {
		return
	}
	l.fusionEngine.IngestObservation(obs)
}

// listenMDNS passively listens on 224.0.0.251:5353 and extracts hostnames.
// Pure-Go minimal parser (no external zeroconf dep): reads DNS-like packets and
// pulls printable labels ending in .local as mdns_hostname enrichment.
func (l *ServiceDiscoveryListener) listenMDNS(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(65535)

	buf := make([]byte, 9000)
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil || n < 12 {
				continue
			}
			srcIP := ""
			if src != nil {
				srcIP = src.IP.String()
			}
			// Only self-announcements become hostnames (A/AAAA answers binding
			// a .local name to the sender's own IP, SRV targets, service
			// instance names). Queries are never names: a Windows host asking
			// "who is Android-xyz.local" must not get renamed to Android.
			if host, instance := extractMDNSIdentity(buf[:n], srcIP); host != "" || instance != "" {
				name := host
				if name == "" {
					name = instance
				}
				l.fusionEngine.IngestObservation(models.Observation{
					Timestamp: time.Now().UTC(),
					Source:    "mdns",
					IP:        srcIP,
					Hostname:  name,
					Attributes: map[string]interface{}{
						"mdns_hostname":  host,
						"mdns_instance":  instance,
						"service_proto":  "mdns",
					},
				})
			}
		}
	}
}

// extractMDNSHostname returns the .local hostname a host announces for ITSELF:
// the owner name of an A/AAAA answer whose rdata equals the sender's IP.
// Questions, PTR/SRV/TXT records, and answers about other hosts yield "".
// This prevents misattribution (e.g. a Windows PC resolving "Android.local"
// being renamed to it).
func extractMDNSHostname(pkt []byte, srcIP string) string {
	if len(pkt) < 12 || srcIP == "" {
		return ""
	}
	srcParsed := net.ParseIP(strings.TrimSpace(srcIP))
	if srcParsed == nil {
		return ""
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	off := 12
	// Skip the question section.
	for i := 0; i < qd; i++ {
		_, next, ok := readDNSName(pkt, off)
		if !ok {
			return ""
		}
		off = next + 4 // QTYPE + QCLASS
		if off > len(pkt) {
			return ""
		}
	}
	// Walk answer RRs; accept only A/AAAA bound to the sender.
	for i := 0; i < an; i++ {
		name, next, ok := readDNSName(pkt, off)
		if !ok {
			return ""
		}
		off = next
		if off+10 > len(pkt) {
			return ""
		}
		typ := int(binary.BigEndian.Uint16(pkt[off : off+2]))
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if off+rdlen > len(pkt) {
			return ""
		}
		rdata := pkt[off : off+rdlen]
		off += rdlen
		if (typ == 1 && rdlen == 4) || (typ == 28 && rdlen == 16) {
			if net.IP(rdata).Equal(srcParsed) {
				short := strings.TrimSuffix(name, ".local")
				short = strings.TrimSuffix(short, ".")
				if short != "" && !strings.EqualFold(short, "local") {
					return short
				}
			}
		}
	}
	return ""
}

// extractMDNSIdentity returns (hostname, serviceInstance) announced by the
// sender: A/AAAA self-bindings and SRV targets yield hostnames; PTR answers
// yield service instance names ("Living Room TV" from
// "Living Room TV._googlecast._tcp.local"). Service TYPE enumerations
// ("_googlecast._tcp.local") and queries yield nothing.
func extractMDNSIdentity(pkt []byte, srcIP string) (host, instance string) {
	if len(pkt) < 12 || srcIP == "" {
		return "", ""
	}
	srcParsed := net.ParseIP(strings.TrimSpace(srcIP))
	if srcParsed == nil {
		return "", ""
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, ok := readDNSName(pkt, off)
		if !ok {
			return host, instance
		}
		off = next + 4
		if off > len(pkt) {
			return host, instance
		}
	}
	for i := 0; i < an; i++ {
		name, next, ok := readDNSName(pkt, off)
		if !ok {
			return host, instance
		}
		off = next
		if off+10 > len(pkt) {
			return host, instance
		}
		typ := int(binary.BigEndian.Uint16(pkt[off : off+2]))
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if off+rdlen > len(pkt) {
			return host, instance
		}
		rdata := pkt[off : off+rdlen]
		off += rdlen
		switch {
		case (typ == 1 && rdlen == 4) || (typ == 28 && rdlen == 16):
			if host == "" && net.IP(rdata).Equal(srcParsed) {
				host = trimLocal(name)
			}
		case typ == 33: // SRV: target is the host's .local name
			// rdata = priority(2) + weight(2) + port(2) + target name
			if rdlen > 6 {
				if tgt, _, ok := readDNSName(pkt, off-rdlen+6); ok {
					if host == "" {
						host = trimLocal(tgt)
					}
				}
				if instance == "" {
					instance = instanceName(name)
				}
			}
		case typ == 12: // PTR: rdata names a service instance
			if rdataName, _, ok := readDNSName(pkt, off-rdlen); ok {
				if instance == "" {
					instance = instanceName(rdataName)
				}
			}
		}
	}
	return host, instance
}

// trimLocal strips a trailing .local suffix.
func trimLocal(name string) string {
	short := strings.TrimSuffix(name, ".local")
	short = strings.TrimSuffix(short, ".")
	if short == "" || strings.EqualFold(short, "local") {
		return ""
	}
	return short
}

// instanceName extracts "Living Room TV" from
// "Living Room TV._googlecast._tcp.local": the labels preceding a trailing
// <_service>._tcp|_udp.local suffix. Service types, bare hostnames, and
// underscore-prefixed names yield "".
func instanceName(name string) string {
	labels := strings.Split(name, ".")
	if len(labels) < 4 {
		return ""
	}
	n := len(labels)
	domain, proto, svc := labels[n-1], labels[n-2], labels[n-3]
	if !strings.EqualFold(domain, "local") {
		return ""
	}
	if !strings.EqualFold(proto, "_tcp") && !strings.EqualFold(proto, "_udp") {
		return ""
	}
	if !strings.HasPrefix(svc, "_") {
		return ""
	}
	inst := strings.TrimSpace(strings.Join(labels[:n-3], "."))
	if inst == "" || strings.HasPrefix(inst, "_") {
		return ""
	}
	return inst
}

// readDNSName decodes a (possibly compressed) DNS name at off.
// Returns the dotted name and the offset of the next field.
func readDNSName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	next := off
	jumped := false
	for guard := 0; guard < 64; guard++ {
		if off >= len(pkt) {
			return "", 0, false
		}
		b := pkt[off]
		if b&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := int(b&0x3F)<<8 | int(pkt[off+1])
			if ptr >= len(pkt) {
				return "", 0, false
			}
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = ptr
			continue
		}
		if b == 0 {
			if !jumped {
				next = off + 1
			}
			break
		}
		if b > 63 || off+1+int(b) > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, string(pkt[off+1:off+1+int(b)]))
		off += 1 + int(b)
	}
	return strings.Join(labels, "."), next, true
}
