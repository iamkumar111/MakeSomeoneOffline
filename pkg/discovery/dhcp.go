package discovery

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// DHCPLease represents a parsed DHCP lease entry.
type DHCPLease struct {
	IP       string
	MAC      string
	Hostname string
	Expiry   time.Time // zero = infinite / unknown
}

// Expired reports whether the lease is past its expiry (zero expiry = valid).
func (l DHCPLease) Expired(now time.Time) bool {
	return !l.Expiry.IsZero() && now.After(l.Expiry)
}

// ParseDNSMasqLeases parses dnsmasq lease files: "<expiry> <mac> <ip> <hostname> <client-id>".
// Expired leases are dropped: a lease file remembers hours-old bindings for
// departed devices, which previously became permanent phantom "online" devices.
func ParseDNSMasqLeases(path string) []DHCPLease {
	return parseDNSMasqLeasesAt(path, time.Now().UTC())
}

func parseDNSMasqLeasesAt(path string, now time.Time) []DHCPLease {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []DHCPLease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) < 3 {
			continue
		}
		mac, ip := "", ""
		hostname := ""
		var expiry time.Time
		// dnsmasq format: field[0] is expiry epoch (0 = infinite)
		if epoch, err := strconv.ParseInt(fields[0], 10, 64); err == nil && epoch > 0 {
			expiry = time.Unix(epoch, 0).UTC()
		}
		if len(fields) >= 3 {
			mac = strings.ToLower(fields[1])
			ip = fields[2]
		}
		if len(fields) >= 4 && fields[3] != "*" {
			hostname = fields[3]
		}
		if mac == "" || ip == "" {
			continue
		}
		lease := DHCPLease{IP: ip, MAC: mac, Hostname: hostname, Expiry: expiry}
		if lease.Expired(now) {
			continue
		}
		out = append(out, lease)
	}
	return out
}

// DHCPLeaseWatcher polls common lease files and ingests them as observations.
type DHCPLeaseWatcher struct {
	fusion *IdentityFusionEngine
	paths  []string
}

// NewDHCPLeaseWatcher watches dnsmasq/isc-dhcp lease locations.
func NewDHCPLeaseWatcher(fusion *IdentityFusionEngine, extraPaths []string) *DHCPLeaseWatcher {
	paths := []string{
		"/var/lib/misc/dnsmasq.leases",
		"/var/lib/dnsmasq/dnsmasq.leases",
		"/tmp/dhcp.leases",
		"/var/lib/dhcp/dhcpd.leases",
		"/var/db/dnsmasq.leases",
	}
	paths = append(paths, extraPaths...)
	return &DHCPLeaseWatcher{fusion: fusion, paths: paths}
}

// Start polls lease files periodically.
func (w *DHCPLeaseWatcher) Start(ctx context.Context, interval time.Duration) {
	if interval < 5*time.Second {
		interval = 15 * time.Second
	}
	go func() {
		w.ScanOnce()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.ScanOnce()
			}
		}
	}()
}

// ScanOnce ingests all known lease files.
//
// DHCP is a WEAK signal: leases outlive a device's presence by hours, so lease
// observations only enrich already-known devices (hostname/metadata) and never
// create devices or mark them online. Live presence comes from ARP/neighbor
// sightings; departed devices then correctly age offline via the pruner.
func (w *DHCPLeaseWatcher) ScanOnce() {
	now := time.Now().UTC()
	for _, p := range w.paths {
		for _, l := range parseDNSMasqLeasesAt(p, now) {
			attrs := map[string]interface{}{"lease_file": p}
			if !l.Expiry.IsZero() {
				attrs["lease_expiry"] = l.Expiry.Format(time.RFC3339)
			}
			w.fusion.IngestObservation(models.Observation{
				Timestamp:  now,
				Source:     "dhcp",
				MAC:        l.MAC,
				IP:         l.IP,
				Hostname:   l.Hostname,
				Attributes: attrs,
			})
		}
	}
}
