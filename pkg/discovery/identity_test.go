package discovery

import (
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func newTestEngine() *IdentityFusionEngine {
	return NewIdentityFusionEngine("test-site", events.NewEventBus())
}

// DHCP must never create devices: a lease for an unknown MAC is ignored
// (ARP creates the record within seconds if the host is really present).
func TestDHCPDoesNotCreateDevices(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	dev := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "dhcp",
		MAC:       "aa:bb:cc:dd:ee:ff",
		IP:        "192.168.1.77",
		Hostname:  "ghost-phone",
	})
	if dev != nil {
		t.Fatalf("expected nil (no device created from DHCP alone), got %+v", dev)
	}
	if n := len(engine.ListDevices()); n != 0 {
		t.Fatalf("expected 0 devices, got %d", n)
	}
}

// A stale lease for a departed MAC must not steal the IP of whoever holds it
// now, must not move bindings, and must not refresh liveness.
func TestDHCPDoesNotStealIPs(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	// Windows PC currently at .18 (strong ARP sighting).
	win := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp_proc",
		MAC:       "00:11:22:33:44:18",
		IP:        "192.168.1.18",
	})
	// Android phone now at .19.
	and := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp_proc",
		MAC:       "aa:bb:cc:dd:ee:19",
		IP:        "192.168.1.19",
	})
	winLastSeen := win.LastSeen

	// Stale lease: android MAC still claims .18.
	got := engine.IngestObservation(models.Observation{
		Timestamp: time.Now().Add(time.Minute),
		Source:    "dhcp",
		MAC:       "aa:bb:cc:dd:ee:19",
		IP:        "192.168.1.18",
		Hostname:  "android-xyz",
	})
	if got == nil || got.ID != and.ID {
		t.Fatalf("expected enrichment of android record, got %+v", got)
	}
	// Windows record must survive with its IP and untouched liveness.
	winAfter, ok := engine.GetDevice(win.ID)
	if !ok {
		t.Fatal("windows device was merged away by stale lease")
	}
	if winAfter.PrimaryIP != "192.168.1.18" {
		t.Fatalf("windows IP moved to %q", winAfter.PrimaryIP)
	}
	if !winAfter.LastSeen.Equal(winLastSeen) {
		t.Fatal("stale lease refreshed liveness")
	}
	// Android record keeps its ARP-bound IP.
	andAfter, _ := engine.GetDevice(and.ID)
	if andAfter.PrimaryIP != "192.168.1.19" {
		t.Fatalf("android IP moved to %q by weak source", andAfter.PrimaryIP)
	}
	// Hostname enrichment still works for the correct owner.
	if andAfter.Metadata["hostname"] != "android-xyz" {
		t.Fatalf("expected android hostname enrichment, got %v", andAfter.Metadata["hostname"])
	}
	if winAfter.DisplayName == "android-xyz" {
		t.Fatal("windows device renamed by another host's lease")
	}
}

// Hostname precedence: NetBIOS/fingerprint > mDNS/DHCP > reverse-DNS.
// Ties keep the incumbent (no flapping).
func TestHostnamePrecedence(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	dev := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:18", IP: "192.168.1.18",
		Attributes: map[string]interface{}{"ptr_hostname": "Android.local"},
	})
	if dev.DisplayName != "Android.local" {
		t.Fatalf("ptr should fill empty name, got %q", dev.DisplayName)
	}
	// DHCP (rank 2) overwrites PTR (rank 1).
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "dhcp",
		MAC: "00:11:22:33:44:18", IP: "192.168.1.18", Hostname: "laptop-corp",
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "laptop-corp" {
		t.Fatalf("dhcp should beat ptr, got %q", dev.DisplayName)
	}
	// Another PTR must NOT downgrade.
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:18", IP: "192.168.1.18",
		Attributes: map[string]interface{}{"ptr_hostname": "Android.local"},
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "laptop-corp" {
		t.Fatalf("ptr must not overwrite dhcp name, got %q", dev.DisplayName)
	}
	// Fingerprint (rank 3) wins over everything.
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "fingerprint",
		MAC: "00:11:22:33:44:18", IP: "192.168.1.18", Hostname: "DESKTOP-WIN11",
		Attributes: map[string]interface{}{"device_type": "Windows PC"},
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "Windows PC (DESKTOP-WIN11)" {
		t.Fatalf("fingerprint should win, got %q", dev.DisplayName)
	}
	// Equal-rank mDNS must not flap the curated name.
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "mdns",
		MAC: "00:11:22:33:44:18", IP: "192.168.1.18", Hostname: "other-name",
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "Windows PC (DESKTOP-WIN11)" {
		t.Fatalf("tie must keep incumbent, got %q", dev.DisplayName)
	}
}

// Service-discovery artifacts must never become hostnames.
func TestServiceArtifactsRejected(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	dev := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:50", IP: "192.168.1.50",
	})
	for _, bad := range []string{
		"_googlecast._tcp.local",
		"Living Room TV._http._tcp.local",
		"_services._dns-sd._udp.local",
	} {
		engine.IngestObservation(models.Observation{
			Timestamp: time.Now(), Source: "mdns",
			MAC: "00:11:22:33:44:50", IP: "192.168.1.50", Hostname: bad,
		})
	}
	dev, _ = engine.GetDevice(dev.ID)
	if host, _ := dev.Metadata["hostname"].(string); host != "" {
		t.Fatalf("service artifact adopted as hostname: %q", host)
	}
	if dev.DisplayName == "_googlecast._tcp.local" {
		t.Fatal("device renamed to service artifact")
	}
}

// Manual rename outranks everything and survives a JSON snapshot round-trip
// (where hostname_rank decodes as float64).
func TestManualRenameWinsAndSurvivesReload(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	dev := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "fingerprint",
		MAC: "00:11:22:33:44:60", IP: "192.168.1.60", Hostname: "DESKTOP-AUTO",
	})
	if err := engine.SetCustomName(dev.ID, "KJ SST"); err != nil {
		t.Fatal(err)
	}
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "KJ SST" {
		t.Fatalf("expected manual name, got %q", dev.DisplayName)
	}
	// Strong automatic sources must not overwrite it.
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "fingerprint",
		MAC: "00:11:22:33:44:60", IP: "192.168.1.60", Hostname: "DESKTOP-NEW",
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "KJ SST" {
		t.Fatalf("manual name overwritten, got %q", dev.DisplayName)
	}
	// Simulate snapshot reload: rank comes back as float64.
	dev.Metadata["hostname_rank"] = float64(5)
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "mdns",
		MAC: "00:11:22:33:44:60", IP: "192.168.1.60", Hostname: "mdns-name",
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName != "KJ SST" {
		t.Fatalf("manual name lost after reload-shaped rank, got %q", dev.DisplayName)
	}
	// Clearing returns to automatic naming.
	if err := engine.ClearCustomName(dev.ID); err != nil {
		t.Fatal(err)
	}
	dev, _ = engine.GetDevice(dev.ID)
	if dev.DisplayName == "KJ SST" {
		t.Fatal("expected automatic name after clear")
	}
}

// The 00:e0:27 OUI belongs to DUX, Inc. (IEEE-registered) — it must resolve
// to the full company name, never a cryptic stub that looks like a hostname.
func TestDUXOUIMapsToCompanyName(t *testing.T) {
	if v := LookupVendor("00:e0:27:2e:b1:b3"); v != "DUX, Inc." {
		t.Fatalf("expected DUX, Inc., got %q", v)
	}
}

// Corrected OUI entries propagate to existing records on the next sighting,
// unless a fingerprint override is in force.
func TestVendorRefreshPropagatesCorrections(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	dev := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:e0:27:2e:b1:b3", IP: "192.168.1.18",
	})
	// Simulate a record created under the old bogus entry.
	dev.Vendor = "DUX"
	delete(dev.Metadata, "vendor_source")

	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:e0:27:2e:b1:b3", IP: "192.168.1.18",
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.Vendor != "DUX, Inc." {
		t.Fatalf("expected corrected vendor, got %q", dev.Vendor)
	}

	// A fingerprint override must stick.
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "fingerprint",
		MAC: "00:e0:27:2e:b1:b3", IP: "192.168.1.18", Hostname: "KJ SST",
		Attributes: map[string]interface{}{"fingerprint_vendor": "Microsoft Windows"},
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.Vendor != "Microsoft Windows" {
		t.Fatalf("expected fingerprint vendor, got %q", dev.Vendor)
	}
	engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:e0:27:2e:b1:b3", IP: "192.168.1.18",
	})
	dev, _ = engine.GetDevice(dev.ID)
	if dev.Vendor != "Microsoft Windows" {
		t.Fatalf("fingerprint vendor must not be downgraded, got %q", dev.Vendor)
	}
	if dev.DisplayName != "KJ SST" {
		t.Fatalf("expected curated hostname, got %q", dev.DisplayName)
	}
}

// Operator device state (manual names, trust) must survive a restart cycle:
// snapshot keeps only meaningful records, restore brings them back offline,
// and live re-discovery merges without losing the manual name.
func TestDeviceOperatorStateRoundTrip(t *testing.T) {
	engine := newTestEngine()
	defer engine.Stop()

	named := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:70", IP: "192.168.1.70",
	})
	plain := engine.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:71", IP: "192.168.1.71",
	})
	if err := engine.SetCustomName(named.ID, "KJ SST"); err != nil {
		t.Fatal(err)
	}
	if err := engine.SetTrustState(plain.ID, models.TrustStateTrusted); err != nil {
		t.Fatal(err)
	}

	snap := engine.SnapshotDevices()
	if len(snap) != 2 {
		t.Fatalf("expected 2 persisted devices, got %d", len(snap))
	}

	fresh := newTestEngine()
	defer fresh.Stop()
	fresh.RestoreDevices(snap)

	restored, ok := fresh.GetDeviceByMAC("00:11:22:33:44:70")
	if !ok {
		t.Fatal("named device not restored")
	}
	if restored.DisplayName != "KJ SST" || restored.IsOnline {
		t.Fatalf("expected offline KJ SST, got %q online=%v", restored.DisplayName, restored.IsOnline)
	}
	trusted, ok := fresh.GetDeviceByMAC("00:11:22:33:44:71")
	if !ok || trusted.TrustState != models.TrustStateTrusted {
		t.Fatalf("trust not restored: %+v", trusted)
	}

	// Live re-discovery of the renamed MAC keeps the manual name and flips online.
	again := fresh.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp_proc",
		MAC: "00:11:22:33:44:70", IP: "192.168.1.70",
	})
	if again.ID != restored.ID || again.DisplayName != "KJ SST" || !again.IsOnline {
		t.Fatalf("re-discovery broke operator state: %+v", again)
	}
}
