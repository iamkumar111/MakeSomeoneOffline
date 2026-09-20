package discovery

import (
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestIdentityFusionEngine(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewIdentityFusionEngine("test-site", bus)
	defer engine.Stop()

	// 1. Initial ARP observation: only MAC and IP
	obs1 := models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		MAC:       "b8:27:eb:11:22:33", // Raspberry Pi
		IP:        "192.168.1.150",
	}

	dev1 := engine.IngestObservation(obs1)
	if dev1 == nil {
		t.Fatal("expected device to be created")
	}
	if dev1.Vendor != "Raspberry Pi Foundation" {
		t.Errorf("expected Raspberry Pi vendor, got %q", dev1.Vendor)
	}
	if dev1.PrimaryIP != "192.168.1.150" {
		t.Errorf("expected IP 192.168.1.150, got %q", dev1.PrimaryIP)
	}

	// 2. DHCP observation: brings hostname
	obs2 := models.Observation{
		Timestamp: time.Now(),
		Source:    "dhcp",
		MAC:       "b8:27:eb:11:22:33",
		IP:        "192.168.1.150",
		Hostname:  "octopi",
	}

	dev2 := engine.IngestObservation(obs2)
	if dev2.ID != dev1.ID {
		t.Errorf("expected same device ID %s, got %s", dev1.ID, dev2.ID)
	}
	if dev2.DisplayName != "octopi" {
		t.Errorf("expected display name 'octopi', got %q", dev2.DisplayName)
	}

	// 3. mDNS observation: brings advertised service
	obs3 := models.Observation{
		Timestamp: time.Now(),
		Source:    "mdns",
		IP:        "192.168.1.150",
		Attributes: map[string]interface{}{
			"service_name": "_http._tcp",
			"service_port": 80,
		},
	}
	dev3 := engine.IngestObservation(obs3)
	if len(dev3.Services) == 0 {
		t.Fatal("expected service to be recorded")
	}
	if dev3.Services[0].Name != "_http._tcp" || dev3.Services[0].Port != 80 {
		t.Errorf("unexpected service details: %+v", dev3.Services[0])
	}
}

func TestOUILookupRandomizedMAC(t *testing.T) {
	// A locally administered MAC (randomized address, e.g. iOS / Android private Wi-Fi)
	vendor := LookupVendor("da:a1:19:44:55:66")
	if vendor != "Private / Randomized MAC (Mobile)" {
		t.Errorf("expected randomized MAC identification, got %q", vendor)
	}
}
