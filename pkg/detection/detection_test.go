package detection

import (
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestGatewayImpersonationDetection(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewDetectionEngine(KnownGateway{
		IP:  "192.168.1.1",
		MAC: "00:11:22:33:44:55",
	}, bus)

	// Legitimate ARP observation
	alert1 := engine.AnalyzeObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.1",
		MAC:       "00:11:22:33:44:55",
	})
	if alert1 != nil {
		t.Fatalf("unexpected alert for legitimate gateway ARP: %+v", alert1)
	}

	// Malicious / Attacker ARP observation claiming the gateway IP
	alert2 := engine.AnalyzeObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.1",
		MAC:       "aa:bb:cc:dd:ee:ff", // Attacker
	})

	if alert2 == nil {
		t.Fatal("expected CRITICAL alert for gateway impersonation, got nil")
	}
	if alert2.Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %s", alert2.Severity)
	}
	if alert2.Type != models.AlertGatewayImpersonation {
		t.Errorf("expected alert type gateway_impersonation, got %s", alert2.Type)
	}
}

func TestDuplicateIPDetection(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewDetectionEngine(KnownGateway{}, bus)

	// Device A takes 192.168.1.50
	engine.AnalyzeObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.50",
		MAC:       "11:22:33:44:55:66",
	})

	// Device B claims same 192.168.1.50
	alert := engine.AnalyzeObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.50",
		MAC:       "99:88:77:66:55:44",
	})

	if alert == nil {
		t.Fatal("expected duplicate IP alert, got nil")
	}
	if alert.Type != models.AlertDuplicateIP {
		t.Errorf("expected alert duplicate_ip, got %s", alert.Type)
	}
}

func TestPortScanDetection(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewDetectionEngine(KnownGateway{}, bus)

	srcIP := "192.168.1.199"
	targetIP := "192.168.1.10"

	var alert *models.Alert
	// Simulate rapid sweep across 15 ports
	for port := 20; port <= 35; port++ {
		alert = engine.InspectPortConnection(srcIP, targetIP, port)
	}

	if alert == nil {
		t.Fatal("expected port scan alert, got nil")
	}
	if alert.Type != models.AlertPortScanDetected {
		t.Errorf("expected alert type port_scan_detected, got %s", alert.Type)
	}
}

func TestBandwidthAnomalyDetection(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewDetectionEngine(KnownGateway{}, bus)

	// Normal bandwidth (10 Mbps) below 50 Mbps threshold -> no alert
	a1 := engine.InspectBandwidth("dev-1", "192.168.1.50", 10e6, 50e6)
	if a1 != nil {
		t.Fatalf("unexpected alert for normal rate: %+v", a1)
	}

	// Anomaly (85 Mbps) exceeding 50 Mbps threshold -> Alert
	a2 := engine.InspectBandwidth("dev-1", "192.168.1.50", 85e6, 50e6)
	if a2 == nil {
		t.Fatal("expected bandwidth anomaly alert, got nil")
	}
	if a2.Type != models.AlertBandwidthAnomaly {
		t.Errorf("expected bandwidth_anomaly, got %s", a2.Type)
	}
}

func TestRogueIPv6RADetection(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewDetectionEngine(KnownGateway{}, bus)
	engine.SetTrustedIPv6Router("00:11:22:33:44:55")

	// Authorized router sends RA -> no alert
	a1 := engine.InspectIPv6RA("fe80::1", "00:11:22:33:44:55", "2001:db8:1::/64")
	if a1 != nil {
		t.Fatalf("unexpected alert for authorized router: %+v", a1)
	}

	// Unauthorized rogue device sends RA -> CRITICAL alert
	a2 := engine.InspectIPv6RA("fe80::bad", "aa:bb:cc:dd:ee:ff", "2001:db8:666::/64")
	if a2 == nil {
		t.Fatal("expected Rogue IPv6 RA alert, got nil")
	}
	if a2.Type != models.AlertRogueIPv6RA {
		t.Errorf("expected rogue_ipv6_ra, got %s", a2.Type)
	}
	if a2.Severity != models.SeverityCritical {
		t.Errorf("expected severity critical, got %s", a2.Severity)
	}
}


