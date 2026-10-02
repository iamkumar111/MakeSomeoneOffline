package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/detection"
	"github.com/open-netcut/open-netcut/pkg/discovery"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
	"github.com/open-netcut/open-netcut/pkg/policy"
	"github.com/open-netcut/open-netcut/pkg/server"
	"github.com/open-netcut/open-netcut/pkg/store"
		"github.com/open-netcut/open-netcut/pkg/traffic"
)

func TestServerHTTPRoutes(t *testing.T) {
	bus := events.NewEventBus()
	gwIP := "192.168.1.1"
	gwMAC := "00:11:22:33:44:55"

	allowlist := models.Allowlist{
		GatewayIPs:  []string{gwIP},
		GatewayMACs: []string{gwMAC},
		DNSIPs:      []string{"1.1.1.1"},
		AdminIPs:    []string{"127.0.0.1"},
	}

	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))

	fusion := discovery.NewIdentityFusionEngine("test-site", bus)
	detect := detection.NewDetectionEngine(detection.KnownGateway{IP: gwIP, MAC: gwMAC}, bus)
	pol := policy.NewPolicyEngine(registry, bus, allowlist)
	tel := traffic.NewTelemetryEngine("test-site", bus)
	memStore := store.NewMemoryStore()

	// Pre-populate a device
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.10",
		MAC:       "00:11:22:33:44:01",
		Hostname:  "test-pc",
	})

	srv := server.NewServer(fusion, detect, pol, tel, bus, memStore, "test-site")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := ts.Client()

	// 1. Stats Route
	resp, err := client.Get(ts.URL + "/api/v1/stats")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed stats route: %v, status: %d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Devices Route
	resp, err = client.Get(ts.URL + "/api/v1/devices")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed devices route: %v, status: %d", err, resp.StatusCode)
	}
	var devs []*models.Device
	_ = json.NewDecoder(resp.Body).Decode(&devs)
	resp.Body.Close()
	if len(devs) != 1 {
		t.Errorf("expected 1 device, got %d", len(devs))
	}

	// 3. Export Devices CSV
	resp, err = client.Get(ts.URL + "/api/v1/export/devices.csv")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed export devices csv: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected text/csv Content-Type, got %s", ct)
	}
	resp.Body.Close()

	// 4. Export Audit CSV
	resp, err = client.Get(ts.URL + "/api/v1/export/audit.csv")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed export audit csv: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected text/csv Content-Type, got %s", ct)
	}
	resp.Body.Close()

	// 5. Ingest Observation via API
	obsBody, _ := json.Marshal(models.Observation{
		Timestamp: time.Now(),
		Source:    "lan_agent",
		IP:        "192.168.1.20",
		MAC:       "00:11:22:33:44:02",
		Hostname:  "agent-discovered-device",
	})
	resp, err = client.Post(ts.URL+"/api/v1/observations", "application/json", bytes.NewReader(obsBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to post observation: %v", err)
	}
	resp.Body.Close()

	// Verify device count is now 2
	devsAfter := fusion.ListDevices()
	if len(devsAfter) != 2 {
		t.Errorf("expected 2 devices after observation ingestion, got %d", len(devsAfter))
	}
}
