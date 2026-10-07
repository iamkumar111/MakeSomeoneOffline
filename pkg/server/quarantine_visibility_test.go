package server_test

import (
	"context"
	"encoding/json"
	"errors"
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

type releaseFailureAdapter struct{ *adapters.MemoryMockAdapter }

func (a *releaseFailureAdapter) RemoveQuarantine(context.Context, *models.Enforcement) error {
	return errors.New("healing frames could not be sent")
}

func TestQuarantineVisibilityAndReleaseFailures(t *testing.T) {
	bus := events.NewEventBus()
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	registry.Register(&releaseFailureAdapter{adapters.NewMemoryMockAdapter("release_failure")})
	fusion := discovery.NewIdentityFusionEngine("test", bus)
	pol := policy.NewPolicyEngine(registry, bus, models.Allowlist{})
	t.Cleanup(pol.Stop)
	det := detection.NewDetectionEngine(detection.KnownGateway{}, bus)
	tel := traffic.NewTelemetryEngine("test", bus)
	ts := httptest.NewServer(server.NewServer(fusion, det, pol, tel, bus, store.NewMemoryStore(), "test").Handler())
	t.Cleanup(ts.Close)
	dev := fusion.IngestObservation(models.Observation{Timestamp: time.Now(), Source: "arp", IP: "192.168.1.24", MAC: "02:00:00:00:00:24"})
	if err := fusion.SetTrustState(dev.ID, models.TrustStateTrusted); err != nil {
		t.Fatal(err)
	}
	preview, err := pol.ApplyQuarantine(t.Context(), dev, "mock_simulator", time.Minute, "test", true)
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string, value interface{}) {
		t.Helper()
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(value); err != nil {
			t.Fatal(err)
		}
	}
	var stats map[string]interface{}
	read("/api/v1/stats", &stats)
	if stats["quarantined_devices"] != float64(0) {
		t.Fatal("preview counted as quarantined")
	}
	// Direct engine application reproduces schedules/automation without a trust mutation.
	live, err := pol.ApplyQuarantine(t.Context(), dev, "mock_simulator", time.Minute, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	read("/api/v1/stats", &stats)
	if stats["quarantined_devices"] != float64(1) {
		t.Fatalf("stats: %v", stats)
	}
	var devices []models.Device
	read("/api/v1/devices", &devices)
	if len(devices) != 1 || devices[0].TrustState != models.TrustStateQuarantined {
		t.Fatalf("devices: %v", devices)
	}
	var detail models.Device
	read("/api/v1/devices/"+dev.ID, &detail)
	if detail.TrustState != models.TrustStateQuarantined {
		t.Fatal("detail missed live cut")
	}
	if dev.TrustState != models.TrustStateTrusted {
		t.Fatal("view changed administrative trust")
	}
	if err := pol.RemoveQuarantine(t.Context(), live.ID, "test"); err != nil {
		t.Fatal(err)
	}
	read("/api/v1/devices", &devices)
	if devices[0].TrustState != models.TrustStateTrusted {
		t.Fatal("release did not restore trusted display")
	}
	if err := pol.RemoveQuarantine(t.Context(), preview.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pol.ApplyRateLimit(t.Context(), dev, "mock_simulator", 1000, 1000, time.Minute, "test", false); err != nil {
		t.Fatal(err)
	}
	read("/api/v1/stats", &stats)
	if stats["quarantined_devices"] != float64(0) {
		t.Fatal("shaping counted as cut")
	}
	if _, err := pol.ApplyQuarantine(t.Context(), dev, "release_failure", time.Minute, "test", false); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/devices/"+dev.ID+"/quarantine", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("release status=%d", resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["remove_failures"] != float64(1) {
		t.Fatalf("release: %v", result)
	}
	read("/api/v1/stats", &stats)
	if stats["quarantined_devices"] != float64(1) {
		t.Fatal("failed release hid remaining cut")
	}
}
