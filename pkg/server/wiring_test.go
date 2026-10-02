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
	"github.com/open-netcut/open-netcut/pkg/notify"
	"github.com/open-netcut/open-netcut/pkg/policy"
	"github.com/open-netcut/open-netcut/pkg/server"
	"github.com/open-netcut/open-netcut/pkg/store"
	"github.com/open-netcut/open-netcut/pkg/traffic"
)

func setupWiredServer(t *testing.T, opts ...server.ServerOption) (*httptest.Server, *discovery.IdentityFusionEngine) {
	t.Helper()
	bus := events.NewEventBus()
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	fusion := discovery.NewIdentityFusionEngine("test-site", bus)
	det := detection.NewDetectionEngine(detection.KnownGateway{}, bus)
	pol := policy.NewPolicyEngine(registry, bus, models.Allowlist{})
	tel := traffic.NewTelemetryEngine("test-site", bus)
	fc := policy.NewFreezeController(pol, bus,
		fusion.ListDevices,
		func(id string, state models.TrustState) error { return fusion.SetTrustState(id, state) },
		pol.IsProtected,
	)
	t.Cleanup(fc.Stop)
	opts = append(opts, server.WithFreezeController(fc))
	srv := server.NewServer(fusion, det, pol, tel, bus, store.NewMemoryStore(), "test-site", opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, fusion
}

func TestSchedulesAPIEndToEnd(t *testing.T) {
	bus := events.NewEventBus()
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	fusion := discovery.NewIdentityFusionEngine("test-site", bus)
	det := detection.NewDetectionEngine(detection.KnownGateway{}, bus)
	pol := policy.NewPolicyEngine(registry, bus, models.Allowlist{})
	sm := policy.NewScheduleManager(pol)
	defer sm.Stop()
	sm.SetResolver(func(id string) *models.Device {
		d, _ := fusion.GetDevice(id)
		return d
	})
	tel := traffic.NewTelemetryEngine("test-site", bus)
	srv := server.NewServer(fusion, det, pol, tel, bus, store.NewMemoryStore(), "test-site", server.WithScheduler(sm))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	// Device must exist for the schedule to make sense (resolver path).
	dev := fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:99", IP: "192.168.1.99",
	})
	if dev == nil {
		t.Fatal("device not created")
	}

	// Create a schedule covering the whole day.
	body, _ := json.Marshal(map[string]interface{}{
		"device_id": dev.ID, "start_hour": 0, "start_min": 0,
		"end_hour": 23, "end_min": 59, "action": "quarantine",
	})
	resp, err := client.Post(ts.URL+"/api/v1/schedules", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create schedule: %v status=%d", err, resp.StatusCode)
	}
	var created map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("expected schedule id")
	}

	// List shows it.
	resp, _ = client.Get(ts.URL + "/api/v1/schedules")
	var list []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list) != 1 {
		t.Fatalf("expected 1 schedule, got %d", len(list))
	}

	// Invalid hours rejected.
	bad, _ := json.Marshal(map[string]interface{}{"device_id": dev.ID, "start_hour": 99})
	resp, _ = client.Post(ts.URL+"/api/v1/schedules", "application/json", bytes.NewReader(bad))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad hours, got %d", resp.StatusCode)
	}

	// Delete works.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/schedules/"+id, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestWebhooksAndRemediationAPI(t *testing.T) {
	ts, _ := setupWiredServer(t)
	_ = ts
	// Rebuild with dispatcher + autoRem for this test.
	bus := events.NewEventBus()
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	fusion := discovery.NewIdentityFusionEngine("test-site", bus)
	det := detection.NewDetectionEngine(detection.KnownGateway{}, bus)
	pol := policy.NewPolicyEngine(registry, bus, models.Allowlist{})
	tel := traffic.NewTelemetryEngine("test-site", bus)
	ad := notify.NewAlertDispatcher(bus)
	defer ad.Stop()
	ar := policy.NewAutoRemediationEngine(pol, bus, "", time.Minute)
	defer ar.Stop()
	srv := server.NewServer(fusion, det, pol, tel, bus, store.NewMemoryStore(), "test-site",
		server.WithAlertDispatcher(ad), server.WithAutoRemediation(ar))
	ts2 := httptest.NewServer(srv.Handler())
	defer ts2.Close()
	client := ts2.Client()

	// Remediation state reflects the engine.
	resp, _ := client.Get(ts2.URL + "/api/v1/remediation")
	var rem map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&rem)
	resp.Body.Close()
	if rem["auto_remediation_active"] != true {
		t.Fatalf("expected active remediation, got %v", rem)
	}
	// Toggle off.
	toggle, _ := json.Marshal(map[string]bool{"enabled": false})
	resp, _ = client.Post(ts2.URL+"/api/v1/remediation", "application/json", bytes.NewReader(toggle))
	resp.Body.Close()
	if ar.IsEnabled() {
		t.Fatal("expected remediation disabled")
	}

	// Bad webhook URL rejected.
	bad, _ := json.Marshal(map[string]string{"url": "ftp://x"})
	resp, _ = client.Post(ts2.URL+"/api/v1/webhooks", "application/json", bytes.NewReader(bad))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad url, got %d", resp.StatusCode)
	}
	// Good webhook registers.
	good, _ := json.Marshal(map[string]string{"name": "t", "url": "https://example.com/hook", "min_severity": "high"})
	resp, err := client.Post(ts2.URL+"/api/v1/webhooks", "application/json", bytes.NewReader(good))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("register webhook: %v status=%d", err, resp.StatusCode)
	}
	var ep map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&ep)
	resp.Body.Close()
	if len(ad.ListEndpoints()) != 1 {
		t.Fatal("expected 1 endpoint in dispatcher")
	}
}

func TestTrustAPIOpenMode(t *testing.T) {
	// No token configured: API is open, trust works without credentials.
	ts, fusion := setupWiredServer(t)
	client := ts.Client()
	resp, _ := client.Get(ts.URL + "/api/v1/devices")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 in open mode, got %d", resp.StatusCode)
	}
	dev := fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:98", IP: "192.168.1.98",
	})
	body, _ := json.Marshal(map[string]string{"state": "trusted"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/devices/"+dev.ID+"/trust", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("trust set: %v status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()
	after, _ := fusion.GetDevice(dev.ID)
	if after.TrustState != models.TrustStateTrusted {
		t.Fatalf("expected trusted, got %s", after.TrustState)
	}
	// Bad state rejected.
	bad, _ := json.Marshal(map[string]string{"state": "quarantined"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/devices/"+dev.ID+"/trust", bytes.NewReader(bad))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for quarantined via trust endpoint, got %d", resp.StatusCode)
	}
}

func TestCamerasAPIListAndGuards(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()

	// Camera-classified device shows up; plain device does not.
	cam := fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "fingerprint",
		MAC: "00:11:22:33:44:c1", IP: "192.168.1.61", Hostname: "IP-Camera-NVR",
		Attributes: map[string]interface{}{"device_type": "IP Camera / NVR"},
	})
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:c2", IP: "192.168.1.62",
	})
	resp, _ := client.Get(ts.URL + "/api/v1/cameras")
	var list []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list) != 1 || list[0]["id"] != cam.ID {
		t.Fatalf("expected 1 camera, got %v", list)
	}

	// Unknown camera id -> 404.
	resp, _ = client.Get(ts.URL + "/api/v1/cameras/nope/image?path=/snapshot.jpg")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	// Path traversal rejected.
	resp, _ = client.Get(ts.URL + "/api/v1/cameras/" + cam.ID + "/image?path=/../etc/passwd")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for traversal, got %d", resp.StatusCode)
	}
	// Missing param rejected.
	resp, _ = client.Get(ts.URL + "/api/v1/cameras/" + cam.ID + "/image")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing param, got %d", resp.StatusCode)
	}
	// Foreign-host src rejected (SSRF guard).
	resp, _ = client.Get(ts.URL + "/api/v1/cameras/" + cam.ID + "/image?src=http://10.9.9.9/x.jpg")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign src, got %d", resp.StatusCode)
	}
	// Non-http scheme rejected.
	resp, _ = client.Get(ts.URL + "/api/v1/cameras/" + cam.ID + "/image?src=ftp://192.168.1.61/x.jpg")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for ftp src, got %d", resp.StatusCode)
	}
}

func TestDeviceLookupByMAC(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:E0:27:2E:B1:B3", IP: "192.168.1.18",
	})
	// Uppercase/dash-free MAC in URL resolves the same device.
	for _, macURL := range []string{"00:e0:27:2e:b1:b3", "00-E0-27-2E-B1-B3"} {
		resp, _ := client.Get(ts.URL + "/api/v1/devices/" + macURL)
		var dev models.Device
		_ = json.NewDecoder(resp.Body).Decode(&dev)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || dev.PrimaryIP != "192.168.1.18" {
			t.Fatalf("mac %s: status=%d dev=%+v", macURL, resp.StatusCode, dev)
		}
	}
	// Rename by MAC sticks.
	body, _ := json.Marshal(map[string]string{"name": "KJ SST"})
	resp, _ := client.Post(ts.URL+"/api/v1/devices/00:e0:27:2e:b1:b3/rename", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename by MAC status=%d", resp.StatusCode)
	}
	dev, _ := fusion.GetDeviceByMAC("00:e0:27:2e:b1:b3")
	if dev.DisplayName != "KJ SST" {
		t.Fatalf("expected KJ SST, got %q", dev.DisplayName)
	}
}

func pollEnforcements(t *testing.T, client *http.Client, base string, want int, timeout time.Duration) []map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, err := client.Get(base + "/api/v1/enforcements")
		if err == nil {
			var enfs []map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&enfs)
			resp.Body.Close()
			if len(enfs) == want {
				return enfs
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d enforcements", want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestFreezeAppliesAndLifts(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()

	online := fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:d1", IP: "192.168.1.71",
	})
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:d2", IP: "192.168.1.72",
	})

	// Freeze without reason is rejected synchronously.
	resp, _ := client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader([]byte(`{"adapter":"mock_simulator"}`)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 without reason, got %d", resp.StatusCode)
	}
	// Freeze with reason is accepted immediately (202); cuts land async.
	body, _ := json.Marshal(map[string]interface{}{"adapter": "mock_simulator", "ttl_seconds": 60, "reason": "test freeze", "dry_run": true})
	resp, err := client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || res["status"] != "freezing" {
		t.Fatalf("expected 202 freezing, got status=%d %v", resp.StatusCode, res)
	}
	if res["latch"] != false {
		t.Fatalf("dry run must not latch, got %v", res)
	}
	enfs := pollEnforcements(t, client, ts.URL, 2, 5*time.Second)
	for _, e := range enfs {
		if e["action"] != "quarantine" {
			t.Fatalf("unexpected enforcement action: %v", e)
		}
	}
	// Unfreeze unlatches immediately (202); lifts land async.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/freeze", nil)
	resp, _ = client.Do(req)
	var unres map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&unres)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || unres["status"] != "unfreezing" {
		t.Fatalf("expected 202 unfreezing, got status=%d %v", resp.StatusCode, unres)
	}
	pollEnforcements(t, client, ts.URL, 0, 5*time.Second)
	_ = online
}

func TestFreezeLatchCutsLateJoiners(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()

	body, _ := json.Marshal(map[string]interface{}{"adapter": "mock_simulator", "ttl_seconds": 60, "reason": "latch test", "dry_run": false})
	resp, _ := client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("freeze status=%d", resp.StatusCode)
	}
	// Latch reports on.
	resp, _ = client.Get(ts.URL + "/api/v1/freeze")
	var st map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st["active"] != true {
		t.Fatalf("expected active latch, got %v", st)
	}
	// A device discovered after the freeze must be auto-cut (dry-run Mock
	// adapter still records the enforcement).
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:e9", IP: "192.168.1.79",
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, _ := client.Get(ts.URL + "/api/v1/enforcements")
		var enfs []map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&enfs)
		resp.Body.Close()
		found := false
		for _, e := range enfs {
			if e["target_ip"] == "192.168.1.79" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late joiner was not auto-cut within 3s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Unfreeze unlatches immediately (202); lifts land async.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/freeze", nil)
	resp, _ = client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unfreeze status=%d", resp.StatusCode)
	}
	pollEnforcements(t, client, ts.URL, 0, 5*time.Second)
	resp, _ = client.Get(ts.URL + "/api/v1/freeze")
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st["active"] != false {
		t.Fatalf("expected latch off, got %v", st)
	}
}

func TestFreezeSelfExclusionEndToEnd(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()

	// whoami reports the caller (httptest => 127.0.0.1).
	resp, _ := client.Get(ts.URL + "/api/v1/whoami")
	var who map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&who)
	resp.Body.Close()
	if who["ip"] != "127.0.0.1" {
		t.Fatalf("expected caller 127.0.0.1, got %v", who)
	}
	// Register the caller's address as a device (simulating the admin's box).
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:self", IP: "127.0.0.1",
	})
	fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:e1", IP: "192.168.1.81",
	})

	freeze := func(includeSelf bool) map[string]interface{} {
		body, _ := json.Marshal(map[string]interface{}{"adapter": "mock_simulator", "ttl_seconds": 60, "reason": "self test", "dry_run": false, "include_self": includeSelf})
		resp, _ := client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader(body))
		var res map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		return res
	}
	listTargets := func() map[string]bool {
		resp, _ := client.Get(ts.URL + "/api/v1/enforcements")
		var enfs []map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&enfs)
		resp.Body.Close()
		out := map[string]bool{}
		for _, e := range enfs {
			if ip, ok := e["target_ip"].(string); ok {
				out[ip] = true
			}
		}
		return out
	}
	waitFor := func(want map[string]bool, timeout time.Duration) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for {
			got := listTargets()
			match := true
			for ip, wantCut := range want {
				if got[ip] != wantCut {
					match = false
				}
			}
			if match {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("targets mismatch: want %v got %v", want, got)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// Excluding self: other device cut, admin device untouched.
	res := freeze(false)
	if res["status"] != "freezing" {
		t.Fatalf("freeze failed: %v", res)
	}
	waitFor(map[string]bool{"192.168.1.81": true, "127.0.0.1": false}, 5*time.Second)
	// Unfreeze unlatches (202); lifts land async.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/freeze", nil)
	resp, _ = client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unfreeze status=%d", resp.StatusCode)
	}
	waitFor(map[string]bool{"192.168.1.81": false, "127.0.0.1": false}, 5*time.Second)
	// Including self: admin device cut too.
	res = freeze(true)
	if res["status"] != "freezing" {
		t.Fatalf("freeze failed: %v", res)
	}
	waitFor(map[string]bool{"192.168.1.81": true, "127.0.0.1": true}, 5*time.Second)
}

func TestRateLimitEndToEnd(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()

	dev := fusion.IngestObservation(models.Observation{
		Timestamp: time.Now(), Source: "arp",
		MAC: "00:11:22:33:44:r1", IP: "192.168.1.91",
	})
	if dev == nil {
		t.Fatal("device not created")
	}
	// MAC contains 'r1' (non-hex) to prove lookups key on records, not parsing.
	body, _ := json.Marshal(map[string]interface{}{
		"adapter": "mock_simulator", "download_bps": 2000000, "upload_bps": 1000000, "ttl_seconds": 60,
	})
	resp, err := client.Post(ts.URL+"/api/v1/devices/"+dev.ID+"/rate-limit", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("rate-limit apply: %v status=%d", err, resp.StatusCode)
	}
	var enf map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&enf)
	resp.Body.Close()
	if enf["action"] != "rate_limit" || enf["actual_state"] != "applied" {
		t.Fatalf("unexpected enforcement: %v", enf)
	}
	if enf["rate_download"] != float64(2000000) {
		t.Fatalf("download rate not stored: %v", enf)
	}
	// Per-device traffic endpoint still answers (zeroed stats, not 404).
	resp, _ = client.Get(ts.URL + "/api/v1/devices/" + dev.ID + "/traffic")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device traffic status=%d", resp.StatusCode)
	}
	// Lift via DELETE.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/devices/"+dev.ID+"/rate-limit", nil)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("rate-limit lift: %v status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()
}
