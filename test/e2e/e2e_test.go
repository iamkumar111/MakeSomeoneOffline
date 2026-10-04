package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func setupTestServer(t *testing.T) (*httptest.Server, *discovery.IdentityFusionEngine, *detection.DetectionEngine, *policy.PolicyEngine) {
	eventBus := events.NewEventBus()
	gwIP := "192.168.1.1"
	gwMAC := "00:11:22:33:44:55"

	allowlist := models.Allowlist{
		GatewayIPs:    []string{gwIP},
		GatewayMACs:   []string{gwMAC},
		DNSIPs:        []string{"1.1.1.1", "8.8.8.8", gwIP},
		AdminIPs:      []string{"127.0.0.1"},
		ControllerIPs: []string{"127.0.0.1"},
	}

	registry := adapters.NewAdapterRegistry()
	mockAdapter := adapters.NewMemoryMockAdapter("mock_simulator")
	registry.Register(mockAdapter)

	fusionEngine := discovery.NewIdentityFusionEngine("e2e-site", eventBus)
	detectionEngine := detection.NewDetectionEngine(detection.KnownGateway{
		IP:  gwIP,
		MAC: gwMAC,
	}, eventBus)
	policyEngine := policy.NewPolicyEngine(registry, eventBus, allowlist)
	memStore := store.NewMemoryStore()
	telemetryEngine := traffic.NewTelemetryEngine("e2e-site", eventBus)

	srv := server.NewServer(fusionEngine, detectionEngine, policyEngine, telemetryEngine, eventBus, memStore, "e2e-site")
	ts := httptest.NewServer(srv.Handler())

	return ts, fusionEngine, detectionEngine, policyEngine
}

func TestE2EWorkflow(t *testing.T) {
	ts, fusionEngine, detectionEngine, _ := setupTestServer(t)
	defer ts.Close()

	client := ts.Client()

	// 1. Initial Stats Check
	resp, err := client.Get(ts.URL + "/api/v1/stats")
	if err != nil {
		t.Fatalf("failed to GET stats: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /stats, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Discover Legitimate Devices
	dev1 := fusionEngine.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.50",
		MAC:       "b8:27:eb:aa:bb:cc", // Raspberry Pi
		Hostname:  "octopi",
	})
	if dev1 == nil {
		t.Fatal("failed to ingest dev1")
	}

	// Also ingest gateway device
	gwDev := fusionEngine.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.1",
		MAC:       "00:11:22:33:44:55",
	})

	// Query /api/v1/devices
	resp, err = client.Get(ts.URL + "/api/v1/devices")
	if err != nil {
		t.Fatalf("GET /devices error: %v", err)
	}
	var deviceList []models.Device
	_ = json.NewDecoder(resp.Body).Decode(&deviceList)
	resp.Body.Close()

	if len(deviceList) < 2 {
		t.Fatalf("expected at least 2 devices, got %d", len(deviceList))
	}

	// 3. Attack Simulation: Attacker spoofing the default gateway
	attackerObs := models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.1",       // Claims Gateway IP
		MAC:       "de:ad:be:ef:13:37", // Rogue MAC
	}
	alert := detectionEngine.AnalyzeObservation(attackerObs)
	if alert == nil {
		t.Fatal("expected detection engine to flag gateway impersonation alert")
	}
	if alert.Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL alert, got %s", alert.Severity)
	}

	// Query /api/v1/alerts
	resp, err = client.Get(ts.URL + "/api/v1/alerts")
	if err != nil {
		t.Fatalf("GET /alerts error: %v", err)
	}
	var alertList []models.Alert
	_ = json.NewDecoder(resp.Body).Decode(&alertList)
	resp.Body.Close()

	if len(alertList) == 0 {
		t.Fatal("expected alerts in API response")
	}
	if alertList[0].Type != models.AlertGatewayImpersonation {
		t.Errorf("expected alert type gateway_impersonation, got %s", alertList[0].Type)
	}

	// 4. Safety Engine Check: Attempting to quarantine Gateway MUST be blocked
	quarantineBody, _ := json.Marshal(map[string]interface{}{
		"adapter":     "mock_simulator",
		"ttl_seconds": 900,
		"dry_run":     false,
	})
	resp, err = client.Post(fmt.Sprintf("%s/api/v1/devices/%s/quarantine", ts.URL, gwDev.ID), "application/json", bytes.NewReader(quarantineBody))
	if err != nil {
		t.Fatalf("POST quarantine error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when quarantining protected gateway, got %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("safety violation")) {
		t.Errorf("expected 'safety violation' in response body, got %s", string(body))
	}

	// 5. Ingest Attacker as device and apply Quarantine
	attackerDev := fusionEngine.IngestObservation(models.Observation{
		Timestamp: time.Now(),
		Source:    "arp",
		IP:        "192.168.1.99",
		MAC:       "de:ad:be:ef:13:37",
	})

	resp, err = client.Post(fmt.Sprintf("%s/api/v1/devices/%s/quarantine", ts.URL, attackerDev.ID), "application/json", bytes.NewReader(quarantineBody))
	if err != nil {
		t.Fatalf("POST quarantine error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for attacker quarantine, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify device trust state is now quarantined
	resp, err = client.Get(fmt.Sprintf("%s/api/v1/devices/%s", ts.URL, attackerDev.ID))
	if err != nil {
		t.Fatalf("GET /devices/:id error: %v", err)
	}
	var updatedAttacker models.Device
	_ = json.NewDecoder(resp.Body).Decode(&updatedAttacker)
	resp.Body.Close()

	if updatedAttacker.TrustState != models.TrustStateQuarantined {
		t.Errorf("expected trust state quarantined, got %s", updatedAttacker.TrustState)
	}

	// 6. Rate Limit dev1
	rateLimitBody, _ := json.Marshal(map[string]interface{}{
		"adapter":      "mock_simulator",
		"download_bps": 5000000,
		"upload_bps":   1000000,
		"ttl_seconds":  3600,
	})
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/devices/%s/rate-limit", ts.URL, dev1.ID), bytes.NewReader(rateLimitBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT rate-limit error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for rate limit, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 7. Lift Quarantine on Attacker
	req, _ = http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/devices/%s/quarantine", ts.URL, attackerDev.ID), nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DELETE quarantine error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for lift quarantine, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 8. Audit Logs Check
	resp, err = client.Get(ts.URL + "/api/v1/audit")
	if err != nil {
		t.Fatalf("GET /audit error: %v", err)
	}
	var auditList []models.AuditLog
	_ = json.NewDecoder(resp.Body).Decode(&auditList)
	resp.Body.Close()

	if len(auditList) < 3 {
		t.Fatalf("expected at least 3 audit logs, got %d", len(auditList))
	}

	// Verify rejected gateway quarantine was logged in audit
	foundRejected := false
	for _, l := range auditList {
		if l.Action == "quarantine_rejected" {
			foundRejected = true
			break
		}
	}
	if !foundRejected {
		t.Errorf("expected quarantine_rejected audit entry")
	}
}
