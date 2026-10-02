package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestFreezeConflictAndIdempotentRelease(t *testing.T) {
	ts, fusion := setupWiredServer(t)
	client := ts.Client()

	fusion.IngestObservation(models.Observation{Timestamp: time.Now(), Source: "arp", MAC: "00:11:22:33:44:0a", IP: "192.168.1.81"})
	body := map[string]interface{}{"adapter": "mock_simulator", "ttl_seconds": 60, "reason": "conflict test", "dry_run": false}
	raw, _ := json.Marshal(body)
	resp, err := client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
	pollEnforcements(t, client, ts.URL, 1, 5*time.Second)

	resp, err = client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var conflict map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&conflict)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || conflict["status"] != "already_frozen" {
		t.Fatalf("expected 409 already_frozen, got %d %v", resp.StatusCode, conflict)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/freeze", nil)
	resp, _ = client.Do(req)
	resp.Body.Close()
	pollEnforcements(t, client, ts.URL, 0, 5*time.Second)

	resp, _ = client.Get(ts.URL + "/api/v1/freeze")
	var st map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st["active"] != false {
		t.Fatalf("expected inactive freeze after unfreeze, got %v", st)
	}

	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/freeze", nil)
	resp, _ = client.Do(req)
	var already map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&already)
	resp.Body.Close()
	if already["status"] != "already_released" {
		t.Fatalf("expected already_released, got %v", already)
	}
}

func TestFreezeLoopbackSelfWarning(t *testing.T) {
	ts, _ := setupWiredServer(t)
	client := ts.Client()

	body := map[string]interface{}{"adapter": "mock_simulator", "ttl_seconds": 60, "reason": "self-warning", "dry_run": true, "include_self": false}
	raw, _ := json.Marshal(body)
	resp, err := client.Post(ts.URL+"/api/v1/freeze", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d %v", resp.StatusCode, res)
	}
	if res["self_warning"] == nil || !strings.Contains(res["self_warning"].(string), "may cut yourself") {
		t.Fatalf("expected loopback self warning, got %v", res)
	}
}
