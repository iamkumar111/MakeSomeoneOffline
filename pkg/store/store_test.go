package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
	"github.com/open-netcut/open-netcut/pkg/store"
)

func TestMemoryStoreOperations(t *testing.T) {
	s := store.NewMemoryStore()
	ctx := context.Background()

	// 1. Device Operations
	dev := &models.Device{
		ID:          "dev-1",
		SiteID:      "default",
		DisplayName: "Test Device",
		PrimaryIP:   "192.168.1.100",
		PrimaryMAC:  "00:11:22:33:44:55",
	}
	if err := s.SaveDevice(ctx, dev); err != nil {
		t.Fatalf("failed to save device: %v", err)
	}

	gotDev, err := s.GetDevice(ctx, "dev-1")
	if err != nil || gotDev.DisplayName != "Test Device" {
		t.Fatalf("unexpected GetDevice result: %v", err)
	}

	devs, err := s.ListDevices(ctx, "default")
	if err != nil || len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}

	// 2. Alert Operations
	alert := &models.Alert{
		ID:       "alert-1",
		Type:     models.AlertGatewayImpersonation,
		Severity: models.SeverityCritical,
	}
	if err := s.SaveAlert(ctx, alert); err != nil {
		t.Fatalf("failed to save alert: %v", err)
	}
	alerts, err := s.ListAlerts(ctx)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// 3. Policy & Enforcement Operations
	p := &models.Policy{
		ID:   "pol-1",
		Name: "Quarantine Dev 1",
		Selector: models.PolicySelector{
			DeviceID: "dev-1",
		},
		Action: models.PolicyAction{
			Type: models.ActionQuarantine,
		},
	}
	_ = s.SavePolicy(ctx, p)
	policies, _ := s.ListPolicies(ctx)
	if len(policies) != 1 {
		t.Errorf("expected 1 policy")
	}

	enf := &models.Enforcement{
		ID:       "enf-1",
		DeviceID: "dev-1",
		Action:   models.ActionQuarantine,
	}
	_ = s.SaveEnforcement(ctx, enf)
	enforcements, _ := s.ListEnforcements(ctx)
	if len(enforcements) != 1 {
		t.Errorf("expected 1 enforcement")
	}

	// 4. Audit Log Operations
	audit := &models.AuditLog{
		ID:        "audit-1",
		Timestamp: time.Now(),
		Action:    "quarantine_applied",
		Actor:     "admin",
	}
	_ = s.SaveAuditLog(ctx, audit)
	logs, err := s.ListAuditLogs(ctx, 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d", len(logs))
	}
}

func TestSnapshotCorruptionFallback(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/netcut.json"

	// Seed a store with one device and snapshot it.
	s := store.NewMemoryStore()
	dev := &models.Device{ID: "dev-1", PrimaryIP: "192.168.1.50", PrimaryMAC: "aa:bb:cc:dd:ee:ff"}
	if err := s.SaveDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveToFile(path); err != nil {
		t.Fatal(err)
	}

	// Corrupt the primary: .bak (written by SaveToFile? no — .bak only exists
	// after a second save). Save twice so a .bak exists.
	if err := s.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	// Valid .bak rescues the data (error reports the fallback).
	s2 := store.NewMemoryStore()
	err := s2.LoadFromFile(path)
	if err == nil {
		t.Fatal("expected fallback notice error")
	}
	got, lerr := s2.GetDevice(ctx, "dev-1")
	if lerr != nil || got.PrimaryIP != "192.168.1.50" {
		t.Fatalf("expected device rescued from .bak, got %+v err=%v", got, lerr)
	}

	// Both corrupt: hard error + .corrupt quarantine copy for forensics.
	if err := os.WriteFile(path+".bak", []byte("{also bad"), 0600); err != nil {
		t.Fatal(err)
	}
	s3 := store.NewMemoryStore()
	if err := s3.LoadFromFile(path); err == nil {
		t.Fatal("expected hard error when both copies corrupt")
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatal("expected .corrupt quarantine copy")
	}
}
