package adapters

import (
	"context"
	"testing"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// stubAdapter is a configurable NetworkAdapter for ranking tests.
type stubAdapter struct {
	name      string
	info      AdapterInfo
	available bool
}

func (s *stubAdapter) Name() string                     { return s.name }
func (s *stubAdapter) Capabilities() []string           { return s.info.Capabilities }
func (s *stubAdapter) Describe() AdapterInfo            { return s.info }
func (s *stubAdapter) IsAvailable(context.Context) bool { return s.available }
func (s *stubAdapter) ApplyQuarantine(context.Context, *models.Enforcement) error {
	return nil
}
func (s *stubAdapter) RemoveQuarantine(context.Context, *models.Enforcement) error {
	return nil
}
func (s *stubAdapter) ApplyRateLimit(context.Context, *models.Enforcement) error {
	return nil
}
func (s *stubAdapter) RemoveRateLimit(context.Context, *models.Enforcement) error {
	return nil
}

func quarantineStub(name string, eff int, lab, avail bool) *stubAdapter {
	return &stubAdapter{name: name, available: avail, info: AdapterInfo{
		Name: name, Effectiveness: eff, LabOnly: lab,
		Capabilities:       []string{"quarantine"},
		SupportsQuarantine: true,
	}}
}

func TestRankedPrefersAvailableNonLab(t *testing.T) {
	r := NewAdapterRegistry()
	r.Register(quarantineStub("l2_arp", 4, true, true))
	r.Register(quarantineStub("linux_nftables", 5, false, true))
	r.Register(quarantineStub("openwrt", 5, false, false)) // offline

	ranked := MarkRecommended(r.Ranked(context.Background(), "quarantine"))
	if len(ranked) != 3 {
		t.Fatalf("expected 3, got %d", len(ranked))
	}
	if ranked[0].Info.Name != "linux_nftables" {
		t.Fatalf("expected nftables first, got %s", ranked[0].Info.Name)
	}
	if !ranked[0].Recommended {
		t.Fatal("expected nftables recommended")
	}
	// Lab-only must sort after healthy adapters even with high effectiveness.
	if ranked[1].Info.Name != "l2_arp" || ranked[1].Recommended {
		t.Fatalf("expected l2_arp second, unrecommended: %+v", ranked[1])
	}
	if ranked[2].Info.Name != "openwrt" || ranked[2].Available {
		t.Fatalf("expected offline openwrt last: %+v", ranked[2])
	}
}

func TestRankedFallsBackToLabWhenNothingElse(t *testing.T) {
	r := NewAdapterRegistry()
	r.Register(quarantineStub("l2_arp", 4, true, true))

	ranked := MarkRecommended(r.Ranked(context.Background(), "quarantine"))
	if len(ranked) != 1 || !ranked[0].Recommended {
		t.Fatalf("expected lone lab adapter recommended, got %+v", ranked)
	}
	if ranked[0].Reason == "" {
		t.Fatal("expected a reason string")
	}
}

func TestRankedFiltersByAction(t *testing.T) {
	r := NewAdapterRegistry()
	shaper := &stubAdapter{name: "linux_tc", available: true, info: AdapterInfo{
		Name: "linux_tc", Effectiveness: 5,
		Capabilities:    []string{"rate_limit"},
		SupportsShaping: true,
	}}
	r.Register(shaper)
	r.Register(quarantineStub("linux_nftables", 5, false, true))

	ranked := MarkRecommended(r.Ranked(context.Background(), "rate_limit"))
	if len(ranked) != 2 {
		t.Fatalf("expected 2, got %d", len(ranked))
	}
	if ranked[0].Info.Name != "linux_tc" || !ranked[0].SupportsAction {
		t.Fatalf("expected tc first: %+v", ranked[0])
	}
	if ranked[1].SupportsAction {
		t.Fatal("quarantine-only adapter must not support shaping")
	}
}
