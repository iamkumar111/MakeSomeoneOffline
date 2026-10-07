package adapters

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/open-netcut/open-netcut/pkg/models"
)

type macTestWriter struct {
	mu     sync.Mutex
	frames [][]byte
	fail   bool
	closed bool
}

func (w *macTestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail {
		return 0, errors.New("injection denied")
	}
	w.frames = append(w.frames, append([]byte(nil), p...))
	return len(p), nil
}
func (w *macTestWriter) Close() error      { w.mu.Lock(); defer w.mu.Unlock(); w.closed = true; return nil }
func (w *macTestWriter) setFail(fail bool) { w.mu.Lock(); defer w.mu.Unlock(); w.fail = fail }
func macTestPlan() macOSPlan {
	mac := func(value string) net.HardwareAddr { m, _ := net.ParseMAC(value); return m }
	return macOSPlan{iface: "en0", hostIP: net.ParseIP("192.168.1.10"), hostMAC: mac("02:00:00:00:00:10"), gwIP: net.ParseIP("192.168.1.1"), gwMAC: mac("02:00:00:00:00:01"), targetMAC: mac("02:00:00:00:00:24")}
}
func macTestAdapter(w *macTestWriter) *MacOSSideHostAdapter {
	a := newMacOSSideHostAdapter(macOSDependencies{check: func(context.Context) error { return nil }, resolve: func(context.Context, net.IP) (macOSPlan, error) { return macTestPlan(), nil }, open: func(string) (io.WriteCloser, error) { return w, nil }})
	a.healRounds = 1
	a.healInterval = 0
	return a
}
func macTestEnforcement() *models.Enforcement {
	return &models.Enforcement{ID: "cut1", TargetIP: "192.168.1.24", TargetMAC: "02:00:00:00:00:24"}
}

func TestMacCutReleaseAndDryRun(t *testing.T) {
	w := &macTestWriter{}
	a := macTestAdapter(w)
	e := macTestEnforcement()
	if err := a.ApplyQuarantine(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	preview := *e
	preview.DryRun = true
	if err := a.RemoveQuarantine(context.Background(), &preview); err != nil || len(a.active) != 1 {
		t.Fatal("preview removed live cut")
	}
	wrong := *e
	wrong.ID = "other"
	if err := a.RemoveQuarantine(context.Background(), &wrong); err == nil {
		t.Fatal("wrong owner released cut")
	}
	if err := a.RemoveQuarantine(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if !w.closed || len(a.active) != 0 || e.ActualState != models.StateRolledBack {
		t.Fatal("release incomplete")
	}
	// The last six frames heal, with genuine Ethernet AND ARP source MACs.
	frames := w.frames[len(w.frames)-6:]
	for _, f := range frames {
		if !bytes.Equal(f[6:12], f[22:28]) || bytes.Equal(f[6:12], macTestPlan().hostMAC) {
			t.Fatal("healing used operator MAC")
		}
	}
}

func TestMacReleaseFailureRetainsRetryAndInitialFailureRetainsOwnership(t *testing.T) {
	w := &macTestWriter{}
	a := macTestAdapter(w)
	e := macTestEnforcement()
	if err := a.ApplyQuarantine(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	w.setFail(true)
	if err := a.RemoveQuarantine(context.Background(), e); err == nil || len(a.active) != 1 || w.closed {
		t.Fatal("failed release lost retry state")
	}
	w.setFail(false)
	if err := a.RemoveQuarantine(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	w = &macTestWriter{fail: true}
	a = macTestAdapter(w)
	e = macTestEnforcement()
	if err := a.ApplyQuarantine(context.Background(), e); err == nil || e.ActualState != models.StateApplied || len(a.active) != 1 {
		t.Fatal("partial failure lost restoration owner")
	}
	w.setFail(false)
	if err := a.RemoveQuarantine(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

func TestMacSafetyAndShutdown(t *testing.T) {
	w := &macTestWriter{}
	a := macTestAdapter(w)
	e := macTestEnforcement()
	a.deps.check = func(context.Context) error { return errors.New("forwarding unknown") }
	if err := a.ApplyQuarantine(context.Background(), e); err == nil || len(w.frames) != 0 {
		t.Fatal("unsafe injection")
	}
	e.DryRun = true
	if err := a.ApplyQuarantine(context.Background(), e); err != nil || len(w.frames) != 0 {
		t.Fatal("preview did I/O")
	}
	plan := macTestPlan()
	if _, _, err := macOSFrames(plan, plan.gwIP, plan.gwMAC); err == nil {
		t.Fatal("gateway accepted")
	}
	if _, _, err := macOSFrames(plan, net.ParseIP(e.TargetIP), plan.hostMAC); err == nil {
		t.Fatal("host MAC accepted")
	}
	plan.gwMAC = plan.hostMAC
	if _, _, err := macOSFrames(plan, net.ParseIP(e.TargetIP), plan.targetMAC); err == nil {
		t.Fatal("poisoned gateway accepted")
	}
	a = macTestAdapter(w)
	e = macTestEnforcement()
	if err := a.ApplyQuarantine(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyQuarantine(context.Background(), e); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := a.Shutdown(context.Background()); err != nil || len(a.active) != 0 || !w.closed {
		t.Fatal("shutdown did not restore")
	}
}

func TestMacNeighborParsingAndIPv6Frames(t *testing.T) {
	output := "fe80::1%en0 2:0:0:0:0:1 en0 23h59m S R\nfe80::24%en0 2:0:0:0:0:24 en0 20s R\nfe80::2%en1 2:0:0:0:0:2 en0 20s R\nfe80::3%en0 (incomplete) en0 1s I\n"
	n := parseMacNDP(output, "en0")
	if len(n) != 2 {
		t.Fatalf("neighbors: %+v", n)
	}
	plan := macTestPlan()
	plan.gatewayIPv6 = n[plan.gwMAC.String()]
	plan.victimIPv6 = n[plan.targetMAC.String()]
	poison, heal, err := macOSFrames(plan, net.ParseIP("192.168.1.24"), plan.targetMAC)
	if err != nil || len(poison) != 6 || len(heal) != 8 {
		t.Fatalf("dual-stack frames: %d %d %v", len(poison), len(heal), err)
	}
	if !macEthernetInterface("en0") || macEthernetInterface("utun0") || macEthernetInterface("en0;bad") {
		t.Fatal("invalid interface accepted")
	}
	if got := macRouteField(" gateway: 192.168.1.1\n interface: en0\n", "interface"); got != "en0" {
		t.Fatal(got)
	}
}

func TestMacNeverRecommendedAutomatically(t *testing.T) {
	mac := macTestAdapter(&macTestWriter{})
	mock := NewMemoryMockAdapter("mock_simulator")
	ranked := MarkRecommended([]RankedAdapter{{Info: mac.Describe(), Available: true, SupportsAction: true}, {Info: mock.Describe(), Available: true, SupportsAction: true}})
	if ranked[0].Recommended || !ranked[1].Recommended {
		t.Fatal("experimental macOS cut was auto-selected")
	}
}
