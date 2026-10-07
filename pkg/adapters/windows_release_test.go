//go:build windows

package adapters

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestWindowsReleaseRestoresSavedEndpointsAndRetries(t *testing.T) {
	oldRounds, oldInterval := healRounds, healInterval
	healRounds, healInterval = 3, 0
	t.Cleanup(func() { healRounds, healInterval = oldRounds, oldInterval })
	a := NewWindowsSideHostAdapter()
	gwMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	targetMAC, _ := net.ParseMAC("02:00:00:00:00:24")
	done := make(chan struct{})
	close(done)
	closed, sends, fail := false, 0, true
	cut := &windowsCut{stop: make(chan struct{}), done: done,
		gwIP: net.ParseIP("192.168.1.1"), gwMAC: gwMAC,
		targetIP: net.ParseIP("192.168.1.24"), targetMAC: targetMAC,
		closeHandle: func() { closed = true },
	}
	cut.send = func(frame []byte) error {
		if closed {
			t.Fatal("sent after handle closed")
		}
		sends++
		// Genuine sender MACs must survive release without re-resolving ARP.
		sender := net.HardwareAddr(frame[22:28]).String()
		if sender != gwMAC.String() && sender != targetMAC.String() {
			t.Fatalf("wrong sender %s", sender)
		}
		if fail {
			return errors.New("injection failed")
		}
		return nil
	}
	a.active["192.168.1.24"] = cut
	e := &models.Enforcement{TargetIP: "192.168.1.24", ActualState: models.StateApplied}
	if err := a.RemoveQuarantine(t.Context(), e); err == nil || !strings.Contains(err.Error(), "healing frames") {
		t.Fatalf("error: %v", err)
	}
	if closed || a.active[e.TargetIP] == nil || e.ActualState != models.StateApplied {
		t.Fatal("failed healing must retain session for retry")
	}
	fail = false
	sends = 0
	if err := a.RemoveQuarantine(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if sends != 3*6 || !closed || a.active[e.TargetIP] != nil || e.ActualState != models.StateRolledBack {
		t.Fatalf("sends=%d closed=%v state=%s", sends, closed, e.ActualState)
	}
}

func TestWindowsReleaseDryRunDoesNotStopLiveCut(t *testing.T) {
	a := NewWindowsSideHostAdapter()
	stop := make(chan struct{})
	a.active["192.168.1.24"] = &windowsCut{stop: stop}
	e := &models.Enforcement{TargetIP: "192.168.1.24", DryRun: true}
	if err := a.RemoveQuarantine(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stop:
		t.Fatal("preview release stopped real quarantine")
	default:
	}
	if a.active[e.TargetIP] == nil {
		t.Fatal("preview release removed live session")
	}
}
