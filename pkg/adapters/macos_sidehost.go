package adapters

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// Transport-independent lifecycle; macOS supplies a native BPF writer.
type macOSPlan struct {
	iface                   string
	hostIP                  net.IP
	hostMAC                 net.HardwareAddr
	gwIP                    net.IP
	gwMAC                   net.HardwareAddr
	targetMAC               net.HardwareAddr
	victimIPv6, gatewayIPv6 []net.IP
}
type macOSDependencies struct {
	check   func(context.Context) error
	resolve func(context.Context, net.IP) (macOSPlan, error)
	open    func(string) (io.WriteCloser, error)
}
type macOSCut struct {
	id         string
	targetIP   string
	writer     io.WriteCloser
	stop, done chan struct{}
	once       sync.Once
	heal       []healPacket
}
type MacOSSideHostAdapter struct {
	mu           sync.Mutex
	deps         macOSDependencies
	active       map[string]*macOSCut
	healRounds   int
	healInterval time.Duration
	closing      bool
}

func newMacOSSideHostAdapter(deps macOSDependencies) *MacOSSideHostAdapter {
	return &MacOSSideHostAdapter{deps: deps, active: make(map[string]*macOSCut), healRounds: healRounds, healInterval: healInterval}
}
func (a *MacOSSideHostAdapter) Name() string           { return "macos_sidehost" }
func (a *MacOSSideHostAdapter) Capabilities() []string { return []string{"quarantine", "dry_run"} }
func (a *MacOSSideHostAdapter) Describe() AdapterInfo {
	return AdapterInfo{Name: a.Name(), Label: "macOS Side-Host — BPF ARP quarantine (experimental)", Kind: KindLab, Effectiveness: 3,
		Capabilities: a.Capabilities(), SupportsQuarantine: true, LabOnly: true, ExplicitSelection: true,
		RecommendedWhen: "Mac on the same unmanaged LAN as the target; explicit selection only.",
		Requires:        "ENABLE_MACOS_L2_ARP=1, root, Ethernet-compatible BPF interface, IPv4/IPv6 forwarding OFF.",
		Description:     "Native BPF sends ARP frames and restores saved genuine mappings on release/TTL. IPv6 NDP is best effort when both neighbor mappings are known.",
		Warning:         "Experimental; native Mac/LAN validation required. Wi-Fi drivers may reject or rewrite frames. Applied does not prove isolation; IPv6 may remain reachable."}
}
func (a *MacOSSideHostAdapter) IsAvailable(ctx context.Context) bool { return a.deps.check(ctx) == nil }

func validUnicastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00"
}

func macOSFrames(plan macOSPlan, targetIP net.IP, targetMAC net.HardwareAddr) ([]healPacket, []healPacket, error) {
	if targetIP == nil || targetIP.To4() == nil || !targetIP.IsGlobalUnicast() || !validUnicastMAC(targetMAC) {
		return nil, nil, fmt.Errorf("valid unicast target IPv4 and six-byte MAC required")
	}
	if plan.hostIP == nil || plan.hostIP.To4() == nil || !plan.hostIP.IsGlobalUnicast() || plan.gwIP == nil || plan.gwIP.To4() == nil || !plan.gwIP.IsGlobalUnicast() || !validUnicastMAC(plan.gwMAC) || !validUnicastMAC(plan.hostMAC) {
		return nil, nil, fmt.Errorf("genuine gateway and local interface endpoints required")
	}
	if !validUnicastMAC(plan.targetMAC) || plan.targetMAC.String() != targetMAC.String() {
		return nil, nil, fmt.Errorf("target MAC no longer matches the LAN neighbor cache; refresh discovery")
	}
	if targetIP.Equal(plan.hostIP) || targetIP.Equal(plan.gwIP) || targetMAC.String() == plan.hostMAC.String() || targetMAC.String() == plan.gwMAC.String() || plan.gwMAC.String() == plan.hostMAC.String() {
		return nil, nil, fmt.Errorf("refusing cut of local host/gateway or poisoned gateway mapping")
	}
	var poison []healPacket
	for _, op := range []uint16{2, 1} {
		f, _ := buildARPFrame(op, plan.hostMAC, targetMAC, plan.hostMAC, plan.gwIP, targetMAC, targetIP)
		poison = append(poison, healPacket{frame: f})
		f, _ = buildARPFrame(op, plan.hostMAC, plan.gwMAC, plan.hostMAC, targetIP, plan.gwMAC, plan.gwIP)
		poison = append(poison, healPacket{frame: f})
	}
	heal := healingFrames(plan.gwIP, plan.gwMAC, targetIP, targetMAC)
	if len(plan.victimIPv6) > 0 && len(plan.gatewayIPv6) > 0 {
		for _, ip := range plan.victimIPv6 {
			f, err := buildNAFrame(plan.hostMAC, plan.gwMAC, ip, gwPickSrc(plan.gatewayIPv6), ip, plan.hostMAC)
			if err != nil {
				return nil, nil, err
			}
			poison = append(poison, healPacket{frame: f})
		}
		for _, ip := range plan.gatewayIPv6 {
			f, err := buildNAFrame(plan.hostMAC, targetMAC, ip, gwPickSrc(plan.victimIPv6), ip, plan.hostMAC)
			if err != nil {
				return nil, nil, err
			}
			poison = append(poison, healPacket{frame: f})
		}
		heal = append(heal, healingNAFrames(plan.gatewayIPv6, plan.gwMAC, plan.victimIPv6, targetMAC)...)
	}
	return poison, heal, nil
}

func writeMacFrames(writer io.Writer, frames []healPacket) error {
	var first error
	for _, frame := range frames {
		n, err := writer.Write(frame.frame)
		if err == nil && n != len(frame.frame) {
			err = io.ErrShortWrite
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (a *MacOSSideHostAdapter) healCut(ctx context.Context, cut *macOSCut) error {
	var first error
	for round := 0; round < a.healRounds; round++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeMacFrames(cut.writer, cut.heal); err != nil && first == nil {
			first = err
		}
		if round+1 < a.healRounds {
			timer := time.NewTimer(a.healInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return first
}

func (a *MacOSSideHostAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}
	if err := a.deps.check(ctx); err != nil {
		return fmt.Errorf("refusing macOS cut: %w", err)
	}
	target := net.ParseIP(e.TargetIP)
	mac, err := net.ParseMAC(e.TargetMAC)
	if err != nil || target == nil || target.To4() == nil || !validUnicastMAC(mac) {
		return fmt.Errorf("valid target IPv4 and unicast MAC required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		return fmt.Errorf("macOS adapter is shutting down")
	}
	if _, exists := a.active[target.String()]; exists {
		return fmt.Errorf("target already has a macOS cut; restore it before applying another")
	}
	plan, err := a.deps.resolve(ctx, target)
	if err != nil {
		return fmt.Errorf("refusing macOS cut: %w", err)
	}
	poison, heal, err := macOSFrames(plan, target, mac)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writer, err := a.deps.open(plan.iface)
	if err != nil {
		return fmt.Errorf("open BPF on %s: %w", plan.iface, err)
	}
	cut := &macOSCut{id: e.ID, targetIP: target.String(), writer: writer, stop: make(chan struct{}), done: make(chan struct{}), heal: heal}
	if err := writeMacFrames(writer, poison); err != nil {
		close(cut.done)
		// The request may be cancelled after partial injection: cleanup gets its own budget.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if cleanupErr := a.healCut(cleanupCtx, cut); cleanupErr != nil {
			a.active[target.String()] = cut
			e.ActualState = models.StateApplied // retain restoration ownership in the policy engine
			return fmt.Errorf("partial BPF injection failed (%v); restoration incomplete (%v); use Restore", err, cleanupErr)
		}
		writer.Close()
		return fmt.Errorf("BPF injection failed; healing sent: %w", err)
	}
	a.active[target.String()] = cut
	go func() {
		defer close(cut.done)
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()
		failed := false
		for {
			select {
			case <-cut.stop:
				return
			case <-ticker.C:
				if err := writeMacFrames(writer, poison); err != nil {
					if !failed {
						log.Printf("macos_bpf_injection_failed enforcement=%s target=%s error=%q; isolation not confirmed", cut.id, cut.targetIP, err)
					}
					failed = true
				} else if failed {
					log.Printf("macos_bpf_injection_resumed enforcement=%s", cut.id)
					failed = false
				}
			}
		}
	}()
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	log.Printf("macos_bpf_applied enforcement=%s target=%s interface=%s ipv6_pairs=%t; verify target traffic", e.ID, target, plan.iface, len(plan.victimIPv6) > 0 && len(plan.gatewayIPv6) > 0)
	return nil
}

func (a *MacOSSideHostAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	if e.DryRun {
		e.ActualState = models.StateRolledBack
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := a.active[e.TargetIP]
	if cut == nil {
		e.ActualState = models.StateRolledBack
		return nil
	}
	if cut.id != e.ID {
		return fmt.Errorf("enforcement does not own this macOS cut")
	}
	cut.once.Do(func() { close(cut.stop) })
	select {
	case <-cut.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := a.healCut(ctx, cut); err != nil {
		log.Printf("macos_bpf_release_failed enforcement=%s error=%q", e.ID, err)
		return fmt.Errorf("BPF restoration failed; retry Restore: %w", err)
	}
	if err := cut.writer.Close(); err != nil {
		log.Printf("macos_bpf_close_failed enforcement=%s error=%q", e.ID, err)
	}
	delete(a.active, e.TargetIP)
	e.ActualState = models.StateRolledBack
	log.Printf("macos_bpf_released enforcement=%s target=%s", e.ID, e.TargetIP)
	return nil
}
func (a *MacOSSideHostAdapter) ApplyRateLimit(context.Context, *models.Enforcement) error {
	return fmt.Errorf("macOS rate limiting is not implemented")
}
func (a *MacOSSideHostAdapter) RemoveRateLimit(context.Context, *models.Enforcement) error {
	return fmt.Errorf("macOS rate limiting is not implemented")
}

func (a *MacOSSideHostAdapter) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	a.closing = true
	var cuts []*macOSCut
	for _, cut := range a.active {
		cut.once.Do(func() { close(cut.stop) })
		cuts = append(cuts, cut)
	}
	a.mu.Unlock()
	var first error
	for _, cut := range cuts {
		if err := a.RemoveQuarantine(ctx, &models.Enforcement{ID: cut.id, TargetIP: cut.targetIP}); err != nil && first == nil {
			first = err
		}
	}
	return first
}
