//go:build !linux

package adapters

import (
	"context"
	"fmt"
	"net"

	"github.com/open-netcut/open-netcut/pkg/models"
)

type L2ARPAdapter struct{}

func NewL2ARPAdapter(gwIPStr, gwMACStr string, iface *net.Interface, nft *LinuxNFTablesAdapter) (*L2ARPAdapter, error) {
	return nil, fmt.Errorf("l2_arp adapter only supported on Linux")
}

func (a *L2ARPAdapter) Name() string                                              { return "l2_arp" }
func (a *L2ARPAdapter) Capabilities() []string                                    { return []string{} }
func (a *L2ARPAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name: "l2_arp", Label: "L2 ARP Cut — side-host LAN quarantine (disruptive)",
		Kind: KindLab, Effectiveness: 4,
		Capabilities: []string{},
		RecommendedWhen: "Side host on an unmanaged LAN (this box is NOT the gateway). Linux only.",
		Requires: "Linux + root + raw socket, gateway IP/MAC auto-detected.",
		Description: "ARP enforcement: poison victim and gateway caches, drop the attracted traffic. Explicit selection only.",
		Warning: "Use ONLY on networks you own. Disruptive by design.",
		LabOnly: true,
		SupportsQuarantine: true, SupportsShaping: false,
	}
}
func (a *L2ARPAdapter) IsAvailable(ctx context.Context) bool                      { return false }
func (a *L2ARPAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	return fmt.Errorf("l2_arp not supported on non-Linux")
}
func (a *L2ARPAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	return nil
}
func (a *L2ARPAdapter) ApplyRateLimit(ctx context.Context, e *models.Enforcement) error {
	return fmt.Errorf("l2_arp rate limiting not supported")
}
func (a *L2ARPAdapter) RemoveRateLimit(ctx context.Context, e *models.Enforcement) error {
	return nil
}
func (a *L2ARPAdapter) Close() {}
