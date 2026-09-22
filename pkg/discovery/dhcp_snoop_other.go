//go:build !linux

package discovery

import (
	"context"
)

// DHCPSnooper is a no-op on non-Linux (no AF_PACKET).
type DHCPSnooper struct {
	fusionEngine *IdentityFusionEngine
}

// NewDHCPSnooper creates the passive DHCP listener (unsupported here).
func NewDHCPSnooper(fusion *IdentityFusionEngine) *DHCPSnooper {
	return &DHCPSnooper{fusionEngine: fusion}
}

// Start does nothing on non-Linux.
func (s *DHCPSnooper) Start(ctx context.Context) {}

// Stop does nothing on non-Linux.
func (s *DHCPSnooper) Stop() {}
