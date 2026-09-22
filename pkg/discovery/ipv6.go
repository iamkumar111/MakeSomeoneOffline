package discovery

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// IPv6Scanner parses IPv6 neighbor cache (NDP) and interface addresses.
type IPv6Scanner struct {
	fusionEngine *IdentityFusionEngine
}

// NewIPv6Scanner creates a scanner for IPv6 Neighbor Discovery Protocol entries.
func NewIPv6Scanner(fusion *IdentityFusionEngine) *IPv6Scanner {
	return &IPv6Scanner{
		fusionEngine: fusion,
	}
}

// ScanIPv6Neighbors runs `ip -6 neigh show` and ingests discovered IPv6-to-MAC bindings.
func (s *IPv6Scanner) ScanIPv6Neighbors(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "ip", "-6", "neigh", "show")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	now := time.Now().UTC()
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Format: 2001:db8::1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
		if len(fields) >= 5 {
			ip6 := fields[0]
			var dev string
			var mac string
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "dev" {
					dev = fields[i+1]
				}
				if fields[i] == "lladdr" {
					mac = fields[i+1]
				}
			}
			state := fields[len(fields)-1]
			if mac != "" && mac != "00:00:00:00:00:00" && state != "FAILED" {
				s.fusionEngine.IngestObservation(models.Observation{
					Timestamp: now,
					Source:    "ipv6_ndp",
					MAC:       mac,
					IP:        ip6,
					Interface: dev,
					Attributes: map[string]interface{}{
						"ip_version": 6,
						"ndp_state":  state,
					},
				})
			}
		}
	}
}
