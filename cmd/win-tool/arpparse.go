package main

import (
	"github.com/open-netcut/open-netcut/pkg/discovery"
)

// ArpNeighbor is one parsed IPv4 neighbor entry.
type ArpNeighbor struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Type       string `json:"type"`
}

// ParseWindowsArp parses `arp -a` output using the backend discovery parser.
func ParseWindowsArp(output string) []ArpNeighbor {
	parsed := discovery.ParseArpTable(output)
	neighbors := make([]ArpNeighbor, 0, len(parsed))
	for _, n := range parsed {
		neighbors = append(neighbors, ArpNeighbor{
			IPAddress:  n.IPAddress,
			MACAddress: n.MACAddress,
			Type:       n.Type,
		})
	}
	return neighbors
}
