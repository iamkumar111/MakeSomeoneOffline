package adapters

type MacOSProbeResult struct {
	Ready     bool     `json:"ready_for_injection"`
	Interface string   `json:"interface,omitempty"`
	LocalIP   string   `json:"local_ip,omitempty"`
	GatewayIP string   `json:"gateway_ip,omitempty"`
	TargetIP  string   `json:"target_ip,omitempty"`
	Blockers  []string `json:"blockers"`
	Note      string   `json:"note"`
}
