package models

import (
	"time"
)

// TrustState defines the authorization status of a device.
type TrustState string

const (
	TrustStateUnknown     TrustState = "unknown"
	TrustStateTrusted     TrustState = "trusted"
	TrustStateRestricted  TrustState = "restricted"
	TrustStateQuarantined TrustState = "quarantined"
	TrustStateIsolated    TrustState = "isolated"
)

// AlertSeverity defines the security severity level.
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityHigh     AlertSeverity = "high"
	SeverityMedium   AlertSeverity = "medium"
	SeverityLow      AlertSeverity = "low"
	SeverityInfo     AlertSeverity = "info"
)

// AlertType categorizes the threat or anomaly.
type AlertType string

const (
	AlertGatewayImpersonation AlertType = "gateway_impersonation"
	AlertARPSpoofing          AlertType = "arp_spoofing"
	AlertRogueDHCP            AlertType = "rogue_dhcp"
	AlertDuplicateIP          AlertType = "duplicate_ip"
	AlertUnknownDevice        AlertType = "unknown_device"
	AlertBandwidthAnomaly     AlertType = "bandwidth_anomaly"
	AlertPortScanDetected     AlertType = "port_scan_detected"
	AlertRogueIPv6RA          AlertType = "rogue_ipv6_ra"
)

// Device represents an endpoint on the network identified across multiple protocols.
type Device struct {
	ID          string                 `json:"id"`
	SiteID      string                 `json:"site_id"`
	DisplayName string                 `json:"display_name"`
	Vendor      string                 `json:"vendor"`
	TrustState  TrustState             `json:"trust_state"`
	RiskScore   int                    `json:"risk_score"` // 0 to 100
	PrimaryMAC  string                 `json:"primary_mac"`
	PrimaryIP   string                 `json:"primary_ip"`
	IsOnline    bool                   `json:"is_online"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Metadata    map[string]interface{} `json:"metadata"`
	Labels      map[string]string      `json:"labels"`
	Addresses   []DeviceAddress        `json:"addresses"`
	Services    []DeviceService        `json:"services"`
	Attachment  DeviceAttachment       `json:"attachment"`
	Traffic     DeviceTraffic          `json:"traffic"`
}

// DeviceAddress records an observed L2/L3 binding with source attribution.
type DeviceAddress struct {
	DeviceID   string    `json:"device_id"`
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	Segment    string    `json:"segment"`
	Source     string    `json:"source"` // "arp", "dhcp", "mdns", "router_api", "manual"
	Confidence float64   `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// DeviceService represents an advertised or discovered service (mDNS, SSDP, open port).
type DeviceService struct {
	DeviceID string    `json:"device_id"`
	Protocol string    `json:"protocol"` // "tcp", "udp"
	Port     int       `json:"port"`
	Name     string    `json:"name"`     // e.g. "_airplay._tcp", "_http._tcp"
	Hostname string    `json:"hostname"`
	Source   string    `json:"source"`
	LastSeen time.Time `json:"last_seen"`
}

// DeviceAttachment maps the physical or logical network location of the device.
type DeviceAttachment struct {
	Interface  string `json:"interface"`
	VLAN       int    `json:"vlan"`
	SwitchPort string `json:"switch_port,omitempty"`
	APName     string `json:"ap_name,omitempty"`
	SSID       string `json:"ssid,omitempty"`
}

// DeviceTraffic holds real-time aggregated metrics.
type DeviceTraffic struct {
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxPackets   uint64    `json:"rx_packets"`
	TxPackets   uint64    `json:"tx_packets"`
	RxRateBps   float64   `json:"rx_rate_bps"`
	TxRateBps   float64   `json:"tx_rate_bps"`
	LastUpdated time.Time `json:"last_updated"`
}

// Observation is a raw sensor signal before identity fusion.
type Observation struct {
	Timestamp  time.Time              `json:"timestamp"`
	Source     string                 `json:"source"` // "arp", "dhcp", "mdns", "ssdp", "router"
	MAC        string                 `json:"mac"`
	IP         string                 `json:"ip,omitempty"`
	Hostname   string                 `json:"hostname,omitempty"`
	Vendor     string                 `json:"vendor,omitempty"`
	Interface  string                 `json:"interface,omitempty"`
	VLAN       int                    `json:"vlan,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// AlertEvidence provides verifiable proof for why an alert was triggered.
type AlertEvidence struct {
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Alert represents a security or operational event requiring attention.
type Alert struct {
	ID                   string          `json:"id"`
	Type                 AlertType       `json:"type"`
	Severity             AlertSeverity   `json:"severity"`
	Confidence           float64         `json:"confidence"` // 0.0 - 1.0
	DeviceID             string          `json:"device_id,omitempty"`
	TargetMAC            string          `json:"target_mac,omitempty"`
	TargetIP             string          `json:"target_ip,omitempty"`
	Segment              string          `json:"segment,omitempty"`
	FirstSeen            time.Time       `json:"first_seen"`
	LastSeen             time.Time       `json:"last_seen"`
	Evidence             []AlertEvidence `json:"evidence"`
	RecommendedAction    string          `json:"recommended_action"`
	AutomaticActionTaken string          `json:"automatic_action_taken,omitempty"`
	Acknowledged         bool            `json:"acknowledged"`
	AcknowledgedBy       string          `json:"acknowledged_by,omitempty"`
	AcknowledgedAt       *time.Time      `json:"acknowledged_at,omitempty"`
}

// PolicyActionType specifies the enforcement action.
type PolicyActionType string

const (
	ActionQuarantine PolicyActionType = "quarantine"
	ActionRateLimit  PolicyActionType = "rate_limit"
	ActionIsolate    PolicyActionType = "isolate"
	ActionAlertOnly  PolicyActionType = "alert_only"
	ActionAllow      PolicyActionType = "allow"
)

// PolicySelector defines criteria for devices to match.
type PolicySelector struct {
	DeviceID     string     `json:"device_id,omitempty"`
	MAC          string     `json:"mac,omitempty"`
	IP           string     `json:"ip,omitempty"`
	Segment      string     `json:"segment,omitempty"`
	TrustState   TrustState `json:"trust_state,omitempty"`
	MinRiskScore int        `json:"min_risk_score,omitempty"`
}

// PolicyAction describes what enforcement to take on matching devices.
type PolicyAction struct {
	Type        PolicyActionType `json:"type"`
	DownloadBps uint64           `json:"download_bps,omitempty"` // for rate limiting
	UploadBps   uint64           `json:"upload_bps,omitempty"`
	TargetVLAN  int              `json:"target_vlan,omitempty"`
}

// Policy defines an automated or manual network control rule.
type Policy struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	Priority    int            `json:"priority"`
	Selector    PolicySelector `json:"selector"`
	Action      PolicyAction   `json:"action"`
	TTL         time.Duration  `json:"ttl,omitempty"` // 0 = indefinite
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// EnforcementState tracks the lifecycle of an applied network rule.
type EnforcementState string

const (
	StatePending    EnforcementState = "pending"
	StateApplied    EnforcementState = "applied"
	StateFailed     EnforcementState = "failed"
	StateRolledBack EnforcementState = "rolled_back"
)

// Enforcement record for audit and desired-state management.
type Enforcement struct {
	ID           string           `json:"id"`
	PolicyID     string           `json:"policy_id,omitempty"`
	DeviceID     string           `json:"device_id"`
	TargetIP     string           `json:"target_ip"`
	TargetMAC    string           `json:"target_mac"`
	TargetVLAN   int              `json:"target_vlan,omitempty"` // VLAN-based quarantine / move
	Adapter      string           `json:"adapter"` // "linux_nftables", "linux_tc", "l2_arp", "mock_simulator"
	Action       PolicyActionType `json:"action"`
	RateDownload uint64           `json:"rate_download,omitempty"`
	RateUpload   uint64           `json:"rate_upload,omitempty"`
	DesiredState EnforcementState `json:"desired_state"`
	ActualState  EnforcementState `json:"actual_state"`
	DryRun       bool             `json:"dry_run"`
	AppliedAt    *time.Time       `json:"applied_at,omitempty"`
	ExpiresAt    *time.Time       `json:"expires_at,omitempty"`
	ErrorMessage string           `json:"error_message,omitempty"`
}

// Allowlist protects critical management infrastructure from accidental quarantine.
type Allowlist struct {
	GatewayIPs     []string `json:"gateway_ips"`
	GatewayMACs    []string `json:"gateway_macs"`
	DNSIPs         []string `json:"dns_ips"`
	AdminIPs       []string `json:"admin_ips"`
	ControllerIPs  []string `json:"controller_ips"`
	ManagementVLAN int      `json:"management_vlan"`
}

// AuditLog captures changes for compliance and safety.
type AuditLog struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"` // username, API token, or "system_policy"
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"` // "device", "policy", "enforcement"
	TargetID   string    `json:"target_id"`
	Details    string    `json:"details"`
	Status     string    `json:"status"` // "success", "failed"
}
