export type TrustState = 'unknown' | 'trusted' | 'restricted' | 'quarantined' | 'isolated';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface DeviceAddress {
  device_id: string;
  ip: string;
  mac: string;
  segment: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
}

export interface DeviceService {
  device_id: string;
  protocol: string;
  port: number;
  name: string;
  hostname: string;
  source: string;
  last_seen: string;
}

export interface DeviceAttachment {
  interface: string;
  vlan: number;
  switch_port?: string;
  ap_name?: string;
  ssid?: string;
}

export interface DeviceTraffic {
  rx_bytes: number;
  tx_bytes: number;
  rx_rate_bps: number;
  tx_rate_bps: number;
  last_updated: string;
}

export interface DeviceTrafficStats {
  device_id: string;
  primary_ip: string;
  primary_mac: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_rate_bps: number;
  tx_rate_bps: number;
  last_updated: string;
}

export interface Device {
  id: string;
  site_id: string;
  display_name: string;
  vendor: string;
  trust_state: TrustState;
  risk_score: number;
  primary_mac: string;
  primary_ip: string;
  is_online: boolean;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, any>;
  labels: Record<string, string>;
  addresses: DeviceAddress[];
  services: DeviceService[];
  attachment: DeviceAttachment;
  traffic?: DeviceTraffic;
}

export interface AlertEvidence {
  timestamp: string;
  description: string;
  details?: Record<string, any>;
}

export interface Alert {
  id: string;
  type: string;
  severity: AlertSeverity;
  confidence: number;
  device_id?: string;
  target_mac?: string;
  target_ip?: string;
  segment?: string;
  first_seen: string;
  last_seen: string;
  evidence: AlertEvidence[];
  recommended_action: string;
  automatic_action_taken?: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface Enforcement {
  id: string;
  policy_id?: string;
  device_id: string;
  target_ip: string;
  target_mac: string;
  adapter: string;
  action: string;
  rate_download?: number;
  rate_upload?: number;
  desired_state: string;
  actual_state: string;
  dry_run: boolean;
  applied_at?: string;
  expires_at?: string;
  error_message?: string;
}

export interface Stats {
  total_devices: number;
  online_devices: number;
  quarantined_devices: number;
  active_enforcements: number;
  active_alerts: number;
  critical_alerts: number;
  timestamp: string;
}

export interface TopologyNode {
  id: string;
  type: string;
  label: string;
  data: Record<string, any>;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  type: 'verified' | 'inferred';
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}
