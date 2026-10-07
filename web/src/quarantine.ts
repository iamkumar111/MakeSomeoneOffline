import type { Device } from './types';

export interface QuarantineEnforcement {
  device_id: string;
  action: string;
  actual_state: string;
  dry_run: boolean;
  expires_at?: string;
}

export function liveQuarantines<T extends QuarantineEnforcement>(enforcements: T[]): T[] {
  return enforcements.filter(e => e.action === 'quarantine' && e.actual_state === 'applied' && !e.dry_run);
}

// Trust is an operator label; the active enforcement list owns cut status.
export function quarantineDevices(devices: Device[], live: QuarantineEnforcement[]): Device[] {
  const ids = new Set(live.map(e => e.device_id));
  return devices.map(d => ({ ...d, trust_state: ids.has(d.id) ? 'quarantined' : d.trust_state === 'quarantined' ? 'unknown' : d.trust_state }));
}
