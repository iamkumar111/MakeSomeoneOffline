import test from 'node:test';
import assert from 'node:assert/strict';
import { liveQuarantines, quarantineDevices } from '../src/quarantine.ts';

test('live cuts exclude previews, shaping, failed and removed records', () => {
  const base = { device_id: 'device1', action: 'quarantine', actual_state: 'applied', dry_run: false };
  const live = liveQuarantines([base, { ...base, dry_run: true }, { ...base, action: 'rate_limit' }, { ...base, actual_state: 'failed' }, { ...base, actual_state: 'rolled_back' }]);
  assert.deepEqual(live, [base]);
});

test('an applied cut makes the device visible in the quarantine filter without a trust label', () => {
  const device = { id: 'device1', trust_state: 'trusted' };
  const live = [{ device_id: 'device1', action: 'quarantine', actual_state: 'applied', dry_run: false }];
  const view = quarantineDevices([device], liveQuarantines(live));
  assert.equal(view.filter(d => d.trust_state === 'quarantined').length, 1);
  assert.equal(device.trust_state, 'trusted');
  assert.equal(quarantineDevices([device], [])[0].trust_state, 'trusted');
});

test('release clears a stale quarantine badge and duplicate records do not duplicate devices', () => {
  const devices = [{ id: 'device1', trust_state: 'quarantined' }];
  assert.equal(quarantineDevices(devices, [])[0].trust_state, 'unknown');
  const record = { device_id: 'device1', action: 'quarantine', actual_state: 'applied', dry_run: false };
  assert.equal(quarantineDevices(devices, [record, record]).length, 1);
  assert.equal(new Set(liveQuarantines([record, record]).map(e => e.device_id)).size, 1);
});
