import test from 'node:test';
import assert from 'node:assert/strict';
import { diagnosticPath, restoreDiagnostics, installDiagnostics, diagnosticSnapshot } from '../src/diagnostics.ts';

test('diagnostic URLs exclude credentials and query strings', () => {
  assert.equal(diagnosticPath('https://user:password@example.com/api/v1/devices?token=secret#fragment'), '/api/v1/devices');
});

test('button clicks and swallowed HTTP/network failures are retained and reported', async () => {
  const names = ['window', 'document', 'localStorage', 'Element'];
  const original = new Map(names.map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const listeners = new Map();
  const stored = new Map();
  const events = [];
  let mode = 'ok';
  let timers = 0;
  let timerCallback;
  const windowMock = {
    location: { href: 'http://localhost:8080/', origin: 'http://localhost:8080' },
    addEventListener: (name, fn) => listeners.set(name, fn),
    dispatchEvent: event => { events.push(event.detail); return true; },
    setTimeout: callback => { timerCallback = callback; timers++; return 1; },
    clearTimeout: () => { timers--; },
    fetch: async (_input, init) => {
      assert.equal(init.signal.aborted, false);
      if (mode === 'offline') throw new TypeError('network failure');
      if (mode === 'hang') return new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true }));
      return new Response('{}', { status: mode === 'failed' ? 500 : 200, headers: { 'X-Request-ID': 'server-id' } });
    },
  };
  class ButtonTarget {
    closest() { return { getAttribute: () => null, textContent: 'Restore' }; }
  }
  try {
    Object.defineProperties(globalThis, {
      window: { configurable: true, value: windowMock },
      document: { configurable: true, value: { addEventListener: (name, fn) => listeners.set(name, fn) } },
      localStorage: { configurable: true, value: { getItem: key => stored.get(key) ?? null, setItem: (key, value) => stored.set(key, value) } },
      Element: { configurable: true, value: ButtonTarget },
    });
    installDiagnostics();
    listeners.get('click')({ target: new ButtonTarget() });
    await windowMock.fetch('/api/v1/devices');
    await windowMock.fetch('/api/v1/devices');
    mode = 'failed';
    await windowMock.fetch('/api/v1/devices/test/quarantine?token=secret', { method: 'DELETE', headers: { Authorization: 'Bearer secret' } });
    mode = 'offline';
    await assert.rejects(windowMock.fetch('/api/v1/stats'));
    mode = 'hang';
    const pending = windowMock.fetch('/api/v1/stats');
    timerCallback();
    await assert.rejects(pending);
    const snapshot = diagnosticSnapshot();
    assert.equal(snapshot.entries.filter(e => e.kind === 'button_click').length, 1);
    assert.equal(snapshot.entries.filter(e => e.kind === 'request_completed' && e.path === '/api/v1/devices').length, 1);
    assert.ok(snapshot.entries.some(e => e.status === 500 && e.request_id === 'server-id'));
    assert.ok(snapshot.entries.some(e => e.kind === 'request_failed'));
    assert.ok(snapshot.entries.some(e => e.kind === 'request_timeout'));
    assert.equal(events.length, 3);
    assert.equal(timers, 0);
    assert.ok(!JSON.stringify(snapshot).includes('secret'));
    assert.ok([...stored.values()].some(raw => raw.includes('button_click')));
  } finally {
    for (const name of names) { const desc = original.get(name); if (desc) Object.defineProperty(globalThis, name, desc); else delete globalThis[name]; }
  }
});
test('old diagnostics survive reload; corrupt history does not break startup', () => {
  const history = Array.from({ length: 600 }, (_, i) => ({ time: String(i), kind: 'button_click' }));
  const restored = restoreDiagnostics(JSON.stringify(history));
  assert.equal(restored.length, 500);
  assert.equal(restored[0].time, '100');
  assert.deepEqual(restoreDiagnostics('{broken'), []);
  assert.deepEqual(restoreDiagnostics('{}'), []);
  assert.deepEqual(restoreDiagnostics('[null,{"bad":true}]'), []);
});
