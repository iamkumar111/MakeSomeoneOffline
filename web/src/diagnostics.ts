export type DiagnosticEntry = { time: string; kind: string; label?: string; method?: string; path?: string; status?: number; duration_ms?: number; request_id?: string; detail?: string };
const storageKey = 'open-netcut.diagnostics.v1';
const limit = 500;
let entries: DiagnosticEntry[] = [];

export function restoreDiagnostics(raw: string | null): DiagnosticEntry[] {
  try {
    const parsed = JSON.parse(raw ?? '[]');
    return Array.isArray(parsed) ? parsed.filter(e => e && typeof e.time === 'string' && typeof e.kind === 'string').slice(-limit) : [];
  } catch { return []; }
}

export function diagnosticPath(value: string): string {
  try { return new URL(value, 'http://localhost').pathname; } catch { return '/invalid-url'; }
}

export function diagnosticSnapshot() {
  return { exported_at: new Date().toISOString(), entries: entries.map(entry => ({ ...entry })) };
}

function record(kind: string, fields: Omit<DiagnosticEntry, 'time' | 'kind'> = {}) {
  entries = [...entries, { time: new Date().toISOString(), kind, ...fields }].slice(-limit);
  try { localStorage.setItem(storageKey, JSON.stringify(entries)); } catch { /* memory export still works */ }
}

function reportFailure(message: string) {
  window.dispatchEvent(new CustomEvent('netcut-diagnostic-error', { detail: message }));
}

export function installDiagnostics() {
  try { entries = restoreDiagnostics(localStorage.getItem(storageKey)); } catch { entries = []; }
  record('page_loaded', { detail: navigator.platform });
  document.addEventListener('click', event => {
    const button = event.target instanceof Element ? event.target.closest('button') : null;
    if (button) record('button_click', { label: (button.getAttribute('aria-label') || button.textContent || 'button').trim().slice(0, 80) });
  }, true);
  window.addEventListener('error', event => {
    record('javascript_error', { path: diagnosticPath(event.filename), detail: `line ${event.lineno}:${event.colno}` });
    reportFailure('Dashboard error. Download troubleshooting logs and check the browser Console.');
  });
  window.addEventListener('unhandledrejection', () => {
    record('unhandled_promise');
    reportFailure('An action failed unexpectedly. Download troubleshooting logs.');
  });
  const originalFetch = window.fetch.bind(window);
  const loadedPaths = new Set<string>();
  window.fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input), window.location.href);
    // Do not attach credentials or record unrelated third-party requests.
    if (url.origin !== window.location.origin || !url.pathname.startsWith('/api/')) return originalFetch(input, init);
    const path = diagnosticPath(url.href);
    const method = init?.method || (input instanceof Request ? input.method : 'GET');
    const controller = new AbortController();
    const callerSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    const abort = () => controller.abort();
    if (callerSignal?.aborted) abort();
    else callerSignal?.addEventListener('abort', abort, { once: true });
    let timedOut = false;
    const started = performance.now();
    const logSuccess = method.toUpperCase() !== 'GET' || !loadedPaths.has(path);
    if (logSuccess) record('request_started', { method, path });
    const timer = window.setTimeout(() => { timedOut = true; controller.abort(); }, 30000);
    try {
      const response = await originalFetch(input, { ...init, signal: controller.signal });
      if (logSuccess || !response.ok) record('request_completed', { method, path, status: response.status, duration_ms: Math.round(performance.now() - started), request_id: response.headers.get('X-Request-ID') ?? undefined });
      if (response.ok) loadedPaths.add(path);
      if (!response.ok) reportFailure(`${method} ${path} failed (HTTP ${response.status}). Download troubleshooting logs.`);
      return response;
    } catch (error) {
      record(timedOut ? 'request_timeout' : 'request_failed', { method, path, duration_ms: Math.round(performance.now() - started) });
      if (!callerSignal?.aborted) reportFailure(timedOut ? 'Server did not respond within 30 seconds. Check logs before retrying; the action may still finish.' : 'Cannot reach the server. Check its terminal and download troubleshooting logs.');
      throw error;
    } finally {
      window.clearTimeout(timer);
      callerSignal?.removeEventListener('abort', abort);
    }
  };
}

export function downloadDiagnostics() {
  const blob = new Blob([JSON.stringify(diagnosticSnapshot(), null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `open-netcut-browser-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
