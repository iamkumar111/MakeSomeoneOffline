import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  Wifi,
  Activity,
  AlertTriangle,
  CheckCircle,
  Lock,
  Unlock,
  Clock,
  Gauge,
  Sliders,
  FileText,
  RefreshCw,
  Search,
  ArrowDownCircle,
  ArrowUpCircle,
  SlidersHorizontal,
  Camera,
  Video
} from 'lucide-react';
import { Device, Alert, Stats, DeviceTrafficStats } from './types';

// Two-click inline confirm: first click arms (red, 5s), second executes.
// Replaces blocking native confirm() dialogs.
function ConfirmButton({ title, className, style, children, confirmLabel, onConfirm }: {
  title?: string; className?: string; style?: React.CSSProperties; children: React.ReactNode;
  confirmLabel?: string; onConfirm: () => void | Promise<void>;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 5000);
    return () => clearTimeout(t);
  }, [armed]);
  if (!armed) {
    return <button className={className} style={style} title={title} onClick={() => setArmed(true)}>{children}</button>;
  }
  return <button className={className} style={{ ...style, backgroundColor: 'var(--accent-red)', color: '#fff' }} onClick={async () => { setArmed(false); await onConfirm(); }}>{confirmLabel ?? 'Click again to confirm'}</button>;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'devices' | 'traffic' | 'alerts' | 'audit' | 'policies' | 'quarantine' | 'cameras'>('dashboard');
  const [stats, setStats] = useState<Stats | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [trafficStats, setTrafficStats] = useState<DeviceTrafficStats[]>([]);
  const [trafficTotals, setTrafficTotals] = useState<{total_rate_bps:number;total_rx_rate_bps:number;total_tx_rate_bps:number}|null>(null);
  const [trafficSource, setTrafficSource] = useState<string>('');
  const [trafficPerIP, setTrafficPerIP] = useState<boolean>(true);
  const [gatewayTotals, setGatewayTotals] = useState<{rx_bytes:number;tx_bytes:number;rx_rate_bps:number;tx_rate_bps:number}|null>(null);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [enforcements, setEnforcements] = useState<any[]>([]);
  // Ranked adapter guidance from GET /integrations?action=...
  type RankedAdapter = { info: { name: string; label: string; kind: string; effectiveness_1_5: number; capabilities: string[]; recommended_when: string; requires: string; description: string; warning?: string; lab_only?: boolean; test_only?: boolean; supports_quarantine: boolean; supports_shaping: boolean }; available: boolean; supports_action: boolean; recommended: boolean; reason: string };
  const [rankedQuarantine, setRankedQuarantine] = useState<RankedAdapter[]>([]);
  const [rankedShaping, setRankedShaping] = useState<RankedAdapter[]>([]);
  const [bestQuarantine, setBestQuarantine] = useState<string>('');
  const [bestShaping, setBestShaping] = useState<string>('');
  const [deviceDetail, setDeviceDetail] = useState<any | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [showQuarantineModal, setShowQuarantineModal] = useState<boolean>(false);
  const [showRateLimitModal, setShowRateLimitModal] = useState<boolean>(false);
  const [selectedAdapter, setSelectedAdapter] = useState<string>('mock_simulator');
  const [quarantineTTL, setQuarantineTTL] = useState<number>(900); // 15 mins
  const [dryRun, setDryRun] = useState<boolean>(false);
  const [rateDown, setRateDown] = useState<number>(2000000); // 2 Mbps
  const [rateUp, setRateUp] = useState<number>(1000000); // 1 Mbps
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [lastSeq, setLastSeq] = useState<number>(0);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionUndo, setActionUndo] = useState<(() => void) | null>(null);
  const showToast = (msg: string, undo?: () => void, ms = 4000) => {
    setActionMessage(msg);
    setActionUndo(() => undo ?? null);
    setTimeout(() => { setActionMessage(null); setActionUndo(null); }, ms);
  };
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [loadingMap, setLoadingMap] = useState<Record<string, boolean>>({});
  const isLoading = Object.values(loadingMap).some(Boolean);

  const notifyError = (msg: string) => {
    setErrorMessage(msg);
    setTimeout(() => setErrorMessage(null), 6000);
  };

  const trackLoading = async <T,>(key: string, fn: () => Promise<T>): Promise<T | null> => {
    setLoadingMap(m => ({ ...m, [key]: true }));
    try {
      return await fn();
    } catch (e) {
      setErrorMessage(`Couldn't load ${key} — is the server running?`);
      setTimeout(() => setErrorMessage(null), 6000);
      return null;
    } finally {
      setLoadingMap(m => ({ ...m, [key]: false }));
    }
  };

  // Close the topmost open modal on Escape.
  const closeAllModals = () => {
    setShowQuarantineModal(false);
    setShowRateLimitModal(false);
    setShowRenameModal(false);
    setShowFreezeModal(false);
    setDeviceDetail(null);
  };
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') closeAllModals(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'offline' | 'quarantined'>('all');
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [lastRefreshAt, setLastRefreshAt] = useState<number>(Date.now());
  const wsConnectedRef = React.useRef<boolean>(false);

  const refreshData = async () => {
    await trackLoading('overview', async () => {
      const [resStats, resDevs, resAlerts] = await Promise.all([
        fetch('/api/v1/stats').then(r => r.json()),
        fetch('/api/v1/devices').then(r => r.json()),
        fetch('/api/v1/alerts').then(r => r.json())
      ]);
      setStats(resStats);
      // Stable order: backend already sorts by IP; keep sort client-side too
      // so rows never jump between refreshes.
      const sorted = Array.isArray(resDevs) ? [...resDevs].sort((a, b) => (a.primary_ip || '').localeCompare(b.primary_ip || '') || (a.primary_mac || '').localeCompare(b.primary_mac || '')) : [];
      setDevices(sorted);
      setAlerts(resAlerts);
      setLastRefreshAt(Date.now());
      // Keep modal selection pinned to the same device across refreshes.
      setSelectedDevice((cur) => {
        if (!cur) return cur;
        const fresh = sorted.find((d: Device) => d.id === cur.id);
        return (fresh as Device) ?? cur;
      });
    });
  };

  const fetchTraffic = async () => {
    await trackLoading('traffic', async () => {
      const res = await fetch('/api/v1/traffic').then(r => r.json());
      // Backend returns {top_talkers, total_rate_bps,...}; accept legacy array too.
      if (Array.isArray(res)) {
        setTrafficStats(res);
        setTrafficTotals(null);
        setTrafficSource('');
        setTrafficPerIP(true);
        setGatewayTotals(null);
      } else {
        setTrafficStats(res.top_talkers ?? []);
        setTrafficTotals({total_rate_bps: res.total_rate_bps ?? 0, total_rx_rate_bps: res.total_rx_rate_bps ?? 0, total_tx_rate_bps: res.total_tx_rate_bps ?? 0});
        setTrafficSource(res.source ?? '');
        setTrafficPerIP(res.per_ip_available !== false);
        setGatewayTotals(res.gateway_totals ?? null);
      }
    });
  };

  const fetchAudit = async () => {
    await trackLoading('audit', async () => {
      const res = await fetch('/api/v1/audit').then(r => r.json());
      setAuditLogs(res);
    });
  };

  const fetchPolicies = async () => {
    await trackLoading('policies', async () => {
      const [pols, enfs] = await Promise.all([
        fetch('/api/v1/policies').then(r => r.json()),
        fetch('/api/v1/enforcements').then(r => r.json()),
      ]);
      setPolicies(Array.isArray(pols) ? pols : []);
      setEnforcements(Array.isArray(enfs) ? enfs : []);
    });
  };

  const [schedules, setSchedules] = useState<any[]>([]);
  const [polName, setPolName] = useState<string>('');
  const [polTrust, setPolTrust] = useState<string>('');
  const [polRisk, setPolRisk] = useState<string>('');
  const [polMac, setPolMac] = useState<string>('');
  const [polAction, setPolAction] = useState<string>('quarantine');
  const [polReason, setPolReason] = useState<string>('');
  const [polTtl, setPolTtl] = useState<string>('15');
  const [schedDev, setSchedDev] = useState<string>('');
  const [schedStart, setSchedStart] = useState<string>('22:00');
  const [schedEnd, setSchedEnd] = useState<string>('07:00');
  const [schedAction, setSchedAction] = useState<string>('quarantine');
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [whName, setWhName] = useState<string>('');
  const [whUrl, setWhUrl] = useState<string>('');
  const [whSev, setWhSev] = useState<string>('high');
  const [autoRemediation, setAutoRemediation] = useState<boolean>(false);
  const [allowlist, setAllowlist] = useState<any>(null);
  const [allowDraft, setAllowDraft] = useState<Record<string, string>>({});
  const [allowVlan, setAllowVlan] = useState<string>('0');
  const [freezeActive, setFreezeActive] = useState<boolean>(false);
  const [freezeInfo, setFreezeInfo] = useState<any>(null);

  const fetchFreezeStatus = async () => {
    try {
      const res = await fetch('/api/v1/freeze').then(r => r.json());
      setFreezeInfo(res);
      const active = res && res.active === true;
      setFreezeActive(prev => (prev === active ? prev : active));
    } catch (e) {
      console.error('Failed to load freeze status:', e);
    }
  };

  const fetchAllowlist = async () => {
    try {
      const res = await fetch('/api/v1/allowlist').then(r => r.json());
      setAllowlist(res);
      const draft: Record<string, string> = {};
      for (const k of ['gateway_ips', 'gateway_macs', 'dns_ips', 'admin_ips', 'controller_ips']) {
        draft[k] = (res?.[k] || []).join(', ');
      }
      setAllowDraft(draft);
      setAllowVlan(String(res?.management_vlan ?? 0));
    } catch (e) {
      console.error('Failed to load allowlist:', e);
    }
  };
  const [cameras, setCameras] = useState<any[]>([]);
  const [camPaths, setCamPaths] = useState<Record<string, string>>({});
  const [camManual, setCamManual] = useState<Record<string, string>>({});
  const [camTick, setCamTick] = useState<number>(0);
  const [camAuto, setCamAuto] = useState<boolean>(true);

  const fetchCameras = async () => {
    try {
      const res = await fetch('/api/v1/cameras').then(r => r.json());
      setCameras(Array.isArray(res) ? res : []);
    } catch (e) {
      console.error('Failed to load cameras:', e);
    }
  };

  const fetchSchedules = async () => {
    try {
      const res = await fetch('/api/v1/schedules').then(r => r.json());
      setSchedules(Array.isArray(res) ? res : []);
    } catch (e) {
      console.error('Failed to load schedules:', e);
    }
  };

  const fetchWebhooks = async () => {
    try {
      const [hooks, rem] = await Promise.all([
        fetch('/api/v1/webhooks').then(r => r.json()),
        fetch('/api/v1/remediation').then(r => r.json()).catch(() => null),
      ]);
      setWebhooks(Array.isArray(hooks) ? hooks : []);
      if (rem && typeof rem.auto_remediation_active === 'boolean') setAutoRemediation(rem.auto_remediation_active);
    } catch (e) {
      console.error('Failed to load webhooks:', e);
    }
  };

  const fetchRankedAdapters = async () => {
    try {
      const [q, s] = await Promise.all([
        fetch('/api/v1/integrations?action=quarantine').then(r => r.json()),
        fetch('/api/v1/integrations?action=rate_limit').then(r => r.json()),
      ]);
      const qList: RankedAdapter[] = q.adapters ?? [];
      const sList: RankedAdapter[] = s.adapters ?? [];
      setRankedQuarantine(qList);
      setRankedShaping(sList);
      const qb = q.best || '';
      const sb = s.best || '';
      setBestQuarantine(qb);
      setBestShaping(sb);
      // Preselect the recommended adapter unless user already picked a valid one.
      if (qb) setSelectedAdapter((cur) => (cur === 'mock_simulator' || !qList.some((x) => x.info.name === cur && x.available)) ? qb : cur);
    } catch (e) {
      console.error('Failed to load ranked adapters:', e);
    }
  };

  const fetchDeviceDetail = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/devices/${id}?enriched=true`).then(r => r.json());
      setDeviceDetail(res);
    } catch (e) {
      console.error('Failed to load device detail:', e);
    }
  };

  useEffect(() => {
    refreshData();
    // Slow fallback poll (15s). Skipped while WS live updates are connected —
    // previously 3s polling + per-event refetch caused the 1s flicker.
    const interval = setInterval(() => {
      if (!autoRefresh) return;
      if (wsConnectedRef.current) return;
      refreshData();
      if (activeTab === 'traffic') fetchTraffic();
    }, 15000);
    return () => clearInterval(interval);
  }, [activeTab, autoRefresh]);

  useEffect(() => {
    if (activeTab === 'audit') { fetchAudit(); fetchAllowlist(); }
    if (activeTab === 'traffic') fetchTraffic();
    if (activeTab === 'policies' || activeTab === 'quarantine') { fetchPolicies(); fetchSchedules(); fetchFreezeStatus(); }
    if (activeTab === 'devices') fetchFreezeStatus();
    if (activeTab === 'alerts') fetchWebhooks();
    if (activeTab === 'cameras') fetchCameras();
  }, [activeTab]);

  // Camera stills auto-refresh (5s) while the tab is open.
  useEffect(() => {
    if (activeTab !== 'cameras' || !camAuto) return;
    const t = setInterval(() => setCamTick(v => v + 1), 5000);
    return () => clearInterval(t);
  }, [activeTab, camAuto]);

  // Quarantine countdown ticker (1s) + enforcement refresh while visible.
  // Runs on Quarantine, Devices and Dashboard tabs so per-device timers tick
  // right on the inventory rows and stat cards.
  const [nowTs, setNowTs] = useState<number>(Date.now());
  useEffect(() => {
    if (activeTab !== 'quarantine' && activeTab !== 'devices' && activeTab !== 'dashboard') return;
    fetchPolicies();
    const t = setInterval(() => {
      setNowTs(Date.now());
      fetchPolicies();
    }, 5000);
    const fast = setInterval(() => setNowTs(Date.now()), 1000);
    return () => { clearInterval(t); clearInterval(fast); };
  }, [activeTab]);

  // Active quarantine enforcement (if any) for a device, for inline timers.
  const enforcementFor = (deviceId: string): any | null => {
    for (const e of enforcements) {
      if (e.device_id === deviceId && e.action === 'quarantine' && e.actual_state === 'applied') return e;
    }
    return null;
  };

  // mm:ss or hh:mm:ss remaining; null/undefined => indefinite.
  const formatCountdown = (expiresAt: any, now: number): { text: string; urgent: boolean; title: string } => {
    if (!expiresAt) return { text: 'indefinite', urgent: false, title: 'No expiry — manual lift required' };
    const ms = new Date(expiresAt).getTime() - now;
    const title = new Date(expiresAt).toLocaleString();
    if (isNaN(ms)) return { text: 'indefinite', urgent: false, title };
    if (ms <= 0) return { text: 'expired — lifting…', urgent: true, title };
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const pad = (n: number) => String(n).padStart(2, '0');
    const text = h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
    return { text, urgent: ms < 60000, title };
  };

  // WebSocket Live Updates with sequence-gap refetch (WS is acceleration, REST is truth).
  // Throttled: device.updated fires often — at most one list refetch per 4s,
  // and device.updated alone only patches status instead of full reload.
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/v1/events`;
    let ws: WebSocket;
    let lastSeen = 0;
    let lastListFetch = 0;
    let pendingFetch: ReturnType<typeof setTimeout> | null = null;

    const throttledRefresh = () => {
      if (!autoRefresh) return;
      const now = Date.now();
      if (now - lastListFetch < 4000) {
        if (pendingFetch) return;
        pendingFetch = setTimeout(() => {
          pendingFetch = null;
          lastListFetch = Date.now();
          refreshData();
        }, 4000 - (now - lastListFetch));
        return;
      }
      lastListFetch = now;
      refreshData();
    };

    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => { setWsConnected(true); wsConnectedRef.current = true; };
      ws.onclose = () => { setWsConnected(false); wsConnectedRef.current = false; };
      ws.onerror = () => { setWsConnected(false); wsConnectedRef.current = false; };
      ws.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (typeof evt.sequence === 'number') {
            // Gap detected (missed events while disconnected) -> full REST refetch.
            if (lastSeen > 0 && evt.sequence > lastSeen + 1) {
              refreshData();
              if (activeTab === 'traffic') fetchTraffic();
            }
            lastSeen = evt.sequence;
            setLastSeq(evt.sequence);
          }
          // High-frequency device.updated: throttled list sync only.
          // Structural events refetch immediately.
          if (evt.type === 'traffic.sample' && activeTab === 'traffic') fetchTraffic();
          else if (evt.type === 'device.updated') throttledRefresh();
          else throttledRefresh();
        } catch (err) {
          // ignore parsing error
        }
      };
    } catch (e) {
      setWsConnected(false);
      wsConnectedRef.current = false;
    }

    return () => {
      if (pendingFetch) clearTimeout(pendingFetch);
      if (ws) ws.close();
    };
  }, [activeTab, autoRefresh]);

  // Column sorting: click any header to sort. IP sorts numerically
  // (192.168.1.20 < 192.168.1.100), not lexicographically.
  type DeviceSortKey = 'status' | 'name' | 'ip' | 'mac' | 'vendor' | 'risk' | 'trust';
  type TrafficSortKey = 'ip' | 'rx' | 'tx' | 'rxRate' | 'txRate' | 'packets';
  const [deviceSortKey, setDeviceSortKey] = useState<DeviceSortKey>('ip');
  const [deviceSortDir, setDeviceSortDir] = useState<'asc' | 'desc'>('asc');
  const [trafficSortKey, setTrafficSortKey] = useState<TrafficSortKey>('rxRate');
  const [trafficSortDir, setTrafficSortDir] = useState<'asc' | 'desc'>('desc');

  const compareIP = (a: string, b: string): number => {
    const pa = (a || '').split('.').map((x) => parseInt(x, 10));
    const pb = (b || '').split('.').map((x) => parseInt(x, 10));
    if (pa.length === 4 && pb.length === 4 && pa.every((n) => !isNaN(n)) && pb.every((n) => !isNaN(n))) {
      for (let i = 0; i < 4; i++) {
        if (pa[i] !== pb[i]) return pa[i] - pb[i];
      }
      return 0;
    }
    return (a || '').localeCompare(b || '');
  };

  const toggleDeviceSort = (key: DeviceSortKey) => {
    if (deviceSortKey === key) setDeviceSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setDeviceSortKey(key); setDeviceSortDir('asc'); }
  };

  const toggleTrafficSort = (key: TrafficSortKey) => {
    if (trafficSortKey === key) setTrafficSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setTrafficSortKey(key); setTrafficSortDir(key === 'ip' ? 'asc' : 'desc'); }
  };

  const sortArrow = (active: boolean, dir: 'asc' | 'desc') => active ? (dir === 'asc' ? ' ▲' : ' ▼') : '';

  const filteredDevices = useMemo(() => {
    const list = devices.filter(dev => {
      if (statusFilter === 'online' && !dev.is_online) return false;
      if (statusFilter === 'offline' && dev.is_online) return false;
      if (statusFilter === 'quarantined' && dev.trust_state !== 'quarantined') return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        dev.display_name.toLowerCase().includes(q) ||
        (dev.primary_ip && dev.primary_ip.toLowerCase().includes(q)) ||
        (dev.primary_mac && dev.primary_mac.toLowerCase().includes(q)) ||
        (dev.vendor && dev.vendor.toLowerCase().includes(q))
      );
    });
    const dir = deviceSortDir === 'asc' ? 1 : -1;
    return [...list].sort((a, b) => {
      switch (deviceSortKey) {
        case 'status': return ((a.is_online ? 1 : 0) - (b.is_online ? 1 : 0)) * dir;
        case 'name': return a.display_name.localeCompare(b.display_name) * dir;
        case 'ip': return compareIP(a.primary_ip, b.primary_ip) * dir;
        case 'mac': return (a.primary_mac || '').localeCompare(b.primary_mac || '') * dir;
        case 'vendor': return (a.vendor || '').localeCompare(b.vendor || '') * dir;
        case 'risk': return (a.risk_score - b.risk_score) * dir;
        case 'trust': return (a.trust_state || '').localeCompare(b.trust_state || '') * dir;
        default: return 0;
      }
    });
  }, [devices, searchQuery, statusFilter, deviceSortKey, deviceSortDir]);

  const sortedTraffic = useMemo(() => {
    const dir = trafficSortDir === 'asc' ? 1 : -1;
    return [...trafficStats].sort((a, b) => {
      switch (trafficSortKey) {
        case 'ip': return compareIP(a.primary_ip, b.primary_ip) * dir;
        case 'rx': return (a.rx_bytes - b.rx_bytes) * dir;
        case 'tx': return (a.tx_bytes - b.tx_bytes) * dir;
        case 'rxRate': return (a.rx_rate_bps - b.rx_rate_bps) * dir;
        case 'txRate': return (a.tx_rate_bps - b.tx_rate_bps) * dir;
        case 'packets': return ((a.rx_packets + a.tx_packets) - (b.rx_packets + b.tx_packets)) * dir;
        default: return 0;
      }
    });
  }, [trafficStats, trafficSortKey, trafficSortDir]);

  const handleQuarantine = (device: Device) => {
    setSelectedDevice(device);
    setShowQuarantineModal(true);
    setBreakGlass(false);
    setBreakReason('');
    fetchAllowlist();
    fetchRankedAdapters().then(() => {
      // Preselect gateway-best quarantine after list loads.
      setSelectedAdapter((cur) => bestQuarantine && bestQuarantine !== cur ? bestQuarantine : cur);
    });
  };

  // Break-glass state lives here so the modal can show it for protected targets.
  const [breakGlass, setBreakGlass] = useState<boolean>(false);
  const [breakReason, setBreakReason] = useState<string>('');

  const isProtectedTarget = (dev: Device | null): string => {
    if (!dev || !allowlist) return '';
    const ip = (dev.primary_ip || '').trim();
    const mac = (dev.primary_mac || '').toLowerCase();
    const has = (arr: any, v: string) => Array.isArray(arr) && arr.map((x: string) => String(x).toLowerCase().trim()).includes(v.toLowerCase().trim());
    if (ip && (has(allowlist.gateway_ips, ip) || has(allowlist.dns_ips, ip) || has(allowlist.admin_ips, ip) || has(allowlist.controller_ips, ip))) return 'Protected infrastructure IP — cutting it affects the whole network.';
    if (mac && has(allowlist.gateway_macs, mac)) return 'Protected gateway MAC — cutting it affects the whole network.';
    return '';
  };

  const handleRateLimit = (device: Device) => {
    setSelectedDevice(device);
    setShowRateLimitModal(true);
    fetchRankedAdapters().then(() => {
      setSelectedAdapter((cur) => bestShaping && bestShaping !== cur ? bestShaping : cur);
    });
  };

  const [showRenameModal, setShowRenameModal] = useState<boolean>(false);
  const [renameValue, setRenameValue] = useState<string>('');

  const [showFreezeModal, setShowFreezeModal] = useState<boolean>(false);
  const [freezeReason, setFreezeReason] = useState<string>('');
  const [freezeAck, setFreezeAck] = useState<boolean>(false);
  const [freezing, setFreezing] = useState<boolean>(false);
  const [includeSelf, setIncludeSelf] = useState<boolean>(false);
  const [freezeAdapter, setFreezeAdapter] = useState<string>('');
  const [whoAmI, setWhoAmI] = useState<any>(null);
  const [selfOverrideId, setSelfOverrideId] = useState<string>('');
  // Localhost access hides the operator's LAN identity (server sees 127.0.0.1
  // instead of their real device), so exclusion can't work until they either
  // open the dashboard via their LAN IP or pick their device below.
  const selfUnresolved = !whoAmI?.ip || ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(whoAmI.ip);

  const openFreezeModal = async () => {
    setFreezeReason(''); setFreezeAck(false); setIncludeSelf(false);
    setFreezeAdapter(''); setSelfOverrideId(''); setFreezeInfo(null);
    setShowFreezeModal(true);
    // Load the same ranked method list as the quarantine dialog, preselected
    // to the recommended method (user can change it before confirming).
    try {
      const q = await fetch('/api/v1/integrations?action=quarantine').then(r => r.json());
      const list = q.adapters ?? [];
      setRankedQuarantine(list);
      if (q.best) {
        setBestQuarantine(q.best);
        setFreezeAdapter(q.best);
      }
    } catch (e) {
      console.error('Failed to load ranked adapters:', e);
    }
    try {
      const res = await fetch('/api/v1/whoami').then(r => r.json());
      setWhoAmI(res);
    } catch (e) {
      setWhoAmI(null);
    }
  };

  const executeFreeze = async () => {
    if (!freezeAck || !freezeReason.trim() || freezing) return;
    setFreezing(true);
    try {
      const overrideDev = devices.find(d => d.id === selfOverrideId);
      const res = await fetch('/api/v1/freeze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adapter: freezeAdapter || bestQuarantine || 'l2_arp', ttl_seconds: 900, reason: freezeReason.trim(), dry_run: false, include_self: includeSelf, self_ip: overrideDev?.primary_ip || '', self_mac: overrideDev?.primary_mac || '' })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        notifyError(res.status === 409 && data?.status === 'already_frozen'
          ? 'Freeze is already ON. Unblock first before starting a new run.'
          : `Error: ${data?.error || res.statusText}`);
      } else if (res.status === 202 || data.status === 'freezing') {
        // Async contract: cuts land over the next seconds; watch them arrive.
        const selfNote = includeSelf ? ' (including you)' : ' (you stay online)';
        showToast(`❄ Freeze started${selfNote} — cuts landing${data.self_warning ? ' · WARNING: ' + data.self_warning : ''}`, async () => {
          await fetch('/api/v1/freeze', { method: 'DELETE' });
          fetchPolicies(); refreshData(); fetchFreezeStatus();
        }, 30000);
      } else {
        const selfNote = includeSelf ? ' (including you)' : ' (you stay online)';
        showToast(`LAN frozen: ${data.applied ?? 0} cut, ${data.skipped ?? 0} skipped, ${(data.failed ?? []).length} failed${selfNote}`, async () => {
          await fetch('/api/v1/freeze', { method: 'DELETE' });
          fetchPolicies(); refreshData(); fetchFreezeStatus();
        }, 30000);
      }
      setShowFreezeModal(false);
      fetchPolicies(); refreshData(); fetchFreezeStatus();
      // Keep refreshing while cuts land.
      setTimeout(() => { fetchPolicies(); fetchFreezeStatus(); }, 5000);
      setTimeout(() => { fetchPolicies(); fetchFreezeStatus(); }, 15000);
    } catch (err) {
      notifyError(`Request failed: ${err}`);
    } finally {
      setFreezing(false);
    }
  };

  const handleRename = (device: Device) => {
    setSelectedDevice(device);
    const cur = (device.metadata as any)?.hostname_source === 'manual'
      ? ((device.metadata as any)?.hostname || '')
      : '';
    setRenameValue(cur);
    setShowRenameModal(true);
  };

  const executeRename = async () => {
    if (!selectedDevice) return;
    const name = renameValue.trim();
    if (!name) return;
    try {
      const res = await fetch(`/api/v1/devices/${selectedDevice.id}/rename`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      if (!res.ok) {
        const text = await res.text();
        notifyError(`Error: ${text || res.statusText}`);
      } else {
        setActionMessage(`Renamed to ${name} — automatic sources cannot overwrite it`);
        setTimeout(() => setActionMessage(null), 4000);
      }
      setShowRenameModal(false);
      refreshData();
      if (deviceDetail && deviceDetail.device?.id === selectedDevice.id) fetchDeviceDetail(selectedDevice.id);
    } catch (err) {
      notifyError(`Request failed: ${err}`);
    }
  };

  const executeClearRename = async () => {
    if (!selectedDevice) return;
    await fetch(`/api/v1/devices/${selectedDevice.id}/rename`, { method: 'DELETE' });
    setShowRenameModal(false);
    refreshData();
    if (deviceDetail && deviceDetail.device?.id === selectedDevice.id) fetchDeviceDetail(selectedDevice.id);
  };

  const executeQuarantine = async () => {
    if (!selectedDevice) return;
    try {
      const res = await fetch(`/api/v1/devices/${selectedDevice.id}/quarantine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          adapter: selectedAdapter,
          ttl_seconds: quarantineTTL,
          dry_run: dryRun,
          break_glass: breakGlass,
          reason: breakReason
        })
      });
      if (!res.ok) {
        const text = await res.text();
        notifyError(`Error: ${text || res.statusText}`);
      } else {
        setActionMessage(`Quarantine applied to ${selectedDevice.display_name} via ${selectedAdapter}`);
        setTimeout(() => setActionMessage(null), 4000);
      }
      setShowQuarantineModal(false);
      refreshData();
    } catch (err) {
      notifyError(`Request failed: ${err}`);
    }
  };

  const executeLiftQuarantine = async (device: Device) => {
    try {
      const res = await fetch(`/api/v1/devices/${device.id}/quarantine`, {
        method: 'DELETE'
      });
      if (res.ok) {
        setActionMessage(`Quarantine lifted for ${device.display_name}`);
        setTimeout(() => setActionMessage(null), 4000);
        refreshData();
      }
    } catch (err) {
      notifyError(`Request failed: ${err}`);
    }
  };

  const executeRateLimit = async () => {
    if (!selectedDevice) return;
    try {
      const res = await fetch(`/api/v1/devices/${selectedDevice.id}/rate-limit`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          adapter: selectedAdapter,
          download_bps: rateDown,
          upload_bps: rateUp,
          ttl_seconds: quarantineTTL,
          dry_run: dryRun
        })
      });
      if (!res.ok) {
        const text = await res.text();
        notifyError(`Error: ${text || res.statusText}`);
      } else {
        setActionMessage(`Rate limit applied to ${selectedDevice.display_name}`);
        setTimeout(() => setActionMessage(null), 4000);
      }
      setShowRateLimitModal(false);
      refreshData();
    } catch (err) {
      notifyError(`Request failed: ${err}`);
    }
  };

  const acknowledgeAlert = async (id: string) => {
    // Optimistic: mark immediately, roll back if the server refuses.
    const prev = alerts;
    setAlerts(as => as.map(a => (a.id === id ? { ...a, acknowledged: true } : a)));
    try {
      const res = await fetch(`/api/v1/alerts/${id}/ack`, { method: 'POST' });
      if (!res.ok) {
        setAlerts(prev);
        notifyError(`Acknowledge failed: ${res.statusText}`);
        return;
      }
      refreshData();
    } catch (e) {
      setAlerts(prev);
      notifyError(`Acknowledge failed: ${e}`);
    }
  };

  const [alertSeverity, setAlertSeverity] = useState<'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'>('all');
  const [alertQuery, setAlertQuery] = useState<string>('');
  const [auditQuery, setAuditQuery] = useState<string>('');

  const filteredAlerts = useMemo(() => {
    const q = alertQuery.trim().toLowerCase();
    return alerts.filter(a => {
      if (alertSeverity !== 'all' && a.severity !== alertSeverity) return false;
      if (!q) return true;
      return (
        a.type.toLowerCase().includes(q) ||
        (a.recommended_action || '').toLowerCase().includes(q) ||
        (a.evidence || []).some(ev => (ev.description || '').toLowerCase().includes(q))
      );
    });
  }, [alerts, alertSeverity, alertQuery]);

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatBps = (bps: number): string => {
    if (!bps || bps === 0) return '0 bps';
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
    if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
    if (bps >= 1e3) return (bps / 1e3).toFixed(2) + ' Kbps';
    return bps.toFixed(0) + ' bps';
  };

  // Raw UPnP/SSDP URNs mean nothing to operators — shorten them.
  // "urn:schemas-upnp-org:device:InternetGatewayDevice:1" -> "Router IGD (UPnP)"
  const prettifyService = (name: string): string => {
    if (!name) return name;
    const urn = name.match(/^urn:[^:]+:[^:]+:([^:]+):(\d+)$/);
    if (urn) {
      const kind = urn[1].replace(/([a-z])([A-Z])/g, '$1 $2');
      return `${kind} (UPnP)`;
    }
    return name;
  };

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo-badge">
            <Shield size={22} />
          </div>
          <div>
            <div className="sidebar-title">Open-NetCut</div>
            <div className="sidebar-subtitle">Observability & Policy Platform</div>
          </div>
        </div>

        <nav className="nav-links">
          <button 
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={18} /> Dashboard
          </button>
          <button 
            className={`nav-item ${activeTab === 'devices' ? 'active' : ''}`}
            onClick={() => setActiveTab('devices')}
          >
            <Wifi size={18} /> Network Devices ({devices.length})
          </button>
          <button 
            className={`nav-item ${activeTab === 'traffic' ? 'active' : ''}`}
            onClick={() => setActiveTab('traffic')}
          >
            <Gauge size={18} /> Bandwidth & Traffic
          </button>
          <button 
            className={`nav-item ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            <ShieldAlert size={18} /> Security Alerts ({alerts.filter(a => !a.acknowledged).length})
          </button>
          <button 
            className={`nav-item ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <FileText size={18} /> Audit & Safety
          </button>
          <button
            className={`nav-item ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab('policies')}
          >
            <Sliders size={18} /> Policies ({policies.length})
          </button>
          <button
            className={`nav-item ${activeTab === 'quarantine' ? 'active' : ''}`}
            onClick={() => setActiveTab('quarantine')}
          >
            <Lock size={18} /> Quarantine ({enforcements.length})
          </button>
          <button
            className={`nav-item ${activeTab === 'cameras' ? 'active' : ''}`}
            onClick={() => setActiveTab('cameras')}
          >
            <Camera size={18} /> Cameras ({cameras.length})
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="status-indicator">
            <span className={`dot ${wsConnected ? '' : 'bg-amber-500'}`} />
            <span>{wsConnected ? 'Realtime Connected' : 'Syncing'}</span>
          </div>
          {lastSeq > 0 && <span className="font-mono text-xs">Seq: {lastSeq}</span>}
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="top-bar">
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600 }}>
            {activeTab === 'dashboard' && 'Network Operations Dashboard'}
            {activeTab === 'devices' && 'Discovered Network Inventory'}
            {activeTab === 'traffic' && 'Real-time Bandwidth Monitoring & Top Talkers'}
            {activeTab === 'alerts' && 'Security Threat Detection'}
            {activeTab === 'audit' && 'System Audit Log & Protected Infrastructure'}
            {activeTab === 'policies' && 'Policy Rules (WHEN / THEN)'}
            {activeTab === 'quarantine' && 'Quarantine & Enforcements (Desired vs Actual)'}
            {activeTab === 'cameras' && 'IP Cameras & NVRs'}
          </h2>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {actionMessage && (
              <div className="badge badge-green" style={{ padding: '0.4rem 0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                <CheckCircle size={14} /> {actionMessage}
                {actionUndo && (
                  <button className="btn btn-secondary btn-sm" style={{ height: '24px', fontSize: '0.72rem' }} onClick={() => { const f = actionUndo; setActionUndo(null); setActionMessage(null); f(); }}>Undo</button>
                )}
              </div>
            )}
            {errorMessage && (
              <div className="badge badge-red" style={{ padding: '0.4rem 0.8rem' }} title="Dismiss" onClick={() => setErrorMessage(null)}>
                <AlertTriangle size={14} /> {errorMessage}
              </div>
            )}
            {isLoading && (
              <span className="font-mono text-xs" style={{ color: '#9ca3af' }} title="Loading data from server…">
                <RefreshCw size={14} className="spin" /> syncing…
              </span>
            )}
            <span style={{ fontSize: '0.75rem', color: '#9ca3af' }} title="List no longer flickers: backend holds online state, UI syncs at most every 4s">
              Updated {Math.max(0, Math.round((Date.now() - lastRefreshAt) / 1000))}s ago {wsConnected ? '· live' : '· polling'}
            </span>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setAutoRefresh((v) => !v)}
              title={autoRefresh ? 'Pause auto-refresh to make a stable quarantine decision' : 'Resume live updates'}
            >
              {autoRefresh ? 'Pause' : 'Resume'}
            </button>
            <button className="btn btn-secondary btn-sm" onClick={refreshData}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        </header>

        <div className="content-body">
          {/* Top Stat Cards — click to jump to the relevant tab */}
          <div className="stats-grid">
            <div className="stat-card" role="button" tabIndex={0} style={{ cursor: 'pointer' }} title="View all devices"
              onClick={() => { setStatusFilter('all'); setActiveTab('devices'); }}
              onKeyDown={(e) => { if (e.key === 'Enter') { setStatusFilter('all'); setActiveTab('devices'); } }}>
              <div className="stat-icon" style={{ backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa' }}>
                <Wifi size={24} />
              </div>
              <div>
                <div className="stat-val">{stats?.online_devices ?? 0} <span style={{ fontSize: '1rem', color: '#9ca3af' }}>/ {stats?.total_devices ?? 0}</span></div>
                <div className="stat-label">Online Devices</div>
              </div>
            </div>

            <div className="stat-card" role="button" tabIndex={0} style={{ cursor: 'pointer' }} title="View quarantined devices"
              onClick={() => { setStatusFilter('quarantined'); setActiveTab('devices'); }}
              onKeyDown={(e) => { if (e.key === 'Enter') { setStatusFilter('quarantined'); setActiveTab('devices'); } }}>
              <div className="stat-icon" style={{ backgroundColor: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
                <Lock size={24} />
              </div>
              <div>
                <div className="stat-val">{stats?.quarantined_devices ?? 0}</div>
                <div className="stat-label">Quarantined / Cut</div>
                {(() => {
                  let minMs = Infinity;
                  for (const e of enforcements) {
                    if (e.action !== 'quarantine' || e.actual_state !== 'applied' || !e.expires_at) continue;
                    const ms = new Date(e.expires_at).getTime() - nowTs;
                    if (ms > 0 && ms < minMs) minMs = ms;
                  }
                  if (minMs === Infinity) return null;
                  const s = Math.floor(minMs / 1000);
                  const t = s >= 3600 ? `${Math.floor(s / 3600)}:${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}` : `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
                  return <div className="font-mono" style={{ fontSize: '0.75rem', color: '#9ca3af' }}>⏳ first release in {t}</div>;
                })()}
              </div>
            </div>

            <div className="stat-card" role="button" tabIndex={0} style={{ cursor: 'pointer' }} title="View critical alerts"
              onClick={() => { setAlertSeverity('critical'); setActiveTab('alerts'); }}
              onKeyDown={(e) => { if (e.key === 'Enter') { setAlertSeverity('critical'); setActiveTab('alerts'); } }}>
              <div className="stat-icon" style={{ backgroundColor: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24' }}>
                <ShieldAlert size={24} />
              </div>
              <div>
                <div className="stat-val">{stats?.critical_alerts ?? 0}</div>
                <div className="stat-label">Critical Alerts</div>
              </div>
            </div>

            <div className="stat-card" role="button" tabIndex={0} style={{ cursor: 'pointer' }} title="View active enforcements"
              onClick={() => setActiveTab('quarantine')}
              onKeyDown={(e) => { if (e.key === 'Enter') setActiveTab('quarantine'); }}>
              <div className="stat-icon" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}>
                <Sliders size={24} />
              </div>
              <div>
                <div className="stat-val">{stats?.active_enforcements ?? 0}</div>
                <div className="stat-label">Active Policies</div>
              </div>
            </div>
          </div>

          {/* TAB: DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div>
              {/* Critical Alerts Banner if any */}
              {alerts.filter(a => !a.acknowledged && (a.severity === 'critical' || a.severity === 'high')).length > 0 && (
                <div className="card" style={{ borderLeft: '4px solid var(--accent-red)' }}>
                  <div className="card-header">
                    <div className="card-title" style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <AlertTriangle size={20} /> Active Threats Detected
                    </div>
                  </div>
                  <div style={{ padding: '1rem 1.5rem' }}>
                    {alerts.filter(a => !a.acknowledged && (a.severity === 'critical' || a.severity === 'high')).map(a => (
                      <div key={a.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <div>
                          <div style={{ fontWeight: 600 }}>{a.type.replace('_', ' ').toUpperCase()}</div>
                          <div style={{ fontSize: '0.85rem', color: '#9ca3af' }}>{a.evidence[0]?.description}</div>
                        </div>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                          <button className="btn btn-secondary btn-sm" onClick={() => acknowledgeAlert(a.id)}>Acknowledge</button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recent Discovered Devices Overview */}
              <div className="card">
                <div className="card-header">
                  <div className="card-title">Live Discovered Endpoints</div>
                  <button className="btn btn-secondary btn-sm" onClick={() => setActiveTab('devices')}>View All</button>
                </div>
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>Status</th>
                        <th>Device Name</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Vendor (OUI)</th>
                        <th>Trust State</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {devices.slice(0, 8).map(dev => (
                        <tr key={dev.id}>
                          <td>
                            <span className={`badge ${dev.is_online ? 'badge-green' : 'badge-gray'}`}>
                              {dev.is_online ? 'Online' : 'Offline'}
                            </span>
                          </td>
                          <td style={{ fontWeight: 600 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                              <span>{dev.display_name}</span>
                              {dev.is_online && dev.metadata?.latency_ms && (
                                <span className="badge badge-gray font-mono" style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>
                                  {`${dev.metadata.latency_ms} ms`}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="font-mono">{dev.primary_ip || '—'}</td>
                          <td className="font-mono text-secondary">{dev.primary_mac || '—'}</td>
                          <td>{dev.vendor || 'Unknown'}</td>
                          <td>
                            <span className={`badge ${
                              dev.trust_state === 'quarantined' ? 'badge-red' :
                              dev.trust_state === 'trusted' ? 'badge-green' : 'badge-amber'
                            }`}>
                              {dev.trust_state}
                            </span>
                          </td>
                          <td>
                            {dev.trust_state === 'quarantined' ? (
                              <button className="btn btn-secondary btn-sm" onClick={() => executeLiftQuarantine(dev)}>
                                <Unlock size={14} /> Restore
                              </button>
                            ) : (
                              <button className="btn btn-danger btn-sm" onClick={() => handleQuarantine(dev)}>
                                <Lock size={14} /> Quarantine
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: DEVICES */}
          {activeTab === 'devices' && (
            <div className="card">
              <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div className="card-title">Device Inventory & Policy Controls ({filteredDevices.length})</div>

                {/* Filter and Search controls */}
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <div style={{ position: 'relative' }}>
                    <Search size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' }} />
                    <input 
                      type="text" 
                      placeholder="Search name, IP, MAC..." 
                      className="form-input" 
                      style={{ paddingLeft: '32px', width: '220px', height: '36px' }}
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>

                  <select 
                    className="form-select" 
                    style={{ width: '140px', height: '36px' }}
                    value={statusFilter}
                    onChange={(e: any) => setStatusFilter(e.target.value)}
                  >
                    <option value="all">All Devices</option>
                    <option value="online">Online Only</option>
                    <option value="offline">Offline Only</option>
                    <option value="quarantined">Quarantined</option>
                  </select>

                  <a 
                    href={`/api/v1/export/devices.csv`} 
                    download="open-netcut-devices.csv" 
                    className="btn btn-secondary btn-sm"
                    style={{ height: '36px', textDecoration: 'none' }}
                  >
                    <FileText size={14} /> Export CSV
                  </a>

                  <button
                    className="btn btn-sm"
                    style={{ height: '36px', backgroundColor: 'var(--accent-red)', color: '#fff' }}
                    title="Cut internet on every online device at once (LAN + WiFi, 15-min auto-heal)"
                    onClick={() => { openFreezeModal(); }}
                  >
                    ❄ Block All Internet
                  </button>
                  {freezeActive && (
                    <span className="badge badge-red" title="Freeze latch is ON — devices joining now are cut automatically">
                      ❄ FREEZE ON{typeof freezeInfo?.active_cuts === 'number' ? ` (${freezeInfo.active_cuts} cuts)` : ''}
                    </span>
                  )}
                  <ConfirmButton
                    className="btn btn-secondary btn-sm"
                    style={{ height: '36px' }}
                    title="Lift every active quarantine (including manual ones)"
                    confirmLabel="Confirm unblock all?"
                    onConfirm={async () => {
                      await fetch('/api/v1/freeze', { method: 'DELETE' });
                      fetchPolicies(); refreshData(); fetchFreezeStatus();
                    }}
                  >
                    <Unlock size={14} /> Unblock All
                  </ConfirmButton>
                </div>
              </div>

              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th onClick={() => toggleDeviceSort('status')} style={{cursor:'pointer'}} title="Sort by online status">Status{sortArrow(deviceSortKey==='status', deviceSortDir)}</th>
                      <th onClick={() => toggleDeviceSort('name')} style={{cursor:'pointer'}} title="Sort by name">Device Name{sortArrow(deviceSortKey==='name', deviceSortDir)}</th>
                      <th onClick={() => toggleDeviceSort('ip')} style={{cursor:'pointer'}} title="Sort numerically by IPv4">IPv4 Address{sortArrow(deviceSortKey==='ip', deviceSortDir)}</th>
                      <th onClick={() => toggleDeviceSort('mac')} style={{cursor:'pointer'}} title="Sort by MAC">MAC Address{sortArrow(deviceSortKey==='mac', deviceSortDir)}</th>
                      <th onClick={() => toggleDeviceSort('vendor')} style={{cursor:'pointer'}} title="Sort by vendor">Hardware Vendor{sortArrow(deviceSortKey==='vendor', deviceSortDir)}</th>
                      <th onClick={() => toggleDeviceSort('risk')} style={{cursor:'pointer'}} title="Sort by risk score">Risk Score{sortArrow(deviceSortKey==='risk', deviceSortDir)}</th>
                      <th onClick={() => toggleDeviceSort('trust')} style={{cursor:'pointer'}} title="Sort by trust state">Trust State{sortArrow(deviceSortKey==='trust', deviceSortDir)}</th>
                      <th>Enforcement Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDevices.map(dev => (
                      <tr key={dev.id}>
                        <td>
                          <span className={`badge ${dev.is_online ? 'badge-green' : 'badge-gray'}`}>
                            {dev.is_online ? 'Online' : 'Offline'}
                          </span>
                        </td>
                        <td style={{ fontWeight: 600 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <span>{dev.display_name}</span>
                            {dev.is_online && dev.metadata?.latency_ms && (
                              <span className="badge badge-gray font-mono" style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>
                                {`${dev.metadata.latency_ms} ms`}
                              </span>
                            )}
                          </div>
                          {dev.services && dev.services.length > 0 && (
                            <div style={{ fontSize: '0.75rem', color: '#9ca3af' }} title={dev.services.map(s => `${s.name} (via ${s.source || 'discovery'})`).join('\n')}>
                              Services: {dev.services.map(s => prettifyService(s.name)).join(', ')}
                            </div>
                          )}
                        </td>
                        <td className="font-mono">{dev.primary_ip || '—'}</td>
                        <td className="font-mono text-secondary">{dev.primary_mac || '—'}</td>
                        <td>{dev.vendor}</td>
                        <td>
                          <span className={`badge ${
                            dev.risk_score > 50 ? 'badge-red' :
                            dev.risk_score > 20 ? 'badge-amber' : 'badge-green'
                          }`}>
                            {dev.risk_score} / 100
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${
                            dev.trust_state === 'quarantined' ? 'badge-red' :
                            dev.trust_state === 'trusted' ? 'badge-green' : 'badge-amber'
                          }`}>
                            {dev.trust_state}
                          </span>
                          {(() => {
                            const enf = enforcementFor(dev.id);
                            if (!enf) return null;
                            const cd = formatCountdown(enf.expires_at, nowTs);
                            return (<div style={{ marginTop: '0.3rem' }} title={`Quarantine ends: ${cd.title}`}>
                              <span className={`badge font-mono ${cd.urgent ? 'badge-red' : 'badge-green'}`} style={{ fontSize: '0.7rem' }}>⏳ {cd.text}</span>
                            </div>);
                          })()}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '0.4rem' }}>
                            {dev.trust_state === 'quarantined' ? (
                              <button className="btn btn-secondary btn-sm" onClick={() => executeLiftQuarantine(dev)}>
                                <Unlock size={14} /> Lift Quarantine
                              </button>
                            ) : (
                              <button className="btn btn-danger btn-sm" onClick={() => handleQuarantine(dev)}>
                                <Lock size={14} /> Quarantine
                              </button>
                            )}
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => fetchDeviceDetail(dev.id)}
                            >
                              Details
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => handleRateLimit(dev)}
                            >
                              <Gauge size={14} /> Limit Speed
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              title={((dev.metadata as any)?.hostname_source === 'manual') ? `Named manually (${((dev.metadata as any)?.hostname) || ''}) — click to change` : 'Give this device a permanent name'}
                              onClick={() => handleRename(dev)}
                            >
                              ✏️ Rename
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: TRAFFIC & BANDWIDTH */}
          {activeTab === 'traffic' && (
            <div>
              <div className="card">
                <div className="card-header">
                  <div className="card-title">Bandwidth Consumption & Top Talkers{trafficTotals ? ` — Total ${formatBps(trafficTotals.total_rate_bps)} (↓ ${formatBps(trafficTotals.total_rx_rate_bps)} / ↑ ${formatBps(trafficTotals.total_tx_rate_bps)})` : ''}</div>
                  <button className="btn btn-secondary btn-sm" onClick={fetchTraffic}>
                    <RefreshCw size={14} /> Refresh Rates
                  </button>
                </div>
                <div style={{padding:'0.6rem 1.5rem',fontSize:'0.8rem',color: trafficPerIP ? '#9ca3af' : '#fbbf24'}}>
                  {trafficSource === 'nft-accounting' ? (
                    <>Source: <span className="font-mono">nftables per-IP counters (live)</span> — click any column to sort. No conntrack module needed.</>
                  ) : trafficSource === 'nf_conntrack' || trafficSource === 'conntrack-cmd' ? (
                    <>Source: <span className="font-mono">conntrack live counters</span> — click any column to sort.</>
                  ) : gatewayTotals && (gatewayTotals.rx_bytes + gatewayTotals.tx_bytes > 0) ? (
                    <>Per-device counters starting… nftables accounting rules install on first poll (needs root). Showing gateway interface totals meanwhile: ↓ {formatBps(gatewayTotals.rx_rate_bps)} / ↑ {formatBps(gatewayTotals.tx_rate_bps)}.</>
                  ) : (
                    <>Collecting baseline… counters appear after ~10s of gateway traffic (nftables per-IP + /proc/net/dev totals).</>
                  )}
                </div>
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th onClick={() => toggleTrafficSort('ip')} style={{cursor:'pointer'}} title="Sort numerically by IP">Device IP / Identifier{sortArrow(trafficSortKey==='ip', trafficSortDir)}</th>
                        <th>MAC Address</th>
                        <th onClick={() => toggleTrafficSort('rx')} style={{cursor:'pointer'}} title="Sort by downloaded bytes">Download (Rx){sortArrow(trafficSortKey==='rx', trafficSortDir)}</th>
                        <th onClick={() => toggleTrafficSort('tx')} style={{cursor:'pointer'}} title="Sort by uploaded bytes">Upload (Tx){sortArrow(trafficSortKey==='tx', trafficSortDir)}</th>
                        <th onClick={() => toggleTrafficSort('rxRate')} style={{cursor:'pointer'}} title="Sort by live download rate">Download Rate{sortArrow(trafficSortKey==='rxRate', trafficSortDir)}</th>
                        <th onClick={() => toggleTrafficSort('txRate')} style={{cursor:'pointer'}} title="Sort by live upload rate">Upload Rate{sortArrow(trafficSortKey==='txRate', trafficSortDir)}</th>
                        <th onClick={() => toggleTrafficSort('packets')} style={{cursor:'pointer'}} title="Sort by packet count">Packets{sortArrow(trafficSortKey==='packets', trafficSortDir)}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedTraffic.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: '#9ca3af' }}>
                            {trafficPerIP === false && gatewayTotals ? 'No per-device flows yet — gateway totals above are live.' : 'No active traffic flows observed yet.'}
                          </td>
                        </tr>
                      ) : (
                        sortedTraffic.map((s, idx) => (
                          <tr key={s.device_id || idx}>
                            <td style={{ fontWeight: 600 }}>{s.primary_ip || s.device_id.slice(0, 8)}</td>
                            <td className="font-mono text-secondary">{s.primary_mac || '—'}</td>
                            <td>
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: '#60a5fa' }}>
                                <ArrowDownCircle size={14} /> {formatBytes(s.rx_bytes)}
                              </span>
                            </td>
                            <td>
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: '#34d399' }}>
                                <ArrowUpCircle size={14} /> {formatBytes(s.tx_bytes)}
                              </span>
                            </td>
                            <td className="font-mono" style={{ color: '#60a5fa' }}>{formatBps(s.rx_rate_bps)}</td>
                            <td className="font-mono" style={{ color: '#34d399' }}>{formatBps(s.tx_rate_bps)}</td>
                            <td className="font-mono text-muted">{s.rx_packets + s.tx_packets}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: ALERTS */}
          {activeTab === 'alerts' && (
            <div>
            <div className="card">
              <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div className="card-title">Security & Anomaly Alerts ({filteredAlerts.length})</div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <div style={{ position: 'relative' }}>
                    <Search size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' }} />
                    <input
                      type="text"
                      placeholder="Search alerts..."
                      className="form-input"
                      style={{ paddingLeft: '32px', width: '200px', height: '36px' }}
                      value={alertQuery}
                      onChange={(e) => setAlertQuery(e.target.value)}
                    />
                  </div>
                  <select
                    className="form-select"
                    style={{ width: '140px', height: '36px' }}
                    value={alertSeverity}
                    onChange={(e: any) => setAlertSeverity(e.target.value)}
                  >
                    <option value="all">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: '#9ca3af', cursor: 'pointer' }}>
                    <input type="checkbox" checked={autoRemediation} onChange={async (e) => {
                      const enabled = e.target.checked;
                      await fetch('/api/v1/remediation', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
                      setAutoRemediation(enabled);
                    }} />
                    Auto-quarantine critical threats
                  </label>
                </div>
              </div>
              <div style={{ padding: '1.5rem' }}>
                {alerts.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '3rem', color: '#9ca3af' }}>
                    <CheckCircle size={48} style={{ color: '#10b981', margin: '0 auto 1rem' }} />
                    <p>No active security threats detected on LAN.</p>
                  </div>
                ) : filteredAlerts.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '3rem', color: '#9ca3af' }}>
                    <p>No alerts match the current filter.</p>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {filteredAlerts.map(a => (
                      <div 
                        key={a.id} 
                        style={{ 
                          backgroundColor: 'var(--bg-card)', 
                          borderRadius: '8px', 
                          padding: '1.25rem',
                          borderLeft: `4px solid ${
                            a.severity === 'critical' ? 'var(--accent-red)' :
                            a.severity === 'high' ? 'var(--accent-amber)' : 'var(--accent-blue)'
                          }`
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                          <div>
                            <span className={`badge ${
                              a.severity === 'critical' ? 'badge-red' :
                              a.severity === 'high' ? 'badge-amber' : 'badge-blue'
                            }`} style={{ marginRight: '0.5rem' }}>
                              {a.severity.toUpperCase()}
                            </span>
                            <span style={{ fontWeight: 700, fontSize: '1rem' }}>
                              {a.type.replace('_', ' ').toUpperCase()}
                            </span>
                          </div>
                          {!a.acknowledged && (
                            <button className="btn btn-secondary btn-sm" onClick={() => acknowledgeAlert(a.id)}>
                              Acknowledge
                            </button>
                          )}
                        </div>

                        <div style={{ fontSize: '0.875rem', color: '#e5e7eb', marginBottom: '0.75rem' }}>
                          {a.evidence && a.evidence.map((ev, i) => (
                            <div key={i} style={{ marginBottom: '0.25rem' }}>
                              • {ev.description}
                            </div>
                          ))}
                        </div>

                        <div style={{ fontSize: '0.8rem', color: '#9ca3af' }}>
                          <strong>Recommended action:</strong> {a.recommended_action}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="card" style={{marginTop:'1.25rem'}}>
              <div className="card-header"><div className="card-title">Alert Notifications (webhooks)</div></div>
              <div style={{ padding: '1.25rem 1.5rem', fontSize: '0.875rem' }}>
                {webhooks.length === 0 ? (
                  <p style={{ color: '#9ca3af' }}>No endpoints. Add a Discord/Slack/ntfy URL to get critical alerts on your phone.</p>
                ) : webhooks.map((h: any) => (
                  <div key={h.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <div><div style={{ fontWeight: 600 }}>{h.name || h.url}</div>
                    <div className="font-mono text-muted" style={{ fontSize: '0.75rem' }}>{h.url} · {h.min_severity || 'all'}</div></div>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="btn btn-secondary btn-sm" onClick={async () => { await fetch(`/api/v1/webhooks/${h.id}/test`, { method: 'POST' }); setActionMessage('Test notification sent'); setTimeout(() => setActionMessage(null), 3000); }}>Test</button>
                      <button className="btn btn-secondary btn-sm" onClick={async () => { await fetch(`/api/v1/webhooks/${h.id}`, { method: 'DELETE' }); fetchWebhooks(); }}>Delete</button>
                    </div>
                  </div>
                ))}
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
                  <input className="form-input" style={{ height: '34px', minWidth: '200px' }} placeholder="Name (e.g. phone)" value={whName} onChange={(e) => setWhName(e.target.value)} />
                  <input className="form-input font-mono" style={{ height: '34px', minWidth: '260px', flex: 1 }} placeholder="https://... webhook URL" value={whUrl} onChange={(e) => setWhUrl(e.target.value)} />
                  <select className="form-select" style={{ height: '34px' }} value={whSev} onChange={(e) => setWhSev(e.target.value)}>
                    <option value="all">all severities</option>
                    <option value="medium">medium+</option>
                    <option value="high">high+</option>
                    <option value="critical">critical only</option>
                  </select>
                  <button className="btn btn-primary btn-sm" onClick={async () => {
                    const name = whName.trim() || 'webhook';
                    const url = whUrl.trim();
                    if (!url) { notifyError('Webhook URL is required'); return; }
                    if (!/^https?:\/\/.+\..+/.test(url)) { notifyError('URL must start with http(s):// and contain a host'); return; }
                    await fetch('/api/v1/webhooks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, url, min_severity: whSev }) });
                    setWhName(''); setWhUrl('');
                    fetchWebhooks();
                  }}>Add</button>
                </div>
              </div>
            </div>
            </div>
          )}

          {/* TAB: TOPOLOGY (removed) */}

          {/* TAB: AUDIT */}
          {activeTab === 'audit' && (
            <div>
              <div className="card">
                <div className="card-header">
                  <div className="card-title">Protected Management Infrastructure (Allowlist)</div>
                  <button className="btn btn-secondary btn-sm" onClick={fetchAllowlist}><RefreshCw size={14}/> Reload</button>
                </div>
                <div style={{ padding: '1.25rem 1.5rem', fontSize: '0.875rem' }}>
                  <p style={{ color: '#9ca3af', marginBottom: '1rem' }}>
                    These can never be quarantined or rate-limited — not by hand, policy, schedule, or auto-defense. Comma-separated; save to apply.
                  </p>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
                    {[['gateway_ips','Gateway IPs'],['gateway_macs','Gateway MACs'],['dns_ips','DNS / DHCP IPs'],['admin_ips','Admin workstation IPs'],['controller_ips','Controller IPs']].map(([key, label]) => (
                      <div key={key}>
                        <label className="form-label">{label}</label>
                        <input className="form-input font-mono" style={{ width: '100%', height: '34px' }}
                          value={allowDraft[key] ?? (allowlist?.[key] || []).join(', ')}
                          onChange={(e) => setAllowDraft(d => ({ ...d, [key]: e.target.value }))} />
                      </div>
                    ))}
                    <div>
                      <label className="form-label">Management VLAN (0 = none)</label>
                      <input className="form-input font-mono" style={{ width: '100%', height: '34px' }} type="number" min={0}
                        value={allowVlan} onChange={(e) => setAllowVlan(e.target.value)} />
                    </div>
                  </div>
                  <button className="btn btn-primary btn-sm" style={{ marginTop: '0.75rem' }} onClick={async () => {
                    const csv = (v: string) => v.split(',').map(s => s.trim()).filter(Boolean);
                    const vlan = parseInt(allowVlan || '0', 10) || 0;
                    const res = await fetch('/api/v1/allowlist', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
                      gateway_ips: csv(allowDraft['gateway_ips'] ?? ''), gateway_macs: csv(allowDraft['gateway_macs'] ?? ''),
                      dns_ips: csv(allowDraft['dns_ips'] ?? ''), admin_ips: csv(allowDraft['admin_ips'] ?? ''),
                      controller_ips: csv(allowDraft['controller_ips'] ?? ''), management_vlan: vlan,
                    }) });
                    if (res.ok) {
                      setActionMessage('Allowlist saved — protected hosts cannot be cut');
                      setTimeout(() => setActionMessage(null), 3000);
                      fetchAllowlist();
                    } else {
                      notifyError(`Allowlist save failed: ${res.statusText}`);
                    }
                  }}>Save allowlist</button>
                </div>
              </div>

              <div className="card">
                <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div className="card-title">Audit Trail & Enforcement History ({auditLogs.length})</div>
                  <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <div style={{ position: 'relative' }}>
                      <Search size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' }} />
                      <input
                        type="text"
                        placeholder="Search actor, action, target..."
                        className="form-input"
                        style={{ paddingLeft: '32px', width: '240px', height: '36px' }}
                        value={auditQuery}
                        onChange={(e) => setAuditQuery(e.target.value)}
                      />
                    </div>
                    <a 
                      href={`/api/v1/export/audit.csv`} 
                      download="open-netcut-audit.csv" 
                      className="btn btn-secondary btn-sm"
                      style={{ textDecoration: 'none' }}
                    >
                      <FileText size={14} /> Export Audit Log
                    </a>
                  </div>
                </div>
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Target</th>
                        <th>Details</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', color: '#9ca3af', padding: '2rem' }}>
                            No audit events recorded yet.
                          </td>
                        </tr>
                      ) : (
                        auditLogs.filter((log: any) => {
                          const q = auditQuery.trim().toLowerCase();
                          if (!q) return true;
                          return (
                            (log.actor || '').toLowerCase().includes(q) ||
                            (log.action || '').toLowerCase().includes(q) ||
                            (log.target_id || '').toLowerCase().includes(q) ||
                            (log.details || '').toLowerCase().includes(q)
                          );
                        }).map((log: any, idx: number) => (
                          <tr key={idx}>
                            <td className="font-mono text-secondary">{new Date(log.timestamp).toLocaleTimeString()}</td>
                            <td style={{ fontWeight: 600 }}>{log.actor}</td>
                            <td><span className="badge badge-blue">{log.action}</span></td>
                            <td className="font-mono">{log.target_id?.slice(0, 8)}...</td>
                            <td>{log.details}</td>
                            <td>
                              <span className={`badge ${log.status === 'success' ? 'badge-green' : 'badge-red'}`}>
                                {log.status}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: POLICIES */}
          {activeTab === 'policies' && (
            <div>
            <div className="card">
              <div className="card-header"><div className="card-title">Policy Rules — evaluated every minute, highest priority first</div>
              <button className="btn btn-secondary btn-sm" onClick={fetchPolicies}><RefreshCw size={14}/> Reload</button></div>
              <div className="table-wrapper"><table><thead><tr><th>Name</th><th>WHEN</th><th>THEN</th><th>On</th><th>TTL</th><th></th></tr></thead>
              <tbody>{policies.length===0 ? (<tr><td colSpan={6} style={{textAlign:'center',color:'#9ca3af',padding:'2rem'}}>No policies yet. Example: WHEN trust is unknown THEN quarantine — new rogue devices get cut automatically.</td></tr>) :
                policies.map((p:any)=>(<tr key={p.id}>
                  <td style={{fontWeight:600}}>{p.name}</td>
                  <td className="font-mono text-secondary">{JSON.stringify(p.selector)}</td>
                  <td><span className="badge badge-blue">{p.action?.type}</span></td>
                  <td><button className="btn btn-secondary btn-sm" onClick={async () => {
                    await fetch(`/api/v1/policies/${p.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...p, enabled: !p.enabled }) });
                    fetchPolicies();
                  }}>{p.enabled ? 'on' : 'off'}</button></td>
                  <td className="font-mono">{p.ttl ? `${Math.round(p.ttl / 60e9)}m` : '15m'}</td>
                  <td><ConfirmButton className="btn btn-secondary btn-sm" confirmLabel="Confirm delete?" onConfirm={async () => {
                    await fetch(`/api/v1/policies/${p.id}`, { method: 'DELETE' });
                    fetchPolicies();
                  }}>Delete</ConfirmButton></td>
                </tr>))}</tbody></table></div>
              <div style={{ padding: '1rem 1.5rem', fontSize: '0.875rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>New rule</div>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                  <input className="form-input" style={{ height: '34px', minWidth: '140px' }} placeholder="Name" value={polName} onChange={(e) => setPolName(e.target.value)} />
                  <select className="form-select" style={{ height: '34px' }} value={polTrust} onChange={(e) => setPolTrust(e.target.value)}>
                    <option value="">any trust</option>
                    <option value="unknown">trust: unknown</option>
                    <option value="restricted">trust: restricted</option>
                    <option value="trusted">trust: trusted</option>
                  </select>
                  <input className="form-input" style={{ height: '34px', width: '110px' }} type="number" min={0} max={100} placeholder="min risk" value={polRisk} onChange={(e) => setPolRisk(e.target.value)} />
                  <input className="form-input font-mono" style={{ height: '34px', width: '150px' }} placeholder="MAC (opt)" value={polMac} onChange={(e) => setPolMac(e.target.value)} />
                  <select className="form-select" style={{ height: '34px' }} value={polAction} onChange={(e) => setPolAction(e.target.value)}>
                    <option value="quarantine">quarantine</option>
                    <option value="rate_limit">rate limit</option>
                    <option value="alert_only">log only</option>
                    <option value="allow">allow (override)</option>
                  </select>
                  <input className="form-input" style={{ height: '34px', minWidth: '180px' }} placeholder="Reason (audit)" value={polReason} onChange={(e) => setPolReason(e.target.value)} />
                  <input className="form-input" style={{ height: '34px', width: '90px' }} type="number" min={0} placeholder="TTL min" value={polTtl} onChange={(e) => setPolTtl(e.target.value)} title="0 = 15 min default" />
                  <button className="btn btn-primary btn-sm" onClick={async () => {
                    const risk = parseInt(polRisk, 10);
                    const ttlMin = parseInt(polTtl, 10);
                    const body: any = {
                      name: polName.trim() || 'unnamed rule',
                      description: polReason.trim(),
                      enabled: true, priority: 100,
                      selector: {} as any,
                      action: { type: polAction || 'quarantine' },
                    };
                    if (polTrust) body.selector.trust_state = polTrust;
                    if (!isNaN(risk)) body.selector.min_risk_score = risk;
                    if (polMac.trim()) body.selector.mac = polMac.trim();
                    if (body.action.type === 'rate_limit') { body.action.download_bps = 2000000; body.action.upload_bps = 1000000; }
                    if (!isNaN(ttlMin) && ttlMin > 0) body.ttl = ttlMin * 60 * 1e9;
                    const res = await fetch('/api/v1/policies', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                    if (!res.ok) { notifyError(`Rule rejected: ${res.statusText}`); return; }
                    setPolName(''); setPolRisk(''); setPolMac(''); setPolTtl('15'); setPolReason('');
                    fetchPolicies();
                  }}>Add rule</button>
                </div>
                <div style={{ color: '#9ca3af', fontSize: '0.75rem', marginTop: '0.4rem' }}>Blank rules never fire. Online devices with an active enforcement are skipped. An <span className="font-mono">allow</span> rule outranks lower rules.</div>
              </div>
            </div>
            <div className="card" style={{marginTop:'1.25rem'}}>
              <div className="card-header"><div className="card-title">Scheduled quarantines — e.g. kids' devices off 22:00–07:00</div>
              <button className="btn btn-secondary btn-sm" onClick={fetchSchedules}><RefreshCw size={14}/> Reload</button></div>
              <div style={{ padding: '1.25rem 1.5rem', fontSize: '0.875rem' }}>
                {schedules.length === 0 ? (
                  <p style={{ color: '#9ca3af' }}>No schedules. Pick a device + window below; enforcement applies and lifts automatically.</p>
                ) : schedules.map((s: any) => (
                  <div key={s.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <div>
                      <span style={{ fontWeight: 600 }}>{(devices.find(d => d.id === s.device_id)?.display_name) || s.device_id.slice(0, 8)}</span>
                      {' '}<span className="badge badge-blue">{s.action || 'quarantine'}</span>
                      <span className="font-mono text-secondary" style={{ marginLeft: '0.5rem' }}>
                        {String(s.start_hour).padStart(2, '0')}:{String(s.start_min).padStart(2, '0')}–{String(s.end_hour).padStart(2, '0')}:{String(s.end_min).padStart(2, '0')}
                        {(s.days && s.days.length > 0) ? ` ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].filter((_, i) => s.days.includes(i)).join(',')}` : ' daily'}
                      </span>
                    </div>
                    <button className="btn btn-secondary btn-sm" onClick={async () => { await fetch(`/api/v1/schedules/${s.id}`, { method: 'DELETE' }); fetchSchedules(); }}>Delete</button>
                  </div>
                ))}
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
                  <select className="form-select" style={{ height: '34px', minWidth: '180px' }} value={schedDev} onChange={(e) => setSchedDev(e.target.value)}>
                    <option value="" disabled>Device…</option>
                    {devices.map(d => (<option key={d.id} value={d.id}>{d.display_name} ({d.primary_ip})</option>))}
                  </select>
                  <input className="form-input" style={{ height: '34px', width: '80px' }} type="time" value={schedStart} onChange={(e) => setSchedStart(e.target.value)} />
                  <span style={{ color: '#9ca3af' }}>→</span>
                  <input className="form-input" style={{ height: '34px', width: '80px' }} type="time" value={schedEnd} onChange={(e) => setSchedEnd(e.target.value)} />
                  <select className="form-select" style={{ height: '34px' }} value={schedAction} onChange={(e) => setSchedAction(e.target.value)}>
                    <option value="quarantine">quarantine</option>
                    <option value="rate_limit">rate limit 2M/1M</option>
                  </select>
                  <button className="btn btn-primary btn-sm" onClick={async () => {
                    if (!schedDev) { notifyError('Pick a device first'); return; }
                    const [sh, sm] = schedStart.split(':').map(Number);
                    const [eh, em] = schedEnd.split(':').map(Number);
                    const res = await fetch('/api/v1/schedules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ device_id: schedDev, start_hour: sh, start_min: sm, end_hour: eh, end_min: em, action: schedAction, download_bps: 2000000, upload_bps: 1000000 }) });
                    if (!res.ok) { notifyError(`Schedule rejected: ${res.statusText}`); return; }
                    fetchSchedules();
                  }}>Add schedule</button>
                </div>
              </div>
            </div>
            </div>
          )}

          {/* TAB: QUARANTINE */}
          {activeTab === 'quarantine' && (
            <div>
            <div className="card">
              <div className="card-header"><div className="card-title">Quarantine — Device • Reason • Actor • Method • Applied • Expiration • Desired vs Actual</div>
              <div style={{display:'flex',gap:'0.5rem',alignItems:'center'}}>
              {freezeActive && (<span className="badge badge-red" title="Freeze latch is ON — devices joining now are cut automatically">❄ FREEZE ON{typeof freezeInfo?.active_cuts === 'number' ? ` (${freezeInfo.active_cuts} cuts)` : ''}</span>)}
                <button className="btn btn-secondary btn-sm" onClick={fetchPolicies}><RefreshCw size={14}/> Reload</button>
                <button className="btn btn-sm" style={{backgroundColor:'var(--accent-red)',color:'#fff'}} onClick={() => { openFreezeModal(); }}>❄ Freeze ALL internet</button>
                <ConfirmButton
                  className="btn btn-secondary btn-sm"
                  title="Lift every active quarantine (including manual ones)"
                  confirmLabel="Confirm unfreeze?"
                  onConfirm={async () => {
                    await fetch('/api/v1/freeze', { method: 'DELETE' });
                    fetchPolicies(); refreshData();
                  }}
                >Unfreeze all</ConfirmButton>
              </div></div>
              {freezeInfo && (
                <div style={{ padding: '0.75rem 1.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '0.8rem', color: '#9ca3af' }}>
                  <strong>Freeze:</strong> {freezeInfo.active ? 'ON' : 'OFF'}
                  {typeof freezeInfo.active_cuts === 'number' && <> · <strong className="font-mono">{freezeInfo.active_cuts}</strong> active cut(s)</>}
                  {freezeInfo.reason && <> · reason <span className="font-mono">{freezeInfo.reason}</span></>}
                  {freezeInfo.adapter && <> · method <span className="font-mono">{freezeInfo.adapter}</span></>}
                  {freezeInfo.self_ip && <> · self <span className="font-mono">{freezeInfo.self_ip}</span></>}
                </div>
              )}
              <div className="table-wrapper"><table><thead><tr><th>Device</th><th>Adapter (Method)</th><th>Applied</th><th>Time left</th><th>Desired → Actual</th><th>Error</th><th>Dry-run</th></tr></thead>
              <tbody>{enforcements.length===0 ? (<tr><td colSpan={7} style={{textAlign:'center',color:'#9ca3af',padding:'2rem'}}>No active enforcements.</td></tr>) :
                enforcements.map((e:any)=>{
                  const cd = formatCountdown(e.expires_at, nowTs);
                  return (<tr key={e.id}><td className="font-mono">{e.target_ip||e.target_mac}</td><td><span className="badge badge-blue">{e.adapter}</span> {e.action}</td><td className="font-mono text-secondary">{e.applied_at?new Date(e.applied_at).toLocaleString():'—'}</td><td className="font-mono" title={`Expires: ${cd.title}`}><span className={`badge ${cd.urgent ? 'badge-red' : e.expires_at ? 'badge-green' : 'badge-gray'}`}>⏳ {cd.text}</span></td><td><span className="badge badge-green">{e.desired_state} → {e.actual_state}</span></td><td style={{maxWidth:'260px',wordBreak:'break-word',color:e.error_message?'#f87171':'#9ca3af',fontSize:'0.75rem'}}>{e.error_message || '—'}</td><td>{e.dry_run?'yes':'no'}</td></tr>);
                })}</tbody></table></div>
            </div>
            </div>
          )}

          {/* TAB: INTEGRATIONS (removed: unmanaged LAN has no router/AP integrations;
              adapter choice lives in the Quarantine modal via the ranked list) */}

          {/* TAB: CAMERAS */}
          {activeTab === 'cameras' && (
            <div>
              <div className="card">
                <div className="card-header">
                  <div className="card-title">IP Cameras & NVRs <span style={{fontWeight:400,fontSize:'0.8rem',color:'#9ca3af'}}>— detected by web banner / RTSP port; only your own devices</span></div>
                  <div style={{display:'flex',gap:'0.5rem',alignItems:'center'}}>
                    <label style={{display:'flex',alignItems:'center',gap:'0.4rem',fontSize:'0.8rem',color:'#9ca3af',cursor:'pointer'}}>
                      <input type="checkbox" checked={camAuto} onChange={(e) => setCamAuto(e.target.checked)} /> Live stills
                    </label>
                    <button className="btn btn-secondary btn-sm" onClick={fetchCameras}><RefreshCw size={14}/> Reload</button>
                  </div>
                </div>
                <div style={{ padding: '1.5rem' }}>
                  {cameras.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '3rem', color: '#9ca3af' }}>
                      <Video size={48} style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
                      <p>No cameras detected yet. Discovery flags devices with camera web banners or an open RTSP port (554).</p>
                    </div>
                  ) : (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
                      {cameras.map((cam: any) => {
                        const path = camPaths[cam.id];
                        const imgSrc = path ? `/api/v1/cameras/${cam.id}/image?path=${encodeURIComponent(path)}&t=${camTick}` : null;
                        return (
                        <div key={cam.id} style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '1rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                            <div style={{ fontWeight: 700 }}>{cam.display_name}</div>
                            <span className={`badge ${cam.is_online ? 'badge-green' : 'badge-gray'}`}>{cam.is_online ? 'Online' : 'Offline'}</span>
                          </div>
                          <div className="font-mono text-secondary" style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>{cam.primary_ip} · {cam.primary_mac}</div>
                          <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginBottom: '0.75rem' }}>
                            {cam.vendor || 'Unknown vendor'}{cam.rtsp_open ? ' · RTSP :554 open' : ''}{cam.banner ? ` · ${cam.banner}` : ''}
                          </div>
                          <div style={{ backgroundColor: '#000', borderRadius: '8px', minHeight: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', marginBottom: '0.75rem' }}>
                            {imgSrc ? (
                              <img src={imgSrc} alt={`Camera ${cam.primary_ip}`} style={{ width: '100%', display: 'block' }} onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                            ) : (
                              <div style={{ textAlign: 'center', color: '#6b7280', padding: '2rem', fontSize: '0.85rem' }}>
                                <Camera size={32} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
                                <div>No public snapshot found.</div>
                                <div>Login-protected cameras need their web UI.</div>
                              </div>
                            )}
                          </div>
                          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                            <button className="btn btn-secondary btn-sm" onClick={async () => {
                              const res = await fetch(`/api/v1/cameras/${cam.id}/snapshot`, { method: 'POST' }).then(r => r.json()).catch(() => null);
                              if (res && res.found) {
                                setCamPaths(p => ({ ...p, [cam.id]: res.path }));
                                setCamTick(v => v + 1);
                                setActionMessage(`Snapshot found: ${res.path}`);
                                setTimeout(() => setActionMessage(null), 3000);
                              } else {
                                setActionMessage('No anonymous snapshot — use web UI login');
                                setTimeout(() => setActionMessage(null), 3000);
                              }
                            }}>Find snapshot</button>
                            {path && <button className="btn btn-secondary btn-sm" onClick={() => setCamTick(v => v + 1)}><RefreshCw size={14} /> Refresh</button>}
                            <a className="btn btn-secondary btn-sm" style={{ textDecoration: 'none' }} href={cam.web_url} target="_blank" rel="noreferrer">Open web UI</a>
                          </div>
                          <details style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#9ca3af' }}>
                            <summary style={{ cursor: 'pointer' }}>Manual stream path (MJPEG over HTTP)</summary>
                            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem' }}>
                              <input className="form-input font-mono" style={{ height: '32px', flex: 1 }} placeholder="/snapshot.jpg or /video.mjpg"
                                value={camManual[cam.id] ?? path ?? ''} onChange={(e) => setCamManual(m => ({ ...m, [cam.id]: e.target.value }))} />
                              <button className="btn btn-secondary btn-sm" onClick={() => {
                                const v = (camManual[cam.id] ?? path ?? '').trim();
                                if (!v) return;
                                setCamPaths(p => ({ ...p, [cam.id]: v }));
                                setCamTick(t => t + 1);
                              }}>View</button>
                            </div>
                          </details>
                          <details style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#9ca3af' }}>
                            <summary style={{ cursor: 'pointer' }} title="RTSP needs a player like VLC — browsers cannot play it">Stream URLs for VLC →</summary>
                            <div className="font-mono" style={{ marginTop: '0.4rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                              {[`rtsp://${cam.primary_ip}:554/h264Preview_01_main`, `rtsp://${cam.primary_ip}:554/11`, `rtsp://${cam.primary_ip}:554/live`, `http://${cam.primary_ip}/video.mjpg`].map(u => (
                                <input key={u} className="form-input font-mono" style={{ height: '30px', fontSize: '0.72rem' }} readOnly value={u} onClick={(e) => (e.target as HTMLInputElement).select()} title="Click to select, copy into VLC (needs camera login)" />
                              ))}
                              <div>Common logins to try on YOUR OWN camera: admin/admin, admin/12345, admin/(blank). Check its label/manual.</div>
                            </div>
                          </details>
                        </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Quarantine Modal */}
      {showQuarantineModal && selectedDevice && (
        <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) setShowQuarantineModal(false); }}>
          <div className="modal-content">
            <div className="modal-header">
              <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>Apply Network Quarantine</div>
              <button 
                className="btn btn-secondary btn-sm" 
                onClick={() => setShowQuarantineModal(false)}
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p style={{ color: '#9ca3af', marginBottom: '1.25rem', fontSize: '0.875rem' }}>
                Block network connectivity for <strong>{selectedDevice.display_name}</strong> ({selectedDevice.primary_ip || selectedDevice.primary_mac}) via legitimate infrastructure enforcement.
              </p>

              <div className="form-group">
                <label className="form-label">Enforcement Adapter / Infrastructure Point — ★ = most effective on this gateway</label>
                <select
                  className="form-select"
                  value={selectedAdapter}
                  onChange={(e) => setSelectedAdapter(e.target.value)}
                >
                  {rankedQuarantine.length > 0 ? rankedQuarantine.map((r) => (
                    <option key={r.info.name} value={r.info.name} disabled={!r.available || !r.supports_action}>
                      {r.recommended ? '★ ' : ''}{r.info.label} — {r.available ? (r.info.effectiveness_1_5 + '/5') : 'offline'} {r.supports_action ? '' : '(no quarantine)'}
                    </option>
                  )) : (<>
                    <option value="mock_simulator">Mock Simulator / Lab Adapter</option>
                    <option value="linux_nftables">Linux Gateway (nftables kernel filter)</option>
                    <option value="l2_arp">L2 ARP Cut — side-host LAN quarantine</option>
                  </>)}
                </select>
                {(() => {
                  const cur = rankedQuarantine.find((r) => r.info.name === selectedAdapter);
                  if (!cur) return (<div style={{fontSize:'0.8rem',color:'#9ca3af',marginTop:'0.4rem'}}>On this Linux gateway use <strong>linux_nftables</strong> (kernel drop). Router entries need their URL configured.</div>);
                  return (<div style={{fontSize:'0.8rem',color: cur.available ? (cur.info.lab_only ? '#fbbf24' : '#9ca3af') : '#f87171',marginTop:'0.4rem',borderLeft: cur.info.lab_only ? '3px solid #f59e0b' : undefined,paddingLeft: cur.info.lab_only ? '0.5rem' : undefined}}>
                    {cur.recommended ? '★ Recommended: ' : ''}{cur.info.lab_only ? '⚠ DISRUPTIVE — own network only: ' : ''}{cur.reason || cur.info.description}
                    {cur.info.warning ? ` — ${cur.info.warning}` : ''} <span className="font-mono">Requires: {cur.info.requires}</span>
                  </div>);
                })()}
              </div>

              <div className="form-group">
                <label className="form-label">Auto-Rollback TTL (Safety Timer)</label>
                <select 
                  className="form-select" 
                  value={quarantineTTL} 
                  onChange={(e) => setQuarantineTTL(Number(e.target.value))}
                >
                  <option value={900}>15 minutes (Safe default)</option>
                  <option value={3600}>1 hour</option>
                  <option value={86400}>24 hours</option>
                  <option value={0}>Indefinite (Manual lift required)</option>
                </select>
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.875rem' }}>
                  <input 
                    type="checkbox" 
                    checked={dryRun} 
                    onChange={(e) => setDryRun(e.target.checked)} 
                  />
                  <span>Dry Run (Simulate policy without dropping physical traffic)</span>
                </label>
              </div>

              {isProtectedTarget(selectedDevice) && (
                <div style={{ border: '1px solid var(--accent-red)', borderRadius: '8px', padding: '0.9rem', marginTop: '0.5rem', backgroundColor: 'rgba(239,68,68,0.07)' }}>
                  <div style={{ fontWeight: 700, color: '#f87171', marginBottom: '0.4rem' }}>⛔ Protected infrastructure — {isProtectedTarget(selectedDevice)}</div>
                  <div style={{ fontSize: '0.8rem', color: '#9ca3af', marginBottom: '0.6rem' }}>
                    Cutting the gateway alone does <strong>not</strong> stop LAN devices (their caches are untouched).
                    To stop all internet at once, use <strong>Freeze</strong> in the Quarantine tab instead.
                    Break-glass here cuts only this box itself, is audit-logged, and still auto-heals on TTL.
                  </div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                    <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
                    <span>I understand — override the allowlist for this device</span>
                  </label>
                  {breakGlass && (
                    <input className="form-input" style={{ width: '100%', height: '34px' }} placeholder="Reason (required, goes into the audit log)" value={breakReason} onChange={(e) => setBreakReason(e.target.value)} />
                  )}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowQuarantineModal(false)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => {
                if (isProtectedTarget(selectedDevice) && (!breakGlass || !breakReason.trim())) {
                  notifyError('Protected infrastructure: tick the override and give a reason first.');
                  return;
                }
                executeQuarantine();
              }}>Enforce Quarantine</button>
            </div>
          </div>
        </div>
      )}

      {/* Rate Limit Modal */}
      {showRateLimitModal && selectedDevice && (
        <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) setShowRateLimitModal(false); }}>
          <div className="modal-content">
            <div className="modal-header">
              <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>Traffic Shaping / Rate Limit</div>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowRateLimitModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <p style={{ color: '#9ca3af', marginBottom: '1.25rem', fontSize: '0.875rem' }}>
                Throttle bandwidth for <strong>{selectedDevice.display_name}</strong> using QoS / Traffic Control.
              </p>

              <div className="form-group">
                <label className="form-label">Enforcement Adapter — ★ = most effective shaping on this gateway</label>
                <select
                  className="form-select"
                  value={selectedAdapter}
                  onChange={(e) => setSelectedAdapter(e.target.value)}
                >
                  {rankedShaping.length > 0 ? rankedShaping.map((r) => (
                    <option key={r.info.name} value={r.info.name} disabled={!r.available || !r.supports_action}>
                      {r.recommended ? '★ ' : ''}{r.info.label} — {r.available ? (r.info.effectiveness_1_5 + '/5') : 'offline'} {r.supports_action ? '' : '(no shaping)'}
                    </option>
                  )) : (<>
                    <option value="mock_simulator">Mock Simulator / Lab Adapter</option>
                    <option value="linux_tc">Linux Traffic Control (tc HTB + CAKE)</option>
                  </>)}
                </select>
                {(() => {
                  const cur = rankedShaping.find((r) => r.info.name === selectedAdapter);
                  if (!cur) return (<div style={{fontSize:'0.8rem',color:'#9ca3af',marginTop:'0.4rem'}}>On this Linux gateway use <strong>linux_tc</strong> (HTB queue to e.g. 2 Mbps). Throttling queues traffic; quarantine drops it.</div>);
                  return (<div style={{fontSize:'0.8rem',color: cur.available ? (cur.info.lab_only ? '#fbbf24' : '#9ca3af') : '#f87171',marginTop:'0.4rem',borderLeft: cur.info.lab_only ? '3px solid #f59e0b' : undefined,paddingLeft: cur.info.lab_only ? '0.5rem' : undefined}}>
                    {cur.recommended ? '★ Recommended: ' : ''}{cur.info.lab_only ? '⚠ DISRUPTIVE — own network only: ' : ''}{cur.reason || cur.info.description}
                    {cur.info.warning ? ` — ${cur.info.warning}` : ''} <span className="font-mono">Requires: {cur.info.requires}</span>
                  </div>);
                })()}
              </div>

              <div className="form-group">
                <label className="form-label">Max Download Bandwidth</label>
                <select className="form-select" value={rateDown} onChange={(e) => setRateDown(Number(e.target.value))}>
                  <option value={500000}>500 Kbps</option>
                  <option value={1000000}>1 Mbps</option>
                  <option value={2000000}>2 Mbps</option>
                  <option value={5000000}>5 Mbps</option>
                  <option value={10000000}>10 Mbps</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Max Upload Bandwidth</label>
                <select className="form-select" value={rateUp} onChange={(e) => setRateUp(Number(e.target.value))}>
                  <option value={250000}>250 Kbps</option>
                  <option value={500000}>500 Kbps</option>
                  <option value={1000000}>1 Mbps</option>
                  <option value={2000000}>2 Mbps</option>
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowRateLimitModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={executeRateLimit}>Apply Bandwidth Limit</button>
            </div>
          </div>
        </div>
      )}

      {/* Rename Modal */}
      {showRenameModal && selectedDevice && (
        <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) setShowRenameModal(false); }}>
          <div className="modal-content" style={{maxWidth:'440px'}}>
            <div className="modal-header">
              <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>Name Device</div>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowRenameModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <p style={{ color: '#9ca3af', marginBottom: '1rem', fontSize: '0.875rem' }}>
                <strong>{selectedDevice.display_name}</strong><br/>
                <span className="font-mono">{selectedDevice.primary_ip || 'No IP'} · {selectedDevice.primary_mac || 'No MAC'}</span>
              </p>
              <div className="form-group">
                <label className="form-label">Device name (permanent — automatic discovery cannot overwrite it)</label>
                <input
                  className="form-input"
                  style={{width:'100%'}}
                  placeholder="e.g. KJ SST"
                  value={renameValue}
                  autoFocus
                  onChange={(e) => setRenameValue(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') executeRename(); }}
                />
              </div>
            </div>
            <div className="modal-footer" style={{display:'flex',gap:'0.5rem',justifyContent:'flex-end'}}>
              {((selectedDevice.metadata as any)?.hostname_source === 'manual') && (
                <button className="btn btn-secondary" onClick={executeClearRename} title="Return to automatic naming">Auto</button>
              )}
              <button className="btn btn-secondary" onClick={() => setShowRenameModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={executeRename}>Save name</button>
            </div>
          </div>
        </div>
      )}
      {/* Device Details Modal (opened from Inventory rows) */}
      {deviceDetail && (
        <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) setDeviceDetail(null); }}>
          <div className="modal-content" style={{maxWidth:'720px'}}>
            <div className="modal-header">
              <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>Device Details: {deviceDetail.device?.display_name}</div>
              <button className="btn btn-secondary btn-sm" onClick={()=>setDeviceDetail(null)}>✕</button>
            </div>
            <div className="modal-body" style={{fontSize:'0.85rem'}}>
              <div>IP: <span className="font-mono">{deviceDetail.device?.primary_ip}</span> MAC: <span className="font-mono">{deviceDetail.device?.primary_mac}</span> Vendor: {deviceDetail.device?.vendor}</div>
              <div>VLAN: {deviceDetail.device?.attachment?.vlan ?? 0} Port: {deviceDetail.device?.attachment?.switch_port || deviceDetail.device?.attachment?.ap_name || '—'} Interface: {deviceDetail.device?.attachment?.interface || '—'}</div>
              <div style={{display:'flex',gap:'0.5rem',marginTop:'0.5rem',alignItems:'center'}}>
                <span style={{color:'#9ca3af'}}>Trust:</span>
                <span className="badge badge-blue">{deviceDetail.device?.trust_state}</span>
                {['trusted','restricted','unknown'].filter(s => s !== deviceDetail.device?.trust_state).map(s => (
                  <button key={s} className="btn btn-secondary btn-sm" onClick={async () => {
                    await fetch(`/api/v1/devices/${deviceDetail.device.id}/trust`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({state:s})});
                    await fetchDeviceDetail(deviceDetail.device.id); refreshData();
                  }}>Mark {s}</button>
                ))}
              </div>
              <div style={{marginTop:'0.5rem',color:'#9ca3af'}}>
                Name: <strong style={{color:'#e5e7eb'}}>{deviceDetail.device?.metadata?.hostname || '—'}</strong>
                {' '}via <span className="badge badge-blue">{deviceDetail.device?.metadata?.hostname_source || 'none'}</span>
                {deviceDetail.device?.metadata?.hostname_source === 'manual' && ' (your override — automatic sources cannot change it)'}
              </div>
              <div style={{marginTop:'0.5rem'}}>Addresses: {(deviceDetail.device?.addresses||[]).length} | Observations: {(deviceDetail.observations||[]).length} | Alerts: {(deviceDetail.alerts||[]).length} | Enforcements: {(deviceDetail.enforcements||[]).length}</div>
              {(deviceDetail.observations||[]).slice(-8).map((o:any,i:number)=>(<div key={i} className="font-mono text-muted">[{o.source}] {o.ip} {o.hostname||''}{o.attributes?.ptr_hostname ? ` (ptr:${o.attributes.ptr_hostname})` : ''}</div>))}
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={()=>setDeviceDetail(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
      {/* Freeze Modal */}
      {showFreezeModal && (
        <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) setShowFreezeModal(false); }}>
          <div className="modal-content" style={{maxWidth:'480px',border:'1px solid var(--accent-red)'}}>
            <div className="modal-header">
              <div style={{ fontWeight: 700, fontSize: '1.1rem', color: '#f87171' }}>❄ Freeze ALL internet access?</div>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowFreezeModal(false)}>✕</button>
            </div>
            <div className="modal-body" style={{fontSize:'0.875rem'}}>
              <p style={{ color: '#9ca3af', marginBottom: '0.75rem' }}>
                Cuts <strong>every online, non-protected device</strong> on the LAN for 15 minutes
                (gateway/DNS/admin hosts are never touched). Cutting the gateway box alone would
                <strong> not</strong> stop anyone — this is why Freeze exists. Release heals
                automatically, or lift early from this tab.
              </p>
              <p style={{ color: '#fbbf24', marginBottom: '0.75rem' }}>
                While Freeze is ON, <strong>devices joining later are cut automatically too</strong>.
                It stays on until you Unblock All — including across restarts.
              </p>
              <div className="form-group">
                <label className="form-label">Method — same choice as single-device quarantine</label>
                <select
                  className="form-select"
                  style={{width:'100%'}}
                  value={freezeAdapter}
                  onChange={(e) => setFreezeAdapter(e.target.value)}
                >
                  {rankedQuarantine.length > 0 ? rankedQuarantine.map((r) => (
                    <option key={r.info.name} value={r.info.name} disabled={!r.available || !r.supports_action}>
                      {r.recommended ? '★ ' : ''}{r.info.label} — {r.available ? (r.info.effectiveness_1_5 + '/5') : 'offline'} {r.supports_action ? '' : '(no quarantine)'}
                    </option>
                  )) : (
                    <option value="l2_arp">L2 ARP Cut — side-host LAN quarantine</option>
                  )}
                </select>
                {(() => {
                  const cur = rankedQuarantine.find((r) => r.info.name === freezeAdapter);
                  if (!cur) return null;
                  return (<div style={{fontSize:'0.8rem',color: cur.available ? (cur.info.lab_only ? '#fbbf24' : '#9ca3af') : '#f87171',marginTop:'0.4rem'}}>
                    {cur.recommended ? '★ Recommended: ' : ''}{cur.info.lab_only ? '⚠ DISRUPTIVE — own network only: ' : ''}{cur.reason || cur.info.description}
                  </div>);
                })()}
              </div>
              <div className="form-group">
                <label className="form-label">What about MY internet (this browser)?</label>
                <div style={{ fontSize: '0.8rem', color: '#9ca3af', marginBottom: '0.4rem' }}>
                  We see you as <span className="font-mono">{whoAmI?.ip || '…'}{whoAmI?.display_name ? ` (${whoAmI.display_name})` : ''}</span>.
                  Same-LAN dashboard traffic never uses the gateway, so this page keeps working either way.
                </div>
                {selfUnresolved && (
                  <div style={{ fontSize: '0.8rem', color: '#fbbf24', marginBottom: '0.4rem' }}>
                    ⚠ You opened the dashboard via localhost, so we can't tell which LAN device you are.
                    Pick it below, or reopen via <span className="font-mono">http://&lt;your-lan-ip&gt;:8080</span> —
                    otherwise "keep mine working" can't protect you.
                  </div>
                )}
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.875rem', marginBottom: '0.35rem' }}>
                  <input type="radio" name="freeze-self" checked={!includeSelf} onChange={() => setIncludeSelf(false)} />
                  <span>Keep <strong>my</strong> internet working (recommended)</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.875rem' }}>
                  <input type="radio" name="freeze-self" checked={includeSelf} onChange={() => setIncludeSelf(true)} />
                  <span>Cut mine too — my internet stops as well</span>
                </label>
                {(selfUnresolved || !whoAmI?.device_id) && (
                  <select className="form-select" style={{ width: '100%', marginTop: '0.4rem' }} value={selfOverrideId} onChange={(e) => setSelfOverrideId(e.target.value)} title="Tell us which device is yours so we can spare it (or cut it)">
                    <option value="">This device is… (optional)</option>
                    {devices.filter(d => d.is_online).map(d => (
                      <option key={d.id} value={d.id}>{d.display_name} ({d.primary_ip})</option>
                    ))}
                  </select>
                )}
              </div>
              <div className="form-group">
                <label className="form-label">Reason (required, goes into the audit log)</label>
                <input className="form-input" style={{width:'100%'}} placeholder="e.g. kids bedtime, incident response" value={freezeReason} onChange={(e) => setFreezeReason(e.target.value)} />
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={freezeAck} onChange={(e) => setFreezeAck(e.target.checked)} />
                <span>I understand every device loses internet for 15 minutes</span>
              </label>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowFreezeModal(false)}>Cancel</button>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.25rem' }}>
                {(!freezeAck || !freezeReason.trim()) && !freezing && (
                  <span style={{ fontSize: '0.75rem', color: '#fbbf24' }}>
                    ↑ {!freezeReason.trim() ? 'Type a reason' : 'Tick the confirmation'} to enable
                  </span>
                )}
                <button className="btn btn-danger" disabled={!freezeAck || !freezeReason.trim() || freezing} onClick={executeFreeze}>
                  {freezing ? 'Freezing… (cuts landing, watch Quarantine tab)' : 'Freeze everything'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
