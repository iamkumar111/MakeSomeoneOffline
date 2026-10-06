# Open-NetCut

> **Open-source network observability & policy-control platform.**
> Device inventory with real names, LAN threat detection, live per-device
> bandwidth, scheduled + policy-driven quarantine, and camera discovery —
> on a Linux gateway or any LAN host, no managed switches required.

---

## Which quarantine method works for you

| Your setup | Method (adapter) | Wired + WiFi? |
|---|---|---|
| Control plane **runs on the gateway** (native, root) | `linux_nftables` + `linux_tc` (★ recommended, auto-selected) | Yes |
| Side host, unmanaged ISP router | `l2_arp` — ARP enforcement, explicit opt-in (`ENABLE_L2_ARP=1`), own networks only, disruptive by design | Yes |

`mock_simulator` is lab-only and touches no real packets. The UI ranks every
adapter live (`/api/v1/integrations?action=quarantine`) and pre-selects the
best available one — `l2_arp` is never auto-selected.

---

## Features

- **Device inventory with real names** — ARP/neighbor tables, passive DHCP
  snooping (hostnames off the wire), mDNS self-announcements + service
  instances, UPnP friendlyNames, NetBIOS computer names, HTTP page titles,
  reverse DNS (weakest). Stronger sources outrank weaker ones; ties keep the
  incumbent so names never flap. Manual rename (by ID *or MAC*) pins forever.
- **Live bandwidth** — nftables per-IP counters (no conntrack module needed),
  conntrack fallback, gateway totals; sortable Top Talkers.
- **Threat detection** — gateway impersonation, mass ARP spoofing, duplicate
  IP (RFC 5227), rogue DHCP, port scans, rogue IPv6 RA, bandwidth anomalies.
- **Enforcement** — quarantine (IPv4 + IPv6 NDP spoof for dual-stack),
  rate limiting, TTL auto-rollback, dry-run, per-device surgical nft removal
  (no whole-chain flushes), startup reconcile (no zombie blocks).
- **Automation** — WHEN/THEN policy rules evaluated every minute (priority
  ordered, allow-overrides, blank rules never fire), scheduled time windows
  (e.g. 22:00–07:00), critical-alert auto-quarantine (toggleable), alert
  webhooks (Discord/Slack/ntfy) with test button.
- **Cameras tab** — camera/NVR detection (HTTP banner, RTSP :554), anonymous
  snapshot probe + proxied stills, VLC stream-URL helper. No credential
  guessing, ever.
- **Safety** — management allowlist (editable in UI, survives restarts),
  protected gateway/DNS/controller, full audit trail (persisted, CSV export).
- **Storage** — crash-safe JSON snapshot (`-db`, atomic write + `.bak`),
  persisting policies, audit, schedules, webhooks across restarts.

---

## Architecture Overview

```text
                        ┌──────────────────────────────────────┐
                        │      React + TypeScript Dashboard    │
                        │ Devices • Bandwidth • Alerts • Audit │
                        │ Policies • Quarantine • Cameras      │
                        └──────────────────┬───────────────────┘
                                           │
                                   REST + WebSockets
                                           │
                     ┌─────────────────────▼────────────────────┐
                     │          Go Control Plane / API          │
                     │                                          │
                     │ Identity Fusion Engine    Policy Engine  │
                     │ Scheduler/Evaluator  Auto-Remediation    │
                     │ Detection Engine     Webhook Dispatcher  │
                     │ Adapter Registry     JSON Snapshot Store │
                     └──────┬─────────┬──────────────┬──────────┘
                            │         │              │
                   ┌────────▼───┐ ┌──▼────────────┐ ┌▼────────────────┐
                   │ JSON file  │ │  Linux Agent  │ │ Router Adapters │
                   │            │ │               │ │                 │
                   │ snapshot   │ │ ARP / NDP     │ │ L2 ARP cut    │
                   │ .bak       │ │ mDNS / SSDP   │ │ (side-host)   │
                   │            │ │ DHCP snoop    │ │ Mock lab      │
                   │            │ │ nft / tc acct │ │ Mock Simulator  │
                   └────────────┘ └───────────────┘ └─────────────────┘
```

---

## Directory Structure

```
├── cmd/
│   ├── control-plane/         # REST & WebSocket API, static file server, orchestrator
│   ├── netcut-cli/            # Headless admin CLI
│   └── sim-lab/               # Lab threat simulator
├── pkg/
│   ├── models/                # Domain models: Device, Address, Alert, Policy, Enforcement
│   ├── events/                # Monotonic sequence EventBus and pub/sub
│   ├── discovery/             # ARP/NDP scanner, mDNS/SSDP/UPnP, DHCP lease+snoop, OUI, Identity Fusion
│   ├── detection/             # Threat detection (gateway impersonation, spoofing, rogue DHCP/RA …)
│   ├── policy/                # Engine, scheduler, evaluator, freeze latch, auto-remediation, allowlist, TTL
│   ├── adapters/              # Linux nftables/tc, L2 ARP cut, Mock simulator
│   ├── traffic/               # Telemetry, nftables/conntrack accounting collectors
│   ├── notify/                # Webhook alert dispatcher
│   └── store/                 # JSON snapshot store (atomic save, .bak fallback)
├── web/                       # React + TypeScript + Vite frontend dashboard
├── deploy/                    # Dockerfile, Docker Compose, systemd unit files
└── Makefile                   # Build, test, and run automation
```

---

## Quick Start

### 1. Build & Test

```bash
# Run unit tests
make test

# Build frontend and Go binaries (./bin/)
make build
```

### 2. Run (Linux gateway or side host, as root for nftables/tc/raw sockets)

```bash
# Gateway mode (recommended): kernel enforcement, no ARP needed
sudo ./bin/control-plane -port 8080 -db ./netcut.json

# Side host on unmanaged LAN: also enable the L2 ARP cut adapter
# (own networks only — disruptive by design, explicit selection in UI)
sudo ENABLE_L2_ARP=1 ./bin/control-plane -port 8080 -db ./netcut.json

# UI: http://localhost:8080
# Custom LAN interface for shaping: TC_IFACE=wlp3s0
# Or simply: make run  (side-host L2 mode + JSON DB) / make run-gateway
```

### 3. Quarantine a device (your own network)

UI: Devices → Quarantine → pick the ★ recommended adapter → short TTL → Enforce.
Or by MAC, no UI needed:

```bash
# name it first (optional, permanent)
curl -X POST http://localhost:8080/api/v1/devices/00:e0:27:2e:b1:b3/rename \
  -H 'Content-Type: application/json' -d '{"name":"KJ SST"}'

# cut it for 15 minutes (dry_run:false = real)
curl -X POST http://localhost:8080/api/v1/devices/00:e0:27:2e:b1:b3/quarantine \
  -H 'Content-Type: application/json' \
  -d '{"adapter":"l2_arp","ttl_seconds":900,"dry_run":false}'

# lift early (or wait for TTL auto-heal)
curl -X DELETE http://localhost:8080/api/v1/devices/00:e0:27:2e:b1:b3/quarantine
```

### 4. Administrator CLI (`netcut-cli`)

```bash
./bin/netcut-cli status          # network health and threat overview
./bin/netcut-cli devices         # discovered devices table
./bin/netcut-cli cut 192.168.1.102     # quarantine (15m safe default TTL)
./bin/netcut-cli restore 192.168.1.102 # lift quarantine
./bin/netcut-cli limit 192.168.1.102   # rate limit (2 Mbps down / 1 Mbps up)
./bin/netcut-cli alerts          # security alerts with evidence
```

### 5. Scheduled example (kids offline 22:00–07:00)

Policies tab → Scheduled quarantines → pick device, `22:00 → 07:00` → Add schedule.
Or API:

```bash
curl -X POST http://localhost:8080/api/v1/schedules \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"<id>","start_hour":22,"start_min":0,"end_hour":7,"end_min":0,"action":"quarantine"}'
```

### 6. Alert webhook (phone notification)

Alerts tab → add a Discord/Slack/ntfy URL with severity filter → Test.

### 7. Docker Deployment

```bash
docker compose up -d --build
```

---

## Safety notes

- Deploy only on networks you own or administer.
- `l2_arp` causes a real outage on the target — use short TTLs; release heals
  caches automatically (~5s announcement burst + TTL rollback).
- The gateway, DNS/DHCP, and controller IPs in the allowlist can never be
  cut — by hand, policy, schedule, or auto-defense.
- No packet payloads are collected: flow counters, ARP/DHCP metadata, and
  service advertisements only.

---

## Author & Maintainer

- **Author**: **Dimpal Sharma**
- **Role**: DevOps Engineer
- **Email**: [dimplshrm111@gmail.com](mailto:dimplshrm111@gmail.com)
- **LinkedIn**: [sharmadimpal](https://www.linkedin.com/in/sharmadimpal/)
- **Phone / WhatsApp**: [+91 7976327138](tel:+917976327138)
- **GitHub**: [@iamkumar111](https://github.com/iamkumar111)

---

## License

This project is open-source software licensed under the **[MIT License](LICENSE)**.
Copyright (c) 2026 Dimpal Sharma.

