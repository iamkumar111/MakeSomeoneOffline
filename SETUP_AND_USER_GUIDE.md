# Open-NetCut: Complete Setup and User Guide

This guide provides end-to-end instructions for deploying, configuring, and operating **Open-NetCut**, covering every deployment mode, CLI tool, REST API endpoint, UI workflow, and real-world use case with concrete examples.

---

## 1. System Requirements & Prerequisites

> [!IMPORTANT]
> **Strictly Linux Only**: Open-NetCut is built exclusively for the **Linux kernel** and cannot run natively on Windows or macOS. It directly relies on low-level Linux subsystems:
> - **Raw Packet Sockets (`AF_PACKET`, `SOCK_RAW`)** for wire-level ARP/NDP discovery and Layer 2 frames.
> - **Kernel Netfilter (`nftables`)** for multi-chain drop rules and byte/packet accounting.
> - **Traffic Control (`tc` / `iproute2`)** HTB token buckets for per-device bandwidth rate-limiting.
> - **Sysfs & Netlink (`/sys/class/net`, `/proc/net/arp`)** for physical interface filtering and neighbor tables.

### 1.1 Supported Linux Flavors & Distributions

Open-NetCut is tested and supported across all major Linux distributions (Kernel 5.4 or higher):

| Linux Flavor / Family | Supported Distributions & Versions | Default Package Manager | Prerequisite Install Command |
|---|---|---|---|
| **Debian / Ubuntu Family** | Ubuntu 20.04, 22.04, 24.04 LTS<br>Debian 11 (Bullseye), 12 (Bookworm)<br>Kali Linux 2023.x, 2024.x<br>Linux Mint 21+, Pop!_OS 22.04+ | `apt` | `sudo apt update && sudo apt install -y nftables iproute2` |
| **Arch Family** | Arch Linux (Rolling)<br>Manjaro (Rolling)<br>EndeavourOS | `pacman` | `sudo pacman -Sy --noconfirm nftables iproute2` |
| **Red Hat / Fedora Family** | Fedora 38, 39, 40+<br>RHEL 8.x, 9.x<br>Rocky Linux 8/9, AlmaLinux 8/9<br>CentOS Stream 9 | `dnf` | `sudo dnf install -y nftables iproute` |
| **Alpine Linux** | Alpine 3.18, 3.19, 3.20+ (Ideal for lightweight Docker/containers) | `apk` | `apk add --no-cache nftables iproute2` |
| **OpenWrt / Embedded** | OpenWrt 21.02, 22.03, 23.05+ (MIPS, ARM, x86_64 routers) | `opkg` | `opkg update && opkg install nftables ip-full` |
| **Raspberry Pi OS** | Bullseye, Bookworm (Raspberry Pi 3, 4, 5, Compute Module 4) | `apt` | `sudo apt update && sudo apt install -y nftables iproute2` |
| **openSUSE Family** | openSUSE Leap 15.5+, openSUSE Tumbleweed | `zypper` | `sudo zypper install -y nftables iproute2` |

### 1.2 Running from Windows or macOS

If your daily workstation runs Windows or macOS, you **cannot** run Open-NetCut directly in PowerShell or Terminal.
- **Windows Subsystem for Linux (WSL2)**: WSL2 operates behind a virtual Hyper-V NAT switch. It cannot bind raw Layer 2 packets to your physical home Wi-Fi/Ethernet interface.
- **Docker Desktop (Mac/Windows)**: Uses a lightweight VM with internal virtual NAT bridges, hiding the host's actual LAN broadcast domain.
- **Working Solution**: Run Open-NetCut inside a Linux Virtual Machine (such as **VirtualBox**, **VMware Workstation/Fusion**, or **UTM**) with the network adapter set to **Bridged Adapter** attached directly to your physical Ethernet or Wi-Fi card. This grants the Linux guest direct Layer 2 access to your physical LAN.

### 1.3 Hardware & Kernel Capabilities

| Requirement | Specification |
|---|---|
| **CPU Architecture** | `amd64` (x86_64), `arm64` (aarch64), `armv7l`, or `mips`/`mipsel` |
| **Memory** | 64 MB minimum (embedded), 256 MB recommended |
| **Privileges** | `root` or Linux capabilities: `CAP_NET_ADMIN` and `CAP_NET_RAW` |
| **Go Toolchain** | Go 1.22+ (to compile from source) |
| **Node.js** | Node.js 18+ and npm (to build the web dashboard) |

---

## 2. Installation & Setup

### Option A: Direct Build from Source (Recommended)

1. **Clone and build**:
   ```bash
   git clone https://github.com/open-netcut/open-netcut.git
   cd open-netcut

   # Compile frontend dashboard and all Go binaries into ./bin/
   make build
   ```
   This generates:
   - `bin/control-plane`: Core API, background engines, web server
   - `bin/netcut-cli`: Headless management CLI
   - `bin/sim-lab`: Lab traffic and attack injector

2. **Verify tests**:
   ```bash
   make test
   ```

---

### Option B: Choosing Your Deployment Mode

#### Mode 1: Linux Gateway Mode (★ Recommended)
Use this when Open-NetCut runs directly on the machine acting as the router/gateway (e.g., a home Linux router, OpenWrt x86 box, or multi-NIC server):
```bash
sudo ./bin/control-plane -port 8080 -db ./netcut.json
```
- **How it works**: Uses `linux_nftables` and `linux_tc`. Packets are dropped or shaped natively in the kernel.
- **Impact**: Zero broadcast pollution, perfectly quiet, drops both IPv4 and IPv6.

#### Mode 2: Side-Host Mode (Unmanaged ISP Router / Switch)
Use this when Open-NetCut runs on a normal PC, laptop, or Raspberry Pi connected to an unmanaged home router:
```bash
sudo ENABLE_L2_ARP=1 ./bin/control-plane -port 8080 -db ./netcut.json
```
- **How it works**: Uses raw sockets (`l2_arp`) to redirect target traffic through this host, then drops it via `nftables` or kernel routing.
- **Safety**: Requires explicit opt-in via `ENABLE_L2_ARP=1`. Automatically heals ARP caches with 20 consecutive bursts of genuine-MAC frames when quarantine is removed.

#### Mode 3: Docker Deployment
Using `docker-compose.yml`:
```yaml
services:
  control-plane:
    build:
      context: .
      dockerfile: deploy/Dockerfile.control-plane
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: ["-port", "8080", "-db", "/app/netcut.json"]
    environment:
      - PORT=8080
      - SITE_ID=default
    volumes:
      - ./netcut.json:/app/netcut.json
    restart: unless-stopped
```

Deploy with:
```bash
docker compose up -d --build
```
> [!IMPORTANT]
> `network_mode: host` and `cap_add: [NET_ADMIN, NET_RAW]` are **mandatory** in Docker. Without host networking, the container cannot inspect physical LAN interfaces, read kernel ARP/NDP tables, bind raw sockets, or apply kernel nftables drops to LAN client traffic.

---

## 3. Configuration & Environment Variables

| Variable / Flag | Default | Description |
|---|---|---|
| `-port` / `PORT` | `8080` | Port for the HTTP/WebSocket API and Dashboard UI |
| `-db` | `""` (in-memory) | File path for atomic crash-safe JSON database (e.g. `./netcut.json`) |
| `-site` | `default` | Multi-tenant site identifier |
| `-scanner` | `true` | Enables background ARP, mDNS, SSDP, and DHCP listeners |
| `ENABLE_L2_ARP` | `0` | Set to `1` to enable the side-host L2 ARP adapter |
| `TC_IFACE` | `eth0` | Network interface used by `linux_tc` for rate limiting |
| `ALLOWED_ORIGIN` | `http://localhost:8080` | Allowed origin header for CORS |
| `TRUSTED_DHCP` | Gateway IP | Comma-separated list of legitimate DHCP server IPs |
| `TRUSTED_IPV6_ROUTERS`| `""` | Comma-separated list of legitimate IPv6 router MACs |
| `DISABLE_AUTO_REMEDIATION` | `0` | Set to `1` to disable automatic quarantine on critical alerts |

---

## 4. Web Dashboard Walkthrough

Once running, navigate to `http://localhost:8080` (or `http://<LAN-IP>:8080`) in your browser.

The navigation bar contains 8 dedicated views and a live top bar:
- **Top Bar**: Shows authoritative gateway IP and MAC, current LAN bandwidth throughput, and live connection status.
- **Dashboard Tab**:
  - Total devices, online count, quarantined count, active enforcements, and active alerts.
  - Gateway throughput (Rx/Tx Mbps) and Top Talkers widget.
- **Devices Tab**:
  - Live table of discovered devices with real names, IP, MAC, Vendor, Trust State, and Risk Score.
  - Quick Actions: **Rename** (permanent rank 5), **Set Trust** (`trusted`, `restricted`, `unknown`), **Quarantine**, and **Rate Limit**.
- **Traffic Tab**:
  - Sortable Top Talkers table by real-time Rx/Tx rates and cumulative bytes.
  - Per-IP accounting source indicator (`nft-accounting`, `nf_conntrack`, or interface totals).
- **Alerts Tab**:
  - Threat cards for detected network anomalies with timestamped cryptographic evidence chains.
  - **Acknowledge** button to mark alerts as addressed.
- **Audit Tab**:
  - Searchable audit log of all system actions, operator modifications, and safety rejections.
  - **Export CSV** button for compliance archiving.
- **Policies Tab**:
  - **WHEN/THEN Rule Builder**: Automate actions based on IP, MAC, Trust State, or Risk Score with description rationale.
  - **Scheduled Quarantines**: Configure recurring time windows (e.g., bedtime blocks).
  - **Webhooks**: Configure Discord, Slack, or ntfy notification targets with test dispatch button.
- **Quarantine Tab**:
  - Live table of all active enforcements with Target IP, Target MAC, Adapter, Action, countdown TTL, and any error indicators.
  - **Lift Quarantine** button with inline 2-click confirm protection.
  - **Emergency Freeze Network Latch**: Modal to initiate whole-LAN lockdown with self-exclusion controls and real-time active cuts indicator.
- **Cameras Tab**:
  - Discovered IP cameras and NVRs (Hikvision, Dahua, Xiongmai, Axis).
  - Anonymous snapshot probe tester and proxied live camera still viewer.
  - Copy RTSP stream URL helper for VLC/OBS.

---

## 5. Headless Admin CLI (`netcut-cli`)

For headless servers, scripts, or SSH sessions, use `bin/netcut-cli`:

```bash
# 1. View overall health and threat overview
./bin/netcut-cli status

# 2. List all discovered devices
./bin/netcut-cli devices

# 3. Quarantine a device by IP or MAC (15-minute default TTL)
./bin/netcut-cli cut 192.168.1.102

# 4. Quarantine with custom adapter and TTL (e.g. 1 hour = 3600s)
./bin/netcut-cli cut 192.168.1.102 --adapter linux_nftables --ttl 3600

# 5. Restore network access immediately
./bin/netcut-cli restore 192.168.1.102

# 6. Apply bandwidth rate limit (Download 5 Mbps / Upload 2 Mbps)
./bin/netcut-cli limit 192.168.1.102 5000000 2000000

# 7. View active security alerts and attack evidence
./bin/netcut-cli alerts
```

---

## 6. Comprehensive Use Cases & Practical Examples

### Use Case 1: Gateway Native Quarantine (Surgical Block with TTL)
**Scenario**: You manage a Linux gateway router. A guest device (`192.168.1.75`) is misbehaving and needs to be isolated for 30 minutes without affecting other LAN users.

#### Via CLI:
```bash
./bin/netcut-cli cut 192.168.1.75 --adapter linux_nftables --ttl 1800
```

#### Via REST API:
```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.1.75/quarantine \
  -H "Content-Type: application/json" \
  -d '{
    "adapter": "linux_nftables",
    "ttl_seconds": 1800,
    "dry_run": false
  }'
```

*What happens in the background*:
1. `linux_nftables` inserts drop rules into table `open_netcut` on chains `forward` and `input`.
2. The device cannot reach the internet or other LAN devices.
3. The background `ttlWorker` runs every 5 seconds. At 1800 seconds, it removes only these drop rules and publishes `enforcement.removed`.

---

### Use Case 2: Side-Host Quarantine on an Unmanaged Switch (L2 ARP Mode)
**Scenario**: You are running Open-NetCut on a side laptop or Raspberry Pi on an unmanaged home ISP router. A rogue device at `192.168.1.150` (`MAC: a4:c3:f0:12:34:56`) must be quarantined.

1. Start Open-NetCut with `ENABLE_L2_ARP=1`:
   ```bash
   sudo ENABLE_L2_ARP=1 ./bin/control-plane -port 8080 -db ./netcut.json
   ```
2. Trigger the quarantine by MAC:
   ```bash
   curl -X POST http://localhost:8080/api/v1/devices/a4:c3:f0:12:34:56/quarantine \
     -H "Content-Type: application/json" \
     -d '{
       "adapter": "l2_arp",
       "ttl_seconds": 600,
       "dry_run": false
     }'
   ```
3. Lift the quarantine early:
   ```bash
   curl -X DELETE http://localhost:8080/api/v1/devices/a4:c3:f0:12:34:56/quarantine
   ```

*What happens in the background*:
- While active: sends ARP requests and replies every 350ms redirecting victim traffic to your machine, accompanied by IPv6 NDP announcements.
- Upon release: `healingFrames` transmits 20 rounds of genuine-MAC frames to both the victim and the gateway, restoring connectivity within seconds without needing a device reboot.

---

### Use Case 3: Bandwidth Shaping & Throttling
**Scenario**: A smart TV or workstation (`192.168.1.88`) is saturating your uplink with backups. Throttle it to **2 Mbps download** and **1 Mbps upload** for 2 hours.

#### Via CLI:
```bash
./bin/netcut-cli limit 192.168.1.88 2000000 1000000
```

#### Via REST API (Accepts PUT or POST):
```bash
curl -X PUT http://localhost:8080/api/v1/devices/192.168.1.88/rate-limit \
  -H "Content-Type: application/json" \
  -d '{
    "adapter": "linux_tc",
    "download_bps": 2000000,
    "upload_bps": 1000000,
    "ttl_seconds": 7200,
    "dry_run": false
  }'
```

*What happens in the background*:
- `linux_tc` creates an HTB class on interface `TC_IFACE` and attaches a `u32` filter matching IP `192.168.1.88`.
- The device remains connected, but speeds are capped at 2 Mbps / 1 Mbps.

---

### Use Case 4: Nightly Parental Access Schedule (Bedtime Lockdown)
**Scenario**: Automatically cut network access for a kid's gaming console or tablet (`device_id: d-xyz123`) every night from **22:00 to 07:00 (10 PM to 7 AM)**.

#### Create the Schedule via API:
```bash
curl -X POST http://localhost:8080/api/v1/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "d-xyz123",
    "days": [1, 2, 3, 4, 5, 6, 0],
    "start_hour": 22,
    "start_min": 0,
    "end_hour": 7,
    "end_min": 0,
    "action": "quarantine",
    "ttl_seconds": 0
  }'
```

*TTL and Schedule Window Interactions*:
- **When `ttl_seconds: 0` (or omitted)**: The enforcement remains active for the full duration of the schedule window. When the window ends at 07:00, `ScheduleManager` automatically rolls it back.
- **When `ttl_seconds > 0`**: The enforcement expires when the TTL elapses, even if the schedule window is still open.
- Handles midnight wrap-around cleanly (`currentMinutes >= 22*60 || currentMinutes < 7*60`).

---

### Use Case 5: Automated Zero-Trust Policy for Unknown Devices
**Scenario**: Any new or unapproved device connecting to your network (Trust State: `unknown`) should be automatically rate-limited or quarantined until verified.

#### Create the Policy Rule:
```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Zero-Trust Unknown Devices",
    "description": "Quarantine unknown devices until approved by administrator",
    "enabled": true,
    "priority": 10,
    "selector": {
      "trust_state": "unknown"
    },
    "action": {
      "type": "quarantine"
    },
    "ttl": 3600000000000
  }'
```

*Understanding Policy TTL vs REST API TTL*:
- In policy models, `ttl` is represented as a Go duration in nanoseconds (`3600000000000` = 1 hour).
- If `ttl <= 0`, the policy engine falls back to `DefaultPolicyTTL` (15 minutes).
- Every 60 seconds, `Evaluator.EvaluateOnce()` matches online devices. A completely empty selector matches nothing (preventing accidental full-subnet locks).
- When you click **Trust** in the dashboard, the device moves to `trusted`, and the rule ceases firing.

---

### Use Case 6: Emergency Whole-LAN Lockdown (Freeze Latch)
**Scenario**: You detect active ransomware or unauthorized lateral movement on your LAN. You need to immediately cut network access to **every device except your own workstation**, and ensure any newcomer is cut immediately.

#### Correct API Request Shape:
```bash
curl -X POST http://localhost:8080/api/v1/freeze \
  -H "Content-Type: application/json" \
  -d '{
    "adapter": "linux_nftables",
    "ttl_seconds": 1800,
    "reason": "Ransomware outbreak investigation",
    "dry_run": false,
    "include_self": false,
    "self_ip": "192.168.1.50",
    "self_mac": "3c:06:30:44:55:66"
  }'
```

#### Asynchronous Execution & HTTP Status Codes:
- **`202 Accepted`**: Because cutting 20+ devices sequentially takes time, the bulk enforcement runs in a background goroutine to avoid HTTP client timeouts. The API immediately responds:
  ```json
  {
    "status": "freezing",
    "latch": true,
    "self_ip": "192.168.1.50",
    "self_cut": false,
    "self_warning": ""
  }
  ```
- **`409 Conflict` (`status: "already_frozen"`)**: If a freeze is already active, initiating another POST is rejected. You must lift the freeze via `DELETE /api/v1/freeze` before starting a new run.
- **`409 Conflict` (`"a freeze/unfreeze operation is already running..."`)**: Returned if a background action is currently in progress.

#### Important Self-Exclusion Warning (Localhost vs LAN IP):
> [!WARNING]
> When accessing the dashboard via `http://localhost:8080`, your connection peer is `127.0.0.1` or `::1`. Calling `/api/v1/whoami` returns `{"ip": "127.0.0.1"}`, which does **not** map to your physical LAN NIC (`192.168.1.x`).
> If you omit `self_ip` and `self_mac` while on localhost, Open-NetCut will exclude `127.0.0.1` and **your physical LAN interface will be cut**!
> **Solution**: Either access the dashboard using your LAN IP (`http://192.168.1.50:8080`), or explicitly pass `self_ip` and `self_mac` in the request.

#### Freeze Scope on Release (`DELETE /api/v1/freeze`):
- Lifting a freeze executes `fc.Deactivate()`, which unlatches the newcomer trap and calls `fc.LiftAll()`.
- **Scope**: Lifts **every active quarantine across the network**, including manual quarantines.
- Returns `202 Accepted` with `{"status": "unfreezing"}` while removals process in the background. If already released, returns HTTP 200 with `{"status": "already_released"}`.

#### Freeze Lifecycle Across Process Restarts:
> [!NOTE]
> On daemon restart:
> 1. `reconcileQuarantineChains` flushes all existing kernel drop rules to prevent orphaned zombie blocks.
> 2. Active enforcements are intentionally **not** restored from disk.
> 3. `FreezeController.Restore` restores **only the latch state** (`active: true`, reason, adapter, TTL).
> 4. Therefore, devices already connected at restart are **not** retroactively dropped until a new sighting event occurs (`device.seen` / `device.updated`). The latch strictly intercepts newcomers and newly online devices. If you want to re-freeze all existing devices after a restart, trigger a fresh freeze request.

---

### Use Case 7: Threat Detection & Auto-Remediation (MITM / ARP Spoof Defense)
**Scenario**: An attacker on your WiFi (`192.168.1.99`, `MAC: de:ad:be:ef:13:37`) attempts an ARP spoofing attack, announcing itself as the default gateway (`192.168.1.1`).

*What Open-NetCut does automatically*:
1. The `DetectionEngine` flags a **CRITICAL: Gateway Impersonation** alert.
2. An `alert.created` event is published to the monotonic EventBus.
3. The `AutoRemediationEngine` catches the critical alert and quarantines `de:ad:be:ef:13:37` immediately for 10 minutes (600s default TTL).
4. The `AlertDispatcher` dispatches a webhook notification to your phone.

To test this safely in a lab without real attack tools, use the bundled simulator:
```bash
./bin/sim-lab -scenario arp-spoof -url http://localhost:8080
```

---

### Use Case 8: External Phone Notifications via Webhook (Discord / Slack / ntfy)
**Scenario**: Receive push notifications on your phone whenever a critical security threat or gateway spoof is detected.

#### Register an `ntfy.sh` Webhook:
```bash
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phone Notifications",
    "url": "https://ntfy.sh/my-private-netcut-alerts",
    "min_severity": "high",
    "enabled": true
  }'
```

#### Test a Webhook:
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/<webhook-id>/test
```

---

### Use Case 9: IP Camera & NVR Discovery
**Scenario**: Audit IoT security cameras on your LAN, verify open RTSP video streams, and retrieve anonymous still images without logging in.

1. List discovered cameras:
   ```bash
   curl -s http://localhost:8080/api/v1/cameras | jq .
   ```
2. Probe a camera for public anonymous stills:
   ```bash
   curl -X POST http://localhost:8080/api/v1/cameras/<device-id>/snapshot
   ```
3. View the proxied camera still in your browser:
   ```
   http://localhost:8080/api/v1/cameras/<device-id>/image
   ```
4. Stream in VLC:
   ```bash
   vlc rtsp://192.168.1.120:554/live/ch0
   ```

---

### Use Case 10: Permanent Device Renaming & Inventory Export
**Scenario**: A printer or smart home hub shows up as `Device-192.168.1.45`. You want to assign it a permanent friendly name that survives reboots and export your inventory for an audit.

#### Set a permanent name (Accepts POST or PUT):
```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.1.45/rename \
  -H "Content-Type: application/json" \
  -d '{"name": "Office HP LaserJet Pro"}'
```

#### Clear a custom name:
```bash
curl -X DELETE http://localhost:8080/api/v1/devices/192.168.1.45/rename
```

#### Export inventory and audit logs to CSV:
```bash
curl -s http://localhost:8080/api/v1/export/devices.csv -o devices_inventory.csv
curl -s http://localhost:8080/api/v1/export/audit.csv -o audit_trail.csv
```

---

### Use Case 11: Emergency Break-Glass Override
**Scenario**: Under normal circumstances, Open-NetCut's allowlist protects the default gateway from being quarantined. In a controlled test or decommissioning scenario, an operator needs to intentionally cut the gateway.

A standard quarantine call is rejected:
```bash
./bin/netcut-cli cut 192.168.1.1
# Returns: safety violation: cannot quarantine protected device: Default Gateway IP is protected
```

To execute a deliberate break-glass override:
```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.1.1/quarantine \
  -H "Content-Type: application/json" \
  -d '{
    "adapter": "linux_nftables",
    "ttl_seconds": 300,
    "break_glass": true,
    "reason": "Authorized failover drill DR-2026-10"
  }'
```
> [!IMPORTANT]
> Break-glass requires a non-empty human justification string. Automated rules (scheduler, auto-remediation, evaluator) cannot invoke break-glass and remain strictly prevented from cutting protected infrastructure.

---

## 7. REST API Quick Reference

| Endpoint | Methods | Description |
|---|---|---|
| `/api/v1/whoami` | `GET` | Reports caller's IP as seen by the server and matched device profile |
| `/api/v1/stats` | `GET` | System health, online device counts, and threat level summary |
| `/api/v1/devices` | `GET` | List all discovered devices with IP, MAC, Vendor, and Risk Score |
| `/api/v1/devices/:id` | `GET` | Detailed device profile (`?enriched=true` adds live traffic & alerts) |
| `/api/v1/devices/:id/traffic` | `GET` | Live bandwidth metrics for a specific device |
| `/api/v1/devices/:id/observations` | `GET` | Recent raw discovery observations for a device |
| `/api/v1/devices/:id/rename` | `POST`, `PUT`, `DELETE` | Set or clear permanent manual display name |
| `/api/v1/devices/:id/trust` | `POST`, `PUT` | Update trust state (`trusted`, `restricted`, `unknown`) |
| `/api/v1/devices/:id/quarantine` | `POST`, `DELETE` | Apply or lift network quarantine with TTL |
| `/api/v1/devices/:id/rate-limit` | `POST`, `PUT`, `DELETE` | Apply or lift bandwidth shaping ceiling |
| `/api/v1/traffic` | `GET` | Real-time traffic totals, gateway totals, and per-device Top Talkers |
| `/api/v1/alerts` | `GET` | List active threat alerts with evidence chains |
| `/api/v1/alerts/:id/ack` | `POST` | Acknowledge a security alert |
| `/api/v1/enforcements` | `GET` | List all active enforcements, states, countdown TTLs, and errors |
| `/api/v1/freeze` | `GET`, `POST`, `DELETE` | Read latch state, trigger whole-LAN freeze (202), or unfreeze all (202) |
| `/api/v1/allowlist` | `GET`, `PUT` | Read or update protected infrastructure IPs and MACs |
| `/api/v1/audit` | `GET` | Read system audit log history |
| `/api/v1/observations` | `POST` | Ingest external observation or sensor batch |
| `/api/v1/remediation` | `GET`, `POST` | Read or toggle automatic critical threat remediation |
| `/api/v1/integrations` | `GET` | List ranked adapters (`?action=quarantine` or `?action=rate_limit`) |
| `/api/v1/integrations/:name` | `GET` | Detailed adapter capability and guidance card |
| `/api/v1/policies` | `GET`, `POST` | List or create automated WHEN/THEN policy rules |
| `/api/v1/policies/:id` | `GET`, `PUT`/`PATCH`, `DELETE` | Get, update, or delete a policy rule |
| `/api/v1/schedules` | `GET`, `POST` | List or create scheduled recurring time windows |
| `/api/v1/schedules/:id` | `DELETE` | Remove a schedule and immediately roll back active enforcement |
| `/api/v1/webhooks` | `GET`, `POST` | List or register notification webhook targets |
| `/api/v1/webhooks/:id` | `DELETE` | Remove a webhook endpoint |
| `/api/v1/webhooks/:id/test` | `POST` | Dispatch a test alert notification |
| `/api/v1/cameras` | `GET` | Discovered IP security cameras and NVRs |
| `/api/v1/cameras/:id/snapshot` | `POST` | Probe camera for anonymous snapshot endpoints |
| `/api/v1/cameras/:id/image` | `GET` | Proxied camera image stream (SSRF-protected) |
| `/api/v1/export/devices.csv` | `GET` | Download device inventory as CSV |
| `/api/v1/export/audit.csv` | `GET` | Download tamper-evident audit logs as CSV |
| `/api/v1/events` | `GET` (WS) | Monotonic real-time WebSocket event stream |
| `/api/v1/events/sse` | `GET` (SSE) | Server-Sent Events stream fallback |

---

## 8. Safety & Troubleshooting Guide

### 1. Handling Stale or Failed Enforcement Rules
- **At Startup**: Open-NetCut executes `reconcileQuarantineChains` upon boot, which automatically flushes stale drop rules from table `open_netcut` so no orphan drop rules persist from dead processes.
- **While Running**: If an adapter removal fails during runtime (e.g., an `nft delete rule` error or remnant rule surviving), the enforcement remains visible in the **Quarantine tab** with `actual_state = "applied"` and `error_message` populated.
  - **Resolution**: Open the **Quarantine** tab, inspect the specific error on the card, and click **Lift Quarantine** again. If an underlying network interface was renamed or deleted, manually flush rules using:
    ```bash
    sudo nft list table inet open_netcut
    sudo nft flush table inet open_netcut
    ```

### 2. "I cannot quarantine a specific IP"
- **Cause**: The IP is protected by the management allowlist (Gateway, DNS server, or controller host).
- **Fix**: Check `http://localhost:8080/api/v1/allowlist`. If intentional, use the **Break-Glass** parameter with an audit reason.

### 3. "Bandwidth Top Talkers shows zero bytes"
- **Cause**: The kernel does not have the `nf_conntrack` module loaded.
- **Fix**: Open-NetCut automatically initializes the built-in `NftAccountingPoller`, installing lightweight `counter accept` rules into the `open_netcut` table. Ensure Open-NetCut is running as root or with `CAP_NET_ADMIN`.

### 4. "Side-host L2 ARP mode doesn't block traffic"
- **Cause 1**: IP forwarding is enabled on your side-host, causing it to act as a transparent router.
  - **Resolution**: Disable forwarding: `echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward`
- **Cause 2**: `ENABLE_L2_ARP=1` was omitted on startup. Ensure the daemon was started with:
  ```bash
  sudo ENABLE_L2_ARP=1 ./bin/control-plane -port 8080 -db ./netcut.json
  ```

---

## Author & Maintainer

- **Author**: **Dimpal Sharma**
- **Role**: DevOps Engineer
- **Email**: [dimplshrm111@gmail.com](mailto:dimplshrm111@gmail.com)
- **LinkedIn**: [sharmadimpal](https://www.linkedin.com/in/sharmadimpal/)
- **Phone / WhatsApp**: [+91 7976327138](tel:+917976327138)
- **GitHub**: [@iamkumar111](https://github.com/iamkumar111)

