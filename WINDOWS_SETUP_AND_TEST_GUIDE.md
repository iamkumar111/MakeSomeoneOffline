# Open-NetCut on Windows: Setup and Test Guide

This guide covers running Open-NetCut on **Windows 10 / 11 (64-bit)** — dashboard, discovery,
dry-runs, and the new **live side-host ARP quarantine** (`windows_sidehost` adapter).

> [!IMPORTANT]
> ARP quarantine is disruptive by design and can look like an attack to
> security software. Use it **only on networks you own or have explicit
> written permission to test**. Start with dry-runs and short TTLs.

---

## 1. Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 10 / 11 x64 (physical LAN preferred; VMs need bridged networking) |
| **Privileges** | Administrator (elevated PowerShell) for live cuts; normal user is fine for dashboard + dry-run |
| **Packet driver** | [Npcap](https://npcap.com/) (required for live ARP cuts) |
| **IP forwarding** | Must be **OFF** (`IPEnableRouter=0`) on the enforcement host |
| **Build tools** | Go 1.25+ and Node.js 18+ (only if building from source) |
| **Browser** | Any modern browser for `http://localhost:8080` |

---

## 2. Install Npcap

1. Download the Npcap installer from `https://npcap.com/#download`.
2. Run the installer as Administrator.
3. Recommended options:
   - Install Npcap in WinPcap API-compatible Mode (lets tooling find `wpcap.dll`)
   - Restrict Npcap driver's access to Administrators only (safer default)
4. Verify the driver service exists:

```powershell
sc query npcap
```

Expected: `STATE : 4 RUNNING` (or at least present; it starts on demand).

---

## 3. Disable IP Forwarding

The side-host cut works by attracting victim traffic and **not forwarding it**.
If forwarding is on, this PC becomes a router and the cut silently fails —
the adapter refuses to cut in that state.

Check:

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter
```

- `0x0` — correct (forwarding OFF).
- `0x1` — forwarding ON. Disable it:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name IPEnableRouter -Value 0
```

Then **reboot** so the stack picks it up, and re-check.

---

## 4. Get the Binaries

### Option A: Build on Windows

```powershell
npm --prefix web run build
go build -o open-netcut-windows-amd64.exe ./cmd/control-plane
go build -o win-tool.exe ./cmd/win-tool
```

### Option B: Use a cross-compiled build

From Linux/macOS:

```bash
npm --prefix web run build
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o open-netcut-windows-amd64.exe ./cmd/control-plane
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o win-tool.exe ./cmd/win-tool
```

### Required layout

The backend serves the dashboard from `web/dist`, so keep this structure:

```text
open-netcut-windows-amd64.exe
win-tool.exe
web\dist\
netcut.json          (created on first run with -db)
```

If Windows SmartScreen blocks the unsigned binaries, right-click, Properties, Unblock (or allow them explicitly).

---

## 5. Start the Control Plane

Elevated PowerShell (right-click, Run as Administrator), from the folder above:

```powershell
.\open-netcut-windows-amd64.exe -port 8080 -db .\netcut.json
```

Allow the Windows Firewall prompt for port 8080 if shown.

Open the dashboard:

```text
http://localhost:8080
```

Checklist on first start:

- [ ] Devices tab populates (host + LAN neighbors within ~30 seconds)
- [ ] Quarantine method list shows **`windows_sidehost`**
- [ ] `windows_sidehost` shows **available** (Npcap present + forwarding OFF + elevated)
- [ ] If unavailable, the adapter card states why (missing Npcap, forwarding ON, etc.)

> Non-elevated runs are fine for browsing, dry-runs, policies, and mock
> mode — but live `windows_sidehost` cuts will be rejected until elevated.

---

## 6. Direct Helper CLI (`win-tool`)

```powershell
# Readiness: admin, Npcap, interface, gateway
.\win-tool.exe doctor

# Neighbor listing
.\win-tool.exe scan
.\win-tool.exe scan --json

# Point at a remote control plane if needed
$env:OPEN_NETCUT_SERVER = "http://192.168.1.10:8080"
```

`doctor` exits `0` only when the host is ready for a live cut; otherwise it
prints exactly what is missing and exits `2`. It now also checks that the
gateway MAC is already in the ARP cache — a missing entry guarantees a
refused cut later, so `ping` the gateway once if `gateway_mac` is empty.

### 6b. Pre-flight Npcap probe (do this before any live cut)

```powershell
.\win-tool.exe probe
```

This enumerates Npcap devices, selects the LAN interface, resolves your MAC,
and opens + closes the capture handle — **without sending any packet**.
Expected: `"ok": true` with your device/IP/MAC. If it fails, stop here and
report the error: a live cut would fail the same way, but louder.

### 6c. Multi-homed hosts (VM/VPN adapters present)

Device selection is automatic: `NETCUT_WIN_IFACE` override → gateway's /24 →
first private IPv4 → fallback. If `probe` shows the wrong NIC, pin it:

```powershell
# NPF name fragment or the interface IPv4 both work
$env:NETCUT_WIN_IFACE = "Wi-Fi"
.\win-tool.exe probe
```

---

## 7. Test Plan (do this in order)

### Test 1 — Dry-run (no packets touched)

```powershell
.\win-tool.exe cut 192.168.1.50 --ttl 120 --dry-run
```

- [ ] Command succeeds and reports the cut.
- [ ] Victim internet still works (dry-run must never block).
- [ ] Quarantine tab shows the enforcement with `dry_run: yes`.
- [ ] A subsequent **real** cut is NOT blocked by the dry-run record.

### Test 1b — Confirm the dashboard build

The sidebar footer shows a `UI <timestamp>` stamp. It must match the binary
you deployed — a stale `web\dist` next to a fresh EXE shows old behavior
with no error. After copying new files, hard-refresh the browser (`Ctrl+F5`)
and check the stamp before testing.

### Test 2 — Short live cut + manual heal

```powershell
.\win-tool.exe cut 192.168.1.50 --ttl 300
```

- [ ] Victim loses internet within a few seconds
 (`ping 8.8.8.8` and browsing fail on the victim).
- [ ] Dashboard (opened from your own, excluded workstation) keeps working.
- [ ] Quarantine tab shows applied, `dry_run: no`, no error.

Then release:

```powershell
.\win-tool.exe heal 192.168.1.50
```

- [ ] Victim recovers within seconds, no reboot/reconnect needed.
- [ ] Enforcement disappears from the Quarantine tab.

### Test 3 — TTL auto-release

```powershell
.\win-tool.exe cut 192.168.1.50 --ttl 60
```

- [ ] Victim is cut, then comes back on its own after about 60 seconds.
- [ ] No enforcement remains; no manual heal needed.

### Test 4 — Freeze (whole LAN)

Dashboard: **Block All Internet** (short reason required).

- [ ] `FREEZE ON (N cuts)` badge shows the live cut count.
- [ ] Every non-excluded device loses internet; excluded operator stays online.
- [ ] **Unblock All** restores everyone; badge clears; `active_cuts` returns to 0.

### Test 5 — Failure visibility

- Run `win-tool cut` without elevation: must be **rejected with a clear
 administrator message**, not a silent no-op.
- Enable IP forwarding temporarily: cut must be **refused** with the forwarding message.
- Stop Npcap: adapter shows unavailable.

### Test 6 — Dual-stack (IPv6) cut

On a dual-stack victim, cut and then check **both** stacks:

```powershell
# on the victim: IPv4 should fail, and IPv6 too (ping -6)
ping 8.8.8.8
ping -6 2001:4860:4860::8888
```

- [ ] Both fail while cut; both recover after `heal`.
- [ ] If IPv6 stays up, capture `netsh interface ipv6 show neighbors` on the
 enforcement host before/during the cut and report it — NDP pairing depends
 on neighbor-cache visibility.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `windows_sidehost` unavailable | Npcap missing | Install Npcap, re-run elevated |
| Cut rejected: administrator required | Normal PowerShell | Run as Administrator |
| Cut rejected: forwarding ON | `IPEnableRouter=0x1` | Set to `0`, reboot, re-check |
| Cut rejected: gateway unresolvable | No default route / VPN active | Disconnect VPN, ensure DHCP gateway reachable |
| Cut hits the wrong network | VM/VPN adapter auto-selected | Set `$env:NETCUT_WIN_IFACE`, re-run `probe` |
| `doctor` not ready: `gateway_mac` empty | Gateway not in ARP cache yet | `ping` the gateway once, re-run `doctor` |
| Victim unaffected | AP/client isolation, DAI/port-security switch, static ARP entry, or VPN on victim | Use an unmanaged switch/AP without isolation for the lab |
| Victim reachable over IPv6 only | **Known limitation:** Windows adapter currently poisons ARP (IPv4) only; NDP spoofing is not implemented yet | Test IPv4, or force victim to IPv4 for the lab |
| Dashboard blank | `web\dist` missing next to the EXE | Rebuild web assets and keep the folder layout from section 4 |
| Port already in use | Old instance still running | Stop it first, then start |

---

## 9. Safety Rules for Live Tests

1. **Own network only** (or explicit written permission).
2. Always set a **TTL** — never an indefinite cut during testing.
3. Keep your operator workstation **excluded** (pick it in the Freeze dialog
 if you opened the dashboard via localhost).
4. Gateway, DNS, and controller hosts are allowlisted — use break-glass only
 for deliberate drills with a written reason.
5. After every test, confirm the Quarantine tab is empty and every device is back online.

---

## 10. Known Limitations (Windows, current build)

- IPv4 ARP + IPv6 NDP quarantine are both implemented; NDP pairing needs lab
 validation on real dual-stack victims (Test 6 below).
- No per-device traffic shaping on Windows (Linux `tc` gateway only).
- No WinDivert drop stage yet — drops rely on forwarding being OFF so attracted traffic dies on this host.
- Binaries are unsigned — expect SmartScreen/AV prompts; allowlist explicitly instead of disabling security products.
