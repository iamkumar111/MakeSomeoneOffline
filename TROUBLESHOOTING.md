# Troubleshooting: Linux, Windows, and macOS

## Preserve current and older logs

- **Download troubleshooting logs** in the dashboard saves the latest 500 browser
  entries, including older visits on the same browser origin: button clicks,
  API status/duration/request ID, timeouts, and JavaScript error locations.
  Repeated successful polling is omitted. Download before clearing site data;
  private browsing and storage limits can remove history.
- Server logs append across restarts in `logs/control-plane.log`. Rotation retains
  three older files (`.1` newest through `.3` oldest), about 5 MiB each. Save all
  four before reproducing. Change the folder with `-log-dir <writable-folder>`.
- Export **Audit CSV** for action reasons and adapter failures. Match a browser
  `request_id` to server `request_start` / `request_end`. Times are UTC. Include
  OS, time, action, adapter, Dry Run, TTL, target IP and observed result.
- Requests do not log bodies, authorization headers, cookies or query strings.
  Logs may contain LAN/device details and button labels. Review before sharing.
  Runtime logs are ignored by Git and are not pushed to GitHub.

Logs from before this feature cannot be recreated. Preserve existing terminal
captures and Windows event logs. Historical errors below are the actual reported
messages, not fabricated records of earlier runs.

## Any button appears unresponsive

1. Destructive confirmation buttons need **two clicks**, within five seconds.
   Disabled buttons may need a selection or be awaiting a request. Quarantine
   opens a dialog before calling the API.
2. Download browser logs; open browser **Developer Tools → Console and Network**.
   If the dashboard cannot load, use Developer Tools directly.
3. `button_click` without `request_started`: local tabs/dialogs/confirmations may
   not call the API. For a confirmed action that should, inspect Console. Missing
   click entries can mean an overlay or disabled control prevented the click.
4. A started request without completion: check Network and server logs. After
   30 seconds without response headers, the dashboard aborts and shows an error.
   **The server action may still finish.** Check Enforcements/Audit before retrying.
5. Match failed requests by request ID and inspect their response and Audit.
   HTTP 200 means a response arrived, not that a device is isolated. For unchanged
   UI after success, inspect Devices/Enforcements responses and refresh once.

This applies to quarantine/restore, refresh, rename, alerts, policies, freeze,
allowlists, schedules, webhooks, cameras and exports. Image, WebSocket and
browser-managed download requests also need Developer Tools inspection; they
do not all pass through the dashboard's fetch logger.

## Known cases

| Symptom / log | Next check |
|---|---|
| Windows: `An Application Control policy has blocked this file` | App never started, so no server log exists. Preserve Code Integrity event 3077/AppLocker logs. Use approved signed binaries or an approved development PC; ask the Intune policy owner. Administrator/Unblock do not override policy. |
| Windows: `refusing cut: no interface found with IP 192.168.1.24` (historical) | Update/rebuild. `win-tool probe` must select your PC's LAN IP, not the target's IP. Compare candidates with `ipconfig`, gateway/subnet, VPN routes, Npcap and DHCP changes. |
| Npcap/DLL missing or blocked | Install official Npcap; restart server; check service and system/Npcap DLL paths. Do not copy DLLs into the app directory. |
| Permission denied / Administrator required | Elevate the Windows server for live cuts. Linux enforcement needs documented root/capabilities. macOS discovery/previews need no sudo. |
| Forwarding enabled / unknown | Side-host cuts require forwarding off. Inspect routing/ICS with the administrator. Unknown state fails closed. Gateway routing differs. |
| Linux nft/tc unavailable or rule failure | Install nftables/iproute2; check capabilities and selected LAN interface. Inspect `nft list table inet open_netcut` read-only; do not flush unrelated rules. |
| macOS BPF adapter offline / live request rejected | Check ENABLE_MACOS_L2_ARP=1, server root privileges, both forwarding settings OFF and physical enN routes. Explicitly select macos_sidehost. Rate limiting remains unavailable. |
| macOS BPF open/ioctl/injection error | Run mac-tool probe (no packets). Check Ethernet link type, permissions/busy descriptors and Wi-Fi driver behavior. Probe success does not prove isolation. |
| macOS partial apply / restoration incomplete | Save Audit/server logs and use Restore. Failed cleanup keeps a visible Restore/TTL owner. Do not repeat quarantine on that target. |
| Missing device / incomplete ARP / gateway MAC missing | Check LAN/guest isolation, macOS local-network permission, VPN and native route/ARP tables. Ping the known gateway once to populate its neighbor entry. |
| Zero quarantined but preview exists | Expected: previews and shaping do not count. Applied live quarantines drive status; duplicate records count as one device. |
| Live cut absent from Devices/filter | Compare device IDs and successful `/api/v1/devices` / `/api/v1/enforcements` responses. Check inventory, stale UI and Console; save request IDs. |
| Restore error / HTTP 500 / still blocked | Save Audit and logs. Windows healing takes about five seconds; failed healing retains retryable state. Check gateway/MAC and remaining Linux rules before retrying. |
| TTL did not restore / process stopped | Timers need the running server. Forced termination may leave poisoned neighbors/kernel rules. Verify target traffic and native state. Linux startup reconciles its own quarantine chains. |
| Applied preview but still online | Expected simulation. Mock/preview results do not prove live enforcement. |
| Still online after live quarantine | Check Dry Run, adapter, subnet, IPv6 and router/switch defenses. Test fresh connections on the target; side-host cuts are not reliable on every LAN. |
| HTTP 401 remotely | Use configured token (browser Basic password or CLI environment). Localhost has no login when Host/peer are loopback and forwarding headers absent. |
| HTTP 403 / untrusted origin | Check Host, Origin, exact `ALLOWED_ORIGIN` and proxy headers. Remote binding needs a token. Keep authentication/origin checks enabled. |
| HTTP 400/404/405/413 | Inspect validation, path, method and body size in Network. TTL: 0–30 days; body limit: 1 MiB. |
| Timeout / connection refused / network error | Check server terminal, listener, port, proxy and firewall. A timeout does not prove cancellation; inspect current state before retrying. |
| Blank dashboard / missing/stale assets | Build `web/dist`, start from repo root, inspect asset 404s/Console, then hard-refresh. Browser logs cannot initialize if scripts fail to load. |
| WebSocket disconnected / stale updates | Check WS requests, proxy upgrade support, origin/token and server logs. Refresh API data; do not assume a cut was removed. |
| Rename/freeze/policy/allowlist/schedule/webhook fails | Check selection, confirmation, form validation, HTTP result and Audit. Verify current state before repeating destructive actions. |
| Camera blank / rejected response | Check reachability and image type. Redirects/HTML are intentionally rejected. Keep camera credentials out of reports. |
| Missing server logs / unwritable folder / disk full | Check `-log-dir`, permissions and space. Startup reports open failure; later write failures stay on the terminal. Preserve that output. |
| Browser history missing / export fails | Cleared site data, private browsing or storage limits may remove history. Current visit retains a memory fallback; use Console/Network and server/Audit logs. |

## Read-only reports

Windows, when scripts are permitted:

```powershell
.\scripts\Windows-Diagnostics.ps1 -OutputPath .\windows-diagnostics.json
Get-Content .\logs\control-plane.log -Tail 100
Select-String -Path .\logs\control-plane.log* -SimpleMatch 'REQUEST-ID-HERE'
```

Linux/macOS, from the repo root:

```sh
sh scripts/collect-diagnostics.sh > platform-diagnostics.txt 2>&1
tail -n 100 logs/control-plane.log
grep -F 'REQUEST-ID-HERE' logs/control-plane.log*
```

The collectors do not change firewall/routing/security policy. Linux rule reads
may need privileges; permission errors are included. Setup guides:
[Windows](WINDOWS_SETUP_AND_TEST_GUIDE.md), [macOS](MACOS_SETUP_AND_TEST_GUIDE.md),
[Linux](README.md).

## Verify logging without cutting a device

Start the updated server, click Refresh and download browser logs. Check clicks,
initial API requests and matching server request IDs. Restart server/reload page:
old entries should remain. In Developer Tools, set Network to Offline, click
Refresh, then return Online: a visible error and `request_failed` should appear.
Preserve logs before clearing site data. Live quarantine is not needed for this test.
