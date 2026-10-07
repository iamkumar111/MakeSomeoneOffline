# Windows: Quick Setup and Test

Use Windows 11 x64 and a test device on a network you own or administer.

## 1. Download and install

| Download | What to choose | Needed for |
|---|---|---|
| [Npcap](https://npcap.com/#download) | Windows installer; normal or WinPcap-compatible mode | Live quarantine |
| [Go](https://go.dev/dl/) | Windows x64 installer, Go 1.25 or newer | Building the EXEs |
| [Node.js](https://nodejs.org/en/download) | Supported LTS Windows x64 installer, version 22.12 or newer | Building the dashboard; includes npm |

Already have the EXEs and `web/dist`? Skip Go, Node.js, and the build step.
WinDivert is not needed.

**Before testing:** the PC, target device, and gateway must share the same LAN.
Run the server as Administrator. IP forwarding/Internet Connection Sharing must
be off. Windows policy must permit the EXEs and Npcap to run.

## 2. Build (only when using source code)

Open PowerShell in the project folder. Stop the old server first.

```powershell
cd C:\Users\Admin\MakeSomeoneOffline
npm.cmd --prefix web ci
npm.cmd --prefix web run build
go build -o open-netcut-windows-amd64.exe ./cmd/control-plane
go build -o win-tool.exe ./cmd/win-tool
```

If scripts are permitted, `.\scripts\Build-Windows.ps1` runs these steps for you.
Keep `web/dist` in the project folder.

## 3. Check and start

Open PowerShell **as Administrator**, then:

```powershell
cd C:\Users\Admin\MakeSomeoneOffline
.\win-tool.exe probe
.\win-tool.exe doctor
```

Continue only when `probe` shows `ok: true` and `doctor` shows
`ready_for_live_cut: true`. The reported IP must belong to **your PC**, not the
device you want to quarantine. The probe sends no packets.

```powershell
.\open-netcut-windows-amd64.exe -port 8080 -db .\netcut.json
```

Open [the dashboard](http://localhost:8080). Keep the server terminal open.
Localhost needs no token or login. Remote access requires `NETCUT_API_TOKEN`
and an explicit `-listen 0.0.0.0`; use an HTTPS proxy for remote connections.

## 4. Verify the fix

1. Select a separate test device in **Devices**.
2. Click **Quarantine Device** and choose **Windows Side-Host**.
3. Try **Dry Run** first: the target should stay online.
4. Turn Dry Run off and set a **60-second TTL**. Apply quarantine.
5. Check fresh internet connections on the target, including IPv6 if available.
6. Restore it in the dashboard and confirm internet access returns. Repeat once
   and let the TTL expire to check automatic restoration.
   Restoration takes about five seconds. A release error keeps the cut visible
   for retry. The quarantined count tracks unique live devices; previews do not count.

Success: no interface error, target traffic is blocked, then connectivity returns.
An applied status alone does not prove isolation. Keep the server running for TTL
restoration. IPv6 coverage is best effort; Windows traffic shaping is unavailable.

## 5. Common problems

| Problem | What to do |
|---|---|
| **Application Control policy has blocked this file** | The EXE never started. Check Windows Security > App & browser control > Smart App Control settings. Use approved signed binaries or an approved development PC. For Intune devices, ask the policy owner to approve the build. Administrator and Properties > Unblock do not override this policy. |
| **Npcap / wpcap.dll missing** | Install official Npcap, restart the server, and check `sc.exe query npcap`. DLLs load only from the Windows system/Npcap directories. |
| **Administrator required** | Restart the server itself from elevated PowerShell. |
| **Forwarding enabled** | Have the machine administrator disable routing/ICS; recheck after any required reboot. |
| **No local interface / wrong network** | Compare probe candidates with `ipconfig`; check VPN routes and DHCP changes. An override must use your PC's local IP, not the target IP. |
| **Gateway MAC missing** | Ping your actual gateway once, then run `doctor` again. |
| **Blank dashboard / port busy** | Start from the project folder with `web/dist`; stop the known old server or choose another port. |
| **Target still online** | Check Dry Run, adapter choice, IPv6, and router/switch security. Side-host quarantine is not reliable on every LAN. |

Smart App Control has no simple per-app exception. Turning it off affects the
whole PC and may not be easily reversible. [Microsoft guidance](https://learn.microsoft.com/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control).

For a debug report, when scripts are permitted:

```powershell
.\scripts\Windows-Diagnostics.ps1 -OutputPath .\windows-diagnostics.json
```

If scripts are blocked, use the manual commands in [Windows debugging and Intune instructions](WINDOWS_DEBUGGING.md).
That file also covers policy logs, interface overrides, signing, and CLI tests.
