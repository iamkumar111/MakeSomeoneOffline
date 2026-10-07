# Open-NetCut on Windows: setup, prerequisites, debugging, and verification

[Shared troubleshooting](TROUBLESHOOTING.md) covers old errors, retained logs,
request IDs and every dashboard action, including unresponsive buttons.

Native Windows builds support dashboard/discovery, dry-runs, and experimental
`windows_sidehost` quarantine through Npcap. Linux gateway enforcement remains
recommended for reliable blocking and traffic shaping. Use live tests only on
networks and devices you own or administer.

## 1. Prerequisites

| Component | Requirement |
|---|---|
| Windows | Windows 11 x64 recommended. Windows 10 x64 is a legacy test target; choose an OS supported by your organization. |
| LAN | Enforcement PC, target, and IPv4 gateway on the same local subnet. A VM needs a bridged NIC; WSL/Docker NAT is insufficient for this adapter. |
| Elevation | Run the control plane as Administrator for live quarantine. Elevating only the helper does not elevate an already running server. |
| Npcap | Install from [npcap.com](https://npcap.com/#download). Normal and WinPcap-compatible installations are supported. Admin-only driver access is appropriate. |
| Forwarding | `IPEnableRouter` must be zero or absent. This check reads a registry setting, not every possible routing configuration. Verify the PC is not acting as a router/Internet Connection Sharing host. |
| Build tools | Go 1.25+ per `go.mod`. Node compatible with locked Vite/Rolldown: `^20.19.0` or `>=22.12.0`; use a supported Node release satisfying that range. npm is required only when building the dashboard. |
| Windows policy | Both EXEs, Npcap components, and build tools must be permitted by applicable Application Control policies. A successful compile does not imply permission to execute. |
| Files | Start from the repository/release root containing the EXEs and `web/dist/index.html`. |

WinDivert is not required. Windows traffic shaping is not implemented. IPv6 NDP
pairing is best effort and depends on visible neighbor-cache entries; an applied
quarantine record does not prove that all target traffic is blocked.

## 2. Application Control: resolve execution blocks first

If PowerShell reports **An Application Control policy has blocked this file**,
the executable has not started. Rebuilding, Administrator privileges,
`Unblock-File`, and PowerShell execution-policy changes do not override a Code
Integrity policy. Do not rename files or run `go run` as a policy workaround.

Check **Windows Security > App & browser control > Smart App Control settings**.
The `VerifiedAndReputableDesktop` policy in event 3077 identifies Smart App
Control enforcement. An organization policy can also block the same file.

Read-only checks, usable before either EXE can run:

```powershell
cd C:\Users\Admin\MakeSomeoneOffline
.\scripts\Windows-Diagnostics.ps1 -OutputPath .\windows-diagnostics.json
citool.exe -lp
```

If PowerShell itself rejects the script, use your organization's approved script
signing/deployment process, or run these built-in read-only commands individually:

```powershell
Get-ExecutionPolicy -List
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3077} -MaxEvents 10 | Format-List TimeCreated,Message
Get-AuthenticodeSignature .\open-netcut-windows-amd64.exe, .\win-tool.exe
Get-FileHash .\open-netcut-windows-amd64.exe, .\win-tool.exe -Algorithm SHA256
```

Registry values: `0` off, `1` enforcement, `2` evaluation. Missing values are
unknown, not proof that no policy exists. Read event details in **Event Viewer >
Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational**.

For Smart App Control, distribute code signed with an accepted trusted CA
certificate, or verify on an approved development machine where local builds are
permitted. A self-signed certificate is not sufficient for Smart App Control.
Turning Smart App Control off changes protection for the entire PC; Windows
Settings does not provide a simple temporary per-app exception or guaranteed
switch back on. See [Microsoft's signing guidance](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview)
and [testing/mode guidance](https://learn.microsoft.com/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control).

SmartScreen reputation prompts and downloaded-file marks are separate from
Application Control. Properties > Unblock may remove a downloaded-file mark;
it does not fix a 3077 Code Integrity block.

### Intune / organization-managed devices

Have the policy owner review the block event's policy name/GUID, binary SHA256,
signature, Npcap dependencies, and the intended test devices. Intune-managed
App Control for Business approval may use a permitted publisher, a scoped hash
rule, or managed-installer deployment, according to the base policy. Hash rules
must be updated after rebuilding; managed-installer trust is not automatically
applied to existing locally compiled files.

An authorized administrator can deploy an approved supplemental policy through
**Intune admin center > Endpoint security > App Control for Business > App Control
for Business > Create Policy** when the base policy supports supplements. Pilot
on a small test device group and confirm policy delivery and executable startup.
Approval under one policy does not override a denial under another. Smart App
Control and Intune policy are distinct; identify the actual blocking policy.
Follow [Microsoft's Intune App Control documentation](https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/manage-app-control).
The scripts in this repository inspect policy; they do not modify it.

## 3. Install and inspect Npcap

Run the official installer elevated. This build loads `wpcap.dll` only from
the Windows system directory or its Npcap subdirectory, with restricted dependency
search paths. Restart the server after installing Npcap. Do not copy DLLs into
the project directory. Installation details: [Npcap users' guide](https://npcap.com/guide/npcap-users-guide.html).

```powershell
sc.exe query npcap
Test-Path "$env:SystemRoot\System32\wpcap.dll"
Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll"
```

Use `sc.exe`, not `sc` (a PowerShell alias). A stopped service can start on demand;
the `probe` open/close result is the authoritative capture-path check.

Inspect forwarding without changing it:

```powershell
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' /v IPEnableRouter
Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,ConnectionState,Forwarding
```

If this is intentionally a side host and forwarding is enabled, have the machine
administrator disable its routing/ICS configuration. Where appropriate, set the
registry flag to zero, reboot, and verify again:

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Type DWord -Value 0
```

## 4. Build and test source

Stop the previous server with Ctrl+C in its owning terminal before replacing its
EXE. Do not kill an unidentified process using port 8080.

```powershell
cd C:\Users\Admin\MakeSomeoneOffline
go version
node --version
npm.cmd --version
.\scripts\Build-Windows.ps1
go test ./pkg/adapters ./pkg/policy ./pkg/server ./cmd/win-tool
```

For backend-only edits with a current `web/dist`, use
`.\scripts\Build-Windows.ps1 -SkipUI`. Manual equivalent:

```powershell
npm.cmd --prefix web ci
npm.cmd --prefix web run build
go build -o open-netcut-windows-amd64.exe ./cmd/control-plane
go build -o win-tool.exe ./cmd/win-tool
```

`npm.cmd` avoids confusion with an npm PowerShell wrapper. If Go's formatter,
compiler, or temporary `*.test.exe` is blocked, collect its Code Integrity event
and resolve tool approval too. A blocked test executable is not a passed test.
Keep signed release binaries and dashboard assets from the same source revision.
Re-sign binaries after rebuilding if the deployment requires signing.

## 5. Verify the local interface before starting live enforcement

In elevated PowerShell:

```powershell
.\win-tool.exe probe
.\win-tool.exe doctor
```

`probe` sends no packets: it enumerates capture devices, matches their addresses
to active local interfaces, selects the gateway LAN, then opens/closes Npcap.
Expect `ok: true` and the enforcement PC's LAN IP/MAC, not a remote device IP.

`doctor` opens/closes Npcap too, checks elevation, the registry forwarding state,
and gateway IP/MAC, and lists `blockers`. Exit 0 means those host prerequisites
passed; exit 2 means a blocker remains. Readiness does not certify target isolation,
router security behavior, or complete IPv6 coverage. WinDivert status is informational.

If gateway MAC is absent, find the LAN gateway in `ipconfig` and ping it once,
then repeat `doctor`. This is an explicit connectivity check, unlike `probe`:

```powershell
ipconfig
# Example only: replace with your actual gateway.
ping.exe -n 1 192.168.1.1
```

### Multiple adapters or a changed DHCP address

Selection requires a current local IPv4 address and actual subnet membership.
Live quarantine also checks that the target is on the selected LAN. Stale Npcap
addresses and unrelated VM/VPN subnets are excluded. Candidate details are included
in selection errors. The global default gateway may be a VPN gateway; this build
does not resolve an independent per-target gateway.

To pin a candidate, use the enforcement PC's IPv4 address or an NPF GUID/name
fragment from the probe/error output. A friendly name such as `Wi-Fi` generally
does not match Npcap's `\Device\NPF_{GUID}` name.

```powershell
# Example: local enforcement PC address, NOT the quarantine target.
$env:NETCUT_WIN_IFACE = '192.168.1.28'
.\win-tool.exe probe
# Clear a stale override:
Remove-Item Env:NETCUT_WIN_IFACE -ErrorAction SilentlyContinue
```

Set the override in the server's terminal **before** starting the server; a change
in another terminal does not update a running server. An override cannot bypass
local-address/subnet validation. After a DHCP/NIC change, close capture users and
restart Npcap through the approved maintenance process if its addresses remain
stale. Restarting its service affects other capture users.

## 6. Start the server and confirm the dashboard

From the repository root in elevated PowerShell:

```powershell
.\open-netcut-windows-amd64.exe -port 8080 -db .\netcut.json
```

Open [http://localhost:8080](http://localhost:8080). Keep this terminal open.
Localhost needs no token or login. The default listener is `127.0.0.1`.
Remote listening requires `NETCUT_API_TOKEN` and `-listen 0.0.0.0`;
remote clients must authenticate. Use an HTTPS proxy for remote connections.
The server reads `./web/dist` relative to the working directory. A `PORT`
environment variable overrides `-port`; inspect it if the URL differs.
For remote dashboard access, configure only the intended firewall scope and
network access; no firewall exception is needed solely to browse localhost.

Discovery may take time and depends on neighbor-cache visibility. The Windows
adapter appears as `windows_sidehost`; select it explicitly for a live test.
An availability card does not prove elevation or successful packet injection.
After rebuilding, restart the server and hard-refresh the browser (Ctrl+F5).

## 7. Verify discovery, dry-run, quarantine, restore, and TTL

Use a separate test device; replace `192.168.1.24` below with its current IP.
Do not use the gateway or enforcement PC as your test target.

```powershell
.\win-tool.exe scan
.\win-tool.exe cut 192.168.1.24 --ttl 60 --dry-run
```

`scan` reads the ARP cache; it does not populate the server inventory. Confirm
the target appears in the dashboard. Dry-run should create a preview record and
leave target connectivity working; it does not validate live prerequisites.

In the Devices list, select the same device, click **Quarantine Device**, choose
**Windows Side-Host**, use a 60-second TTL, and disable Dry Run. CLI equivalent:

```powershell
.\win-tool.exe cut 192.168.1.24 --ttl 60
```

Confirm the action succeeds without the interface error. On the target, try a
fresh website connection and IPv4 connectivity. On a dual-stack LAN, check IPv6
separately. A single failed ping is insufficient evidence of isolation. The
controller should remain reachable. Then restore through the dashboard or:

```powershell
.\win-tool.exe heal 192.168.1.24
```

Confirm target connectivity recovers. Repeat a short cut and allow the TTL to
expire to verify automatic restoration while the server remains running.
Do not assume TTL healing will run after a crash or forced termination.
Whole-LAN Freeze tests are optional and should follow successful single-device
validation in an isolated lab.

## 8. Troubleshooting

| Error / symptom | Check and next step |
|---|---|
| Application Control policy blocked this file | Section 2; identify event 3077 policy and obtain approved signing/deployment. No application code ran. |
| Scripts cannot execute | `Get-ExecutionPolicy -List`; use approved script signing/deployment or individual diagnostic commands. |
| `wpcap.dll not available` | Official Npcap install, restart server, system/Npcap DLL path and architecture; inspect Code Integrity for DLL blocks. |
| Administrator required | Elevate and restart the server itself. |
| Forwarding ON / unverifiable | Read `doctor.blockers`, registry and interface routing state; correct side-host configuration, then reboot if changed. |
| Gateway IP/MAC not resolvable | Check `ipconfig`, `route.exe print -4`, `arp.exe -a`, and VPN routes; ping the intended gateway once. |
| Old `no interface found with IP 192.168.1.24` | Rebuild/restart the patched server. Current code cross-checks Npcap candidates against active local addresses. |
| `no active local LAN interface` | Compare listed capture/local candidates; verify target and gateway subnet, DHCP changes, bridged NIC and VPN/default route. |
| `NETCUT_WIN_IFACE` matched no device | Use a current LOCAL IP or actual NPF name fragment; set it before server startup. |
| Discovery works but quarantine fails | Discovery and enforcement are separate; run `probe`, `doctor`, then inspect the API error and server log. |
| Applied record but target stays online | Check dry-run/adapter choice, IPv6, AP/client isolation, static ARP and switch security. Use router/gateway enforcement where side-host ARP is ineffective. |
| IPv6 remains online | NDP pairing is best effort and requires cached target/gateway IPv6 addresses; collect `netsh.exe interface ipv6 show neighbors` and use gateway enforcement for complete coverage. |
| Blank dashboard / 404 | Build web assets and start from the directory containing `web/dist/index.html`. |
| Port 8080 already used | `Get-NetTCPConnection -LocalPort 8080`; inspect `OwningProcess` with `Get-Process -Id`, then stop the known old server in its terminal or choose another port. |
| Helper calls wrong server | Check `$env:OPEN_NETCUT_SERVER`; default is `http://localhost:8080`. |
| Tests blocked / binaries unsigned | Distinguish compile errors, test failures and Code Integrity blocks; policy approval is separate from build success. |

## 9. Capture a useful debug report

```powershell
.\scripts\Windows-Diagnostics.ps1 -OutputPath .\windows-diagnostics.json
.\win-tool.exe doctor
.\win-tool.exe probe
netsh.exe interface ipv6 show neighbors
```

Include the diagnostic JSON, exact dashboard/API error, server log around the
failure, target IP, chosen adapter, dry-run flag, TTL, and whether the issue is
startup, discovery, interface selection, quarantine, or restoration. The report
contains local paths, addresses and hardware identifiers; review it before
sharing outside your organization. It neither injects packets nor changes policy.
