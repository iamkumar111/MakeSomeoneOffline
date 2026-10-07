# Read-only diagnostics: no packet injection, policy changes, or service changes.
[CmdletBinding()]
param([string]$OutputPath)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$diagnosticErrors = [System.Collections.Generic.List[string]]::new()
$report = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    project_root = $projectRoot
    sends_packets = $false
    admin = $false
    smart_app_control = 'unknown'
    ip_enable_router = $null
    npcap_service = 'unknown'
    npcap_dlls = @()
    binaries = @()
    dashboard_present = (Test-Path -LiteralPath "$projectRoot\web\dist\index.html")
    interface_override = $env:NETCUT_WIN_IFACE
    routes_ipv4 = ''
    arp_cache = ''
    app_control_blocks = @()
    errors = @()
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $report.admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $diagnosticErrors.Add("Administrator check: $($_.Exception.Message)") }
try {
    $ciPolicy = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction Stop
    switch ($ciPolicy.VerifiedAndReputablePolicyState) {
        0 { $report.smart_app_control = 'off' }
        1 { $report.smart_app_control = 'enforced' }
        2 { $report.smart_app_control = 'evaluation' }
        default { $report.smart_app_control = 'unknown' }
    }
} catch { $diagnosticErrors.Add("Smart App Control state: $($_.Exception.Message)") }
try {
    $tcpip = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    if ($null -eq $tcpip.IPEnableRouter) {
        $report.ip_enable_router = 0 # Value absent: Windows default is disabled.
    } else { $report.ip_enable_router = $tcpip.IPEnableRouter }
} catch { $diagnosticErrors.Add("Forwarding state: $($_.Exception.Message)") }
try {
    $report.npcap_service = (Get-Service -Name npcap).Status.ToString()
} catch { $diagnosticErrors.Add("Npcap service: $($_.Exception.Message)") }
foreach ($dllPath in @("$env:SystemRoot\System32\Npcap\wpcap.dll", "$env:SystemRoot\System32\wpcap.dll")) {
    if (Test-Path -LiteralPath $dllPath) { $report.npcap_dlls += $dllPath }
}
foreach ($binaryName in @('open-netcut-windows-amd64.exe', 'win-tool.exe')) {
    $binaryPath = Join-Path $projectRoot $binaryName
    if (-not (Test-Path -LiteralPath $binaryPath)) {
        $report.binaries += [ordered]@{ name = $binaryName; exists = $false }
        continue
    }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $binaryPath
        $report.binaries += [ordered]@{
            name = $binaryName
            exists = $true
            last_write_time = (Get-Item -LiteralPath $binaryPath).LastWriteTime.ToString('o')
            sha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash
            signature_status = $signature.Status.ToString()
        }
    } catch { $diagnosticErrors.Add("Binary ${binaryName}: $($_.Exception.Message)") }
}
try {
    $report.routes_ipv4 = (& "$env:SystemRoot\System32\route.exe" print -4 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "route.exe exit code $LASTEXITCODE" }
    $report.arp_cache = (& "$env:SystemRoot\System32\arp.exe" -a | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "arp.exe exit code $LASTEXITCODE" }
} catch { $diagnosticErrors.Add("Network tables: $($_.Exception.Message)") }
try {
    # 3077 identifies enforced blocks; omit noisy signature-only 3089 records.
    $blockEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
        Id = 3077
        StartTime = (Get-Date).AddDays(-1)
    } -MaxEvents 50 -ErrorAction Stop)
    foreach ($blockEvent in $blockEvents) {
        $eventXml = [xml]$blockEvent.ToXml()
        $fields = @{}
        foreach ($entry in $eventXml.Event.EventData.Data) { $fields[$entry.Name] = $entry.'#text' }
        if ($fields['File Name'] -match '(win-tool|open-netcut-windows-amd64|gofmt|\.test)\.exe$') {
            $report.app_control_blocks += [ordered]@{
                time = $blockEvent.TimeCreated.ToString('o')
                file = $fields['File Name']
                policy = $fields['PolicyName']
                policy_guid = $fields['PolicyGUID']
                status = $fields['Status']
            }
        }
    }
} catch { $diagnosticErrors.Add("Code Integrity log (may need elevation or have no events): $($_.Exception.Message)") }
$report.errors = @($diagnosticErrors.ToArray())
$json = $report | ConvertTo-Json -Depth 6
if ($OutputPath) { $json | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
$json
