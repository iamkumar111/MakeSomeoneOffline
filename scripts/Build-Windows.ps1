# Build from the repository root without requiring make, CGO, or a Linux shell.
[CmdletBinding()]
param([switch]$SkipUI)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$savedLocation = Get-Location
$savedGOOS = $env:GOOS
$savedGOARCH = $env:GOARCH
$savedCGO = $env:CGO_ENABLED
try {
    Set-Location -LiteralPath $projectRoot
    Get-Command go -ErrorAction Stop | Out-Null
    if (-not $SkipUI) {
        Get-Command npm.cmd -ErrorAction Stop | Out-Null
        & npm.cmd --prefix web ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed; see the output above.' }
        & npm.cmd --prefix web run build
        if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed; check the Node version required by Vite.' }
    }
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    & go build -o open-netcut-windows-amd64.exe ./cmd/control-plane
    if ($LASTEXITCODE -ne 0) { throw 'Control-plane build failed. Stop an existing instance before replacing its executable.' }
    & go build -o win-tool.exe ./cmd/win-tool
    if ($LASTEXITCODE -ne 0) { throw 'Helper build failed; see the output above.' }
    Write-Host 'Build complete. Keep web/dist beside the binaries and start from the repository root.'
    Write-Host 'A successful build does not grant execution permission under Smart App Control or an organization policy.'
    Get-FileHash -LiteralPath "$projectRoot\open-netcut-windows-amd64.exe", "$projectRoot\win-tool.exe" -Algorithm SHA256
} finally {
    $env:GOOS = $savedGOOS
    $env:GOARCH = $savedGOARCH
    $env:CGO_ENABLED = $savedCGO
    Set-Location -LiteralPath $savedLocation.Path
}
