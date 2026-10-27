# install-terastation-tunnel.ps1
# Installs Cloudflare Tunnel (cloudflared) as a Windows service so the TeraStation's
# WebAccess is reachable at https://files.fwogg3r.com — no router ports opened.
#
# HOW TO RUN
#   1. Right-click Start -> "Terminal (Admin)" or "Windows PowerShell (Admin)".
#   2. Run:   powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\install-terastation-tunnel.ps1"
#   3. When asked, paste the tunnel token (Cloudflare -> Zero Trust -> Networks -> Tunnels ->
#      terastation -> Configure -> the long string after "service install" in the Windows command).
#
# What it does
#   - Installs cloudflared with winget (or updates it if already installed)
#   - Registers it as the "Cloudflared" Windows service, start type Automatic (starts at boot,
#     before anyone signs in)
#   - Tells Windows to restart the service automatically if it ever crashes
#   - Stops this PC from sleeping/hibernating while plugged in, so the tunnel stays up
#   - Powering back on after a power outage can't be set from Windows: in the PC's BIOS/UEFI,
#     set "Restore on AC Power Loss" (or "AC Power Recovery") to "Power On".

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Write-Host "`n== 1/5  Installing cloudflared ==" -ForegroundColor Cyan
$cf = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cf) {
    winget install --id Cloudflare.cloudflared -e --accept-source-agreements --accept-package-agreements
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
    $cf = Get-Command cloudflared -ErrorAction SilentlyContinue
    if (-not $cf) {
        $guess = "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe", "$env:ProgramFiles\cloudflared\cloudflared.exe" |
                 Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $guess) { throw "cloudflared installed but not found on PATH. Close this window, open a new Admin PowerShell and run the script again." }
        $cfPath = $guess
    } else { $cfPath = $cf.Source }
} else {
    $cfPath = $cf.Source
    winget upgrade --id Cloudflare.cloudflared -e --accept-source-agreements --accept-package-agreements 2>$null | Out-Null
}
Write-Host "cloudflared: $cfPath"
& $cfPath --version

Write-Host "`n== 2/5  Registering the Windows service ==" -ForegroundColor Cyan
$secure = Read-Host "Paste the tunnel token (input hidden)" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if ($token.Length -lt 50) { throw "That doesn't look like a tunnel token (too short)." }

if (Get-Service -Name Cloudflared -ErrorAction SilentlyContinue) {
    Write-Host "Existing Cloudflared service found - reinstalling with the new token."
    & $cfPath service uninstall | Out-Null
    Start-Sleep -Seconds 3
}
& $cfPath service install $token
$token = $null

Write-Host "`n== 3/5  Start at boot + auto-restart on failure ==" -ForegroundColor Cyan
Set-Service -Name Cloudflared -StartupType Automatic
sc.exe config Cloudflared start= delayed-auto | Out-Null      # wait for networking at boot
sc.exe failure Cloudflared reset= 86400 actions= restart/30000/restart/60000/restart/120000 | Out-Null
sc.exe failureflag Cloudflared 1 | Out-Null
Start-Service -Name Cloudflared -ErrorAction SilentlyContinue

Write-Host "`n== 4/5  Keep this PC awake on AC power ==" -ForegroundColor Cyan
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
Write-Host "Sleep and hibernate on AC power: Never (screen can still turn off)."

Write-Host "`n== 5/5  Checking ==" -ForegroundColor Cyan
Start-Sleep -Seconds 5
Get-Service Cloudflared | Format-Table Name, Status, StartType -AutoSize
try {
    $r = Test-NetConnection 192.168.4.61 -Port 9000 -WarningAction SilentlyContinue
    if ($r.TcpTestSucceeded) { Write-Host "TeraStation WebAccess (192.168.4.61:9000) reachable from this PC." -ForegroundColor Green }
    else { Write-Host "WARNING: can't reach 192.168.4.61:9000 from this PC. Is the TeraStation on and WebAccess enabled?" -ForegroundColor Yellow }
} catch {}
Write-Host "`nDone. In Cloudflare -> Networks -> Tunnels, 'terastation' should show HEALTHY within a minute." -ForegroundColor Green
