param(
  [switch]$Setup
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if ($Setup) {
  if (-not (Test-Path "$scriptDir\package.json")) {
    npm init -y | Out-Null
  }
  npm install playwright --silent
}

$configPath = "$scriptDir\config.json"
if (-not (Test-Path $configPath)) {
  throw "config.json not found. Copy config.example.json to config.json first."
}

$cfg = Get-Content $configPath -Raw | ConvertFrom-Json

function Write-Stage {
  param([string]$Message)
  Write-Host ""
  Write-Host "== $Message =="
}

function Write-Info {
  param([string]$Message)
  Write-Host "   [INFO] $Message"
}

function Write-Ok {
  param([string]$Message)
  Write-Host "   [ OK ] $Message"
}

function Get-WlanInfo {
  $raw = (netsh wlan show interfaces) 2>$null
  if (-not $raw) { return $null }
  $ssid = ''
  $name = ''
  $state = ''
  foreach ($line in $raw) {
    if ($line -match '^\s*SSID\s*:\s*(.+)$' -and $line -notmatch 'BSSID') {
      $ssid = $Matches[1].Trim()
    } elseif ($line -match '^\s*Name\s*:\s*(.+)$') {
      $name = $Matches[1].Trim()
    } elseif ($line -match '^\s*State\s*:\s*(.+)$') {
      $state = $Matches[1].Trim()
    }
  }
  if (-not $ssid) { return $null }
  [PSCustomObject]@{
    SSID = $ssid
    Name = $name
    State = $state
  }
}

if ($null -eq $cfg.enforceWifiSsidCheck -or $cfg.enforceWifiSsidCheck -eq $true) {
  $prefixes = @()
  if ($cfg.wifiSsidPrefixes) {
    $prefixes = @($cfg.wifiSsidPrefixes)
  }
  if ($prefixes.Count -eq 0) {
    $prefixes = @('xju_')
  }
  $waitMaxSec = 120
  if ($cfg.wifiWaitMaxSec) {
    $waitMaxSec = [int]$cfg.wifiWaitMaxSec
  }
  $waitIntervalSec = 3
  if ($cfg.wifiWaitIntervalSec) {
    $waitIntervalSec = [int]$cfg.wifiWaitIntervalSec
  }
  if ($waitIntervalSec -lt 1) { $waitIntervalSec = 1 }

  $start = Get-Date
  $deadline = $start.AddSeconds($waitMaxSec)
  $lastSsid = ''
  $lastStateMsg = ''
  $lastReport = $start.AddSeconds(-30)
  $ok = $false
  Write-Stage "Wi-Fi Readiness Check"
  Write-Info "Waiting for allowed SSID (max ${waitMaxSec}s), prefixes: $($prefixes -join ', ')"
  while ((Get-Date) -lt $deadline) {
    $wlan = Get-WlanInfo
    $elapsedSec = [int]((Get-Date) - $start).TotalSeconds
    if ($wlan -and $wlan.SSID) {
      $lastSsid = $wlan.SSID
      $matched = $false
      foreach ($p in $prefixes) {
        if ($wlan.SSID.StartsWith([string]$p, [System.StringComparison]::OrdinalIgnoreCase)) {
          $matched = $true
          $ok = $true
          break
        }
      }
      $stateMsg = "SSID='$($wlan.SSID)' matched=$matched elapsed=${elapsedSec}s/${waitMaxSec}s"
      if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
        Write-Info $stateMsg
        $lastStateMsg = $stateMsg
        $lastReport = Get-Date
      }
      if ($ok) { break }
    } else {
      $stateMsg = "Wi-Fi not connected yet, elapsed=${elapsedSec}s/${waitMaxSec}s"
      if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
        Write-Info $stateMsg
        $lastStateMsg = $stateMsg
        $lastReport = Get-Date
      }
    }
    Start-Sleep -Seconds $waitIntervalSec
  }
  if (-not $ok) {
    if ($lastSsid) {
      throw "Wi-Fi SSID wait timeout($waitMaxSec s). Last SSID '$lastSsid' does not match allowed prefixes: $($prefixes -join ', ')"
    }
    throw "Wi-Fi SSID wait timeout($waitMaxSec s). Wi-Fi interface/SSID not ready."
  }
  Write-Ok "Wi-Fi check passed: SSID '$lastSsid'"
}

Write-Stage "Online Status Check"
Write-Info "Checking online status before DHCP refresh ..."
node "$scriptDir\login.js" --check-online-only
if ($LASTEXITCODE -eq 0) {
  Write-Ok "Already online, skip authentication."
  exit 0
}
Write-Info "Not online yet, continue authentication flow."

if ($cfg.dhcpRefreshBeforeAuth -eq $true) {
  Write-Stage "DHCP Refresh"
  $wlan = Get-WlanInfo
  $pauseSec = 2
  if ($cfg.dhcpRefreshPauseSec) {
    $pauseSec = [int]$cfg.dhcpRefreshPauseSec
  }
  if ($wlan -and $wlan.Name) {
    Write-Info "Refreshing DHCP on adapter '$($wlan.Name)' ..."
    ipconfig /release "$($wlan.Name)" | Out-Null
    Start-Sleep -Seconds $pauseSec
    ipconfig /renew "$($wlan.Name)" | Out-Null
  } else {
    Write-Info "Refreshing DHCP on all adapters ..."
    ipconfig /release | Out-Null
    Start-Sleep -Seconds $pauseSec
    ipconfig /renew | Out-Null
  }
  Write-Ok "DHCP refresh completed."
}

Write-Stage "Portal Authentication"
node "$scriptDir\login.js"
