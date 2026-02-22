param(
  [switch]$Setup
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if ($Setup) {
  Write-Host "== Setup Mode =="
  Write-Host "Installing dependencies only, authentication will not run."
  if (-not (Test-Path "$scriptDir\package.json")) {
    npm init -y | Out-Null
  }
  npm install playwright --silent
  Write-Host "[ OK ] Setup completed."
  exit 0
}

$configPath = "$scriptDir\config.json"
if (-not (Test-Path $configPath)) {
  throw "config.json not found. Copy config.example.json to config.json first."
}

# Force UTF-8 read to avoid mojibake on Windows PowerShell 5.1 when config.json contains Chinese text.
$cfg = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json

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
    }
    elseif ($line -match '^\s*Name\s*:\s*(.+)$') {
      $name = $Matches[1].Trim()
    }
    elseif ($line -match '^\s*State\s*:\s*(.+)$') {
      $state = $Matches[1].Trim()
    }
  }
  if (-not $ssid) { return $null }
  [PSCustomObject]@{
    SSID  = $ssid
    Name  = $name
    State = $state
  }
}

function Get-MetricValue {
  param($Value)
  if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
    return 9999
  }
  return [int]$Value
}

function Get-PrimaryAccessInterface {
  param(
    [string]$GatewayPrefix = ''
  )
  $routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Sort-Object `
  @{ Expression = { (Get-MetricValue $_.RouteMetric) + (Get-MetricValue $_.InterfaceMetric) } }, `
    RouteMetric, InterfaceMetric
  if (-not $routes) { return $null }

  $ipConfs = Get-NetIPConfiguration -ErrorAction SilentlyContinue
  foreach ($r in $routes) {
    $gw = [string]$r.NextHop
    if ($GatewayPrefix -and -not $gw.StartsWith($GatewayPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      continue
    }
    $it = $ipConfs | Where-Object { $_.InterfaceIndex -eq $r.InterfaceIndex } | Select-Object -First 1
    if (-not $it -or -not $it.NetAdapter) { continue }
    if ($it.NetAdapter.Status -ne 'Up' -or $it.NetAdapter.HardwareInterface -ne $true) { continue }

    $ips = @($it.IPv4Address | ForEach-Object { [string]$_.IPAddress }) | Where-Object { $_ }
    if ($ips.Count -eq 0) { continue }

    $rawMedium = ''
    if ($it.NetAdapter.NdisPhysicalMedium -ne $null) {
      $rawMedium = [string]$it.NetAdapter.NdisPhysicalMedium
    }
    elseif ($it.NetAdapter.MediaType) {
      $rawMedium = [string]$it.NetAdapter.MediaType
    }
    $accessType = 'Unknown'
    if ($rawMedium -eq '9' -or $rawMedium -eq 'Native802_11' -or $rawMedium -match '802.?11') {
      $accessType = 'WLAN'
    }
    elseif ($rawMedium -eq '14' -or $rawMedium -eq '802.3' -or $rawMedium -match '802\.3') {
      $accessType = 'Wired'
    }

    return [PSCustomObject]@{
      AdapterName     = [string]$it.InterfaceAlias
      InterfaceIndex  = [int]$it.InterfaceIndex
      AccessType      = $accessType
      Medium          = $rawMedium
      IPv4List        = $ips
      Gateway         = $gw
      RouteMetric     = (Get-MetricValue $r.RouteMetric)
      InterfaceMetric = (Get-MetricValue $r.InterfaceMetric)
    }
  }
  return $null
}

# ── Step 1: Adapter Enumeration, Fake-IP Detection & Network Readiness ──
$ipPrefix = '10.'
if ($cfg.requireIpPrefix) { $ipPrefix = [string]$cfg.requireIpPrefix }
$gwPrefix = '10.'
if ($cfg.requireGatewayPrefix) { $gwPrefix = [string]$cfg.requireGatewayPrefix }

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

Write-Stage "Adapter Enumeration & Fake-IP Detection"

# Detect Fake-IP mode aggressively:
# - any adapter with 198.18.* address
# - or virtual adapter name/description that matches Mihomo/Clash family
$fakeIpMode = 'false'
try {
  $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
  $allIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue

  $fakeIpByIP = $allIPs | Where-Object { $_.IPAddress.StartsWith('198.18.') }
  if ($fakeIpByIP) {
    $fakeIpMode = 'true'
    $matchedAdapter = $fakeIpByIP | Select-Object -First 1
    Write-Info "Fake-IP detected: adapter='$($matchedAdapter.InterfaceAlias)' ip=$($matchedAdapter.IPAddress)"
  }
  else {
    $proxyAdapters = $allAdapters | Where-Object {
      $_.InterfaceDescription -match 'Meta Tunnel|Mihomo|Clash|Sing-box|TUN|TAP|WireGuard|tailscale' -or
      $_.Name -match 'Mihomo|Clash|sing-?box'
    }
    if ($proxyAdapters) {
      $fakeIpMode = 'true'
      $matchedName = ($proxyAdapters | Select-Object -First 1).Name
      Write-Info "Fake-IP detected: virtual adapter='$matchedName'"
    }
  }
}
catch {
  Write-Info "Fake-IP detection failed, defaulting to false."
}
if ($fakeIpMode -eq 'false') {
  Write-Ok "No Fake-IP proxy detected."
}
else {
  Write-Ok "Fake-IP mode enabled, portal-only URLs will be used."
}

# List physical adapters for diagnostics
$physicalAdapters = $allAdapters | Where-Object { $_.HardwareInterface -eq $true -and $_.Status -eq 'Up' }
if ($physicalAdapters) {
  foreach ($pa in $physicalAdapters) {
    $paIPs = ($allIPs | Where-Object { $_.InterfaceIndex -eq $pa.InterfaceIndex } | ForEach-Object { $_.IPAddress }) -join ', '
    Write-Info "Physical adapter: name='$($pa.Name)' desc='$($pa.InterfaceDescription)' ip=[$paIPs]"
  }
}
else {
  Write-Info "No physical adapter in Up state found yet."
}

# ── Step 2: Network Readiness Check (wait for campus network) ──
Write-Stage "Network Readiness Check"
$start = Get-Date
$deadline = $start.AddSeconds($waitMaxSec)
$lastStateMsg = ''
$lastReport = $start.AddSeconds(-30)
$ok = $false

Write-Info "Rules: WLAN -> SSID must match [$($prefixes -join ', ')]; Wired -> IP must match '$ipPrefix'. Max wait ${waitMaxSec}s."

while ((Get-Date) -lt $deadline) {
  $elapsedSec = [int]((Get-Date) - $start).TotalSeconds
  $access = Get-PrimaryAccessInterface -GatewayPrefix $gwPrefix
  if ($access) {
    $accessMsg = "adapter='$($access.AdapterName)' type=$($access.AccessType) ip=[$(($access.IPv4List -join ', '))] gw=$($access.Gateway)"

    if ($access.AccessType -eq 'WLAN') {
      $wlan = Get-WlanInfo
      $ssid = ''
      if ($wlan -and $wlan.SSID) { $ssid = [string]$wlan.SSID }
      $matched = $false
      if ($ssid) {
        foreach ($p in $prefixes) {
          if ($ssid.StartsWith([string]$p, [System.StringComparison]::OrdinalIgnoreCase)) {
            $matched = $true
            $ok = $true
            break
          }
        }
      }
      $stateMsg = "WLAN: $accessMsg ssid='$ssid' matched=$matched elapsed=${elapsedSec}s/${waitMaxSec}s"
      if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
        Write-Info $stateMsg
        $lastStateMsg = $stateMsg
        $lastReport = Get-Date
      }
      if ($ok) {
        Write-Ok "WLAN ready: SSID '$ssid'"
        break
      }
    }
    elseif ($access.AccessType -eq 'Wired') {
      $ipOk = $false
      foreach ($ip in $access.IPv4List) {
        if (-not $ipPrefix -or $ip.StartsWith($ipPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
          $ipOk = $true
          break
        }
      }
      $stateMsg = "Wired: $accessMsg ipOk=$ipOk elapsed=${elapsedSec}s/${waitMaxSec}s"
      if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
        Write-Info $stateMsg
        $lastStateMsg = $stateMsg
        $lastReport = Get-Date
      }
      if ($ipOk) {
        Write-Ok "Wired ready: adapter '$($access.AdapterName)'"
        $ok = $true
        break
      }
    }
    else {
      $stateMsg = "Unknown medium: $accessMsg elapsed=${elapsedSec}s/${waitMaxSec}s"
      if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
        Write-Info $stateMsg
        $lastStateMsg = $stateMsg
        $lastReport = Get-Date
      }
    }
  }
  else {
    $stateMsg = "No physical default route yet, elapsed=${elapsedSec}s/${waitMaxSec}s"
    if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
      Write-Info $stateMsg
      $lastStateMsg = $stateMsg
      $lastReport = Get-Date
    }
  }
  Start-Sleep -Seconds $waitIntervalSec
}
if (-not $ok) {
  if ($access) {
    throw "Network wait timeout($waitMaxSec s). Last: adapter='$($access.AdapterName)' type=$($access.AccessType)"
  }
  throw "Network wait timeout($waitMaxSec s). No physical default route available."
}

# ── Step 3: Online Check & Authentication ──
Write-Stage "Online Status Check & Authentication"
node "$scriptDir\login.js" --fake-ip-mode=$fakeIpMode
