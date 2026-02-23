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

function Resolve-LogDirPath {
  param([string]$ConfiguredLogDir)
  $raw = [string]$ConfiguredLogDir
  if ([string]::IsNullOrWhiteSpace($raw)) {
    return (Join-Path $scriptDir 'logs')
  }
  if ([System.IO.Path]::IsPathRooted($raw)) {
    return $raw
  }
  return (Join-Path $scriptDir $raw)
}

function Get-NowLogTimestamp {
  $d = Get-Date
  return $d.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
}

$sharedLogEnabled = $true
if ($cfg.PSObject.Properties.Name -contains 'writePowerShellLogsToNodeLog') {
  $sharedLogEnabled = [bool]$cfg.writePowerShellLogsToNodeLog
}
$psVerboseLogs = $false
if ($cfg.PSObject.Properties.Name -contains 'verboseLogs') {
  $psVerboseLogs = [bool]$cfg.verboseLogs
}

$sharedLogDir = Resolve-LogDirPath -ConfiguredLogDir $cfg.logDir
$sharedLogFile = Join-Path $sharedLogDir ("campus-login-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))
if ($sharedLogEnabled) {
  if (-not (Test-Path $sharedLogDir)) {
    New-Item -ItemType Directory -Path $sharedLogDir -Force | Out-Null
  }
}

function Write-SharedLog {
  param(
    [string]$Level,
    [string]$Message
  )
  if (-not $sharedLogEnabled) { return }
  try {
    $line = "[{0}] [PS][{1}] {2}" -f (Get-NowLogTimestamp), $Level, $Message
    Add-Content -Path $sharedLogFile -Value $line -Encoding UTF8
  }
  catch {}
}

function Write-Stage {
  param([string]$Message)
  Write-Host "   [STAGE] $Message"
  Write-SharedLog -Level 'STAGE' -Message $Message
}

function Write-Info {
  param([string]$Message)
  Write-Host "   [INFO] $Message"
  Write-SharedLog -Level 'INFO' -Message $Message
}

function Write-VerboseInfo {
  param([string]$Message)
  if (-not $psVerboseLogs) { return }
  Write-Info $Message
}

function Write-Ok {
  param([string]$Message)
  Write-Host "   [ OK ] $Message"
  Write-SharedLog -Level 'OK' -Message $Message
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
    [string]$GatewayPrefix = '',
    $Adapters = $null,
    $IPs = $null
  )
  $routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Sort-Object `
  @{ Expression = { (Get-MetricValue $_.RouteMetric) + (Get-MetricValue $_.InterfaceMetric) } }, `
    RouteMetric, InterfaceMetric
  if (-not $routes) { return $null }

  # Use cached adapters/IPs if provided, otherwise query (fallback)
  if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
  if (-not $IPs) { $IPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue }

  foreach ($r in $routes) {
    $gw = [string]$r.NextHop
    if ($GatewayPrefix -and -not $gw.StartsWith($GatewayPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      continue
    }
    $adapter = $Adapters | Where-Object { $_.InterfaceIndex -eq $r.InterfaceIndex } | Select-Object -First 1
    if (-not $adapter) { continue }
    if ($adapter.Status -ne 'Up' -or $adapter.HardwareInterface -ne $true) { continue }

    $ips = @($IPs | Where-Object { $_.InterfaceIndex -eq $r.InterfaceIndex } | ForEach-Object { [string]$_.IPAddress }) | Where-Object { $_ }
    if ($ips.Count -eq 0) { continue }

    $rawMedium = ''
    if ($null -ne $adapter.NdisPhysicalMedium) {
      $rawMedium = [string]$adapter.NdisPhysicalMedium
    }
    elseif ($adapter.MediaType) {
      $rawMedium = [string]$adapter.MediaType
    }
    $accessType = 'Unknown'
    if ($rawMedium -eq '9' -or $rawMedium -eq 'Native802_11' -or $rawMedium -match '802.?11') {
      $accessType = 'WLAN'
    }
    elseif ($rawMedium -eq '14' -or $rawMedium -eq '802.3' -or $rawMedium -match '802\.3') {
      $accessType = 'Wired'
    }

    return [PSCustomObject]@{
      AdapterName     = [string]$adapter.Name
      InterfaceIndex  = [int]$r.InterfaceIndex
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

function Get-TemporaryHostsMappings {
  param($Config)
  if ($Config.PSObject.Properties.Name -contains 'temporaryHostsMappings' -and $Config.temporaryHostsMappings) {
    return $Config.temporaryHostsMappings
  }
  $fallback = [ordered]@{}
  $fallback['www.msftconnecttest.com'] = '23.214.95.200'
  return $fallback
}

function Read-FileTextShared {
  param([string]$Path)
  $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::ASCII, $true)
    try {
      return $sr.ReadToEnd()
    }
    finally {
      $sr.Dispose()
    }
  }
  finally {
    $fs.Dispose()
  }
}

function Write-FileText {
  param(
    [string]$Path,
    [string]$Text
  )
  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::ASCII)
}

function Remove-TempHostsEntries {
  param([string]$HostsPath)
  if (-not (Test-Path $HostsPath)) { return }
  $tries = 3
  for ($i = 1; $i -le $tries; $i++) {
    try {
      $raw = Read-FileTextShared -Path $HostsPath
      $lines = @(($raw -split "`r?`n"))
      $filtered = @($lines | Where-Object { $_ -notmatch '#\s*campus-autologin-temp' })
      $text = ($filtered -join [Environment]::NewLine).TrimEnd()
      if ($text.Length -gt 0) { $text += [Environment]::NewLine }
      Write-FileText -Path $HostsPath -Text $text
      return
    }
    catch {
      if ($i -eq $tries) { throw }
      Start-Sleep -Milliseconds 120
    }
  }
}

function Add-TempHostsEntries {
  param(
    [string]$HostsPath,
    $Mappings
  )
  if (-not $Mappings) { return $false }
  Remove-TempHostsEntries -HostsPath $HostsPath

  $append = @()
  $append += '# campus-autologin-temp begin'
  foreach ($name in $Mappings.PSObject.Properties.Name) {
    $ip = [string]$Mappings.$name
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }
    $append += "$ip`t$name`t# campus-autologin-temp"
  }
  $append += '# campus-autologin-temp end'
  $tries = 3
  for ($i = 1; $i -le $tries; $i++) {
    try {
      $current = ''
      if (Test-Path $HostsPath) {
        $current = Read-FileTextShared -Path $HostsPath
      }
      $block = ($append -join [Environment]::NewLine) + [Environment]::NewLine
      $prefix = $current
      if ($prefix.Length -gt 0 -and -not $prefix.EndsWith([Environment]::NewLine)) {
        $prefix += [Environment]::NewLine
      }
      Write-FileText -Path $HostsPath -Text ($prefix + $block)
      break
    }
    catch {
      if ($i -eq $tries) { throw }
      Start-Sleep -Milliseconds 120
    }
  }
  return $true
}

function Try-GetHostFromUrl {
  param([string]$Url)
  try {
    $u = [System.Uri]$Url
    if ($u -and $u.Host) { return $u.Host.ToLowerInvariant() }
  }
  catch {}
  return ''
}

function Get-AuthHostsForBypass {
  param($Config)
  $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

  $null = $set.Add('202.201.252.10')

  if ($Config.gatewayHost) { $null = $set.Add([string]$Config.gatewayHost) }
  if ($Config.statusUrl) {
    $h = Try-GetHostFromUrl -Url ([string]$Config.statusUrl)
    if ($h) { $null = $set.Add($h) }
  }
  if ($Config.portalUrl) {
    $h = Try-GetHostFromUrl -Url ([string]$Config.portalUrl)
    if ($h) { $null = $set.Add($h) }
  }
  if ($Config.detectUrls) {
    foreach ($u in @($Config.detectUrls)) {
      $h = Try-GetHostFromUrl -Url ([string]$u)
      if ($h) { $null = $set.Add($h) }
    }
  }

  return @($set)
}

function Test-OnlineByRadUserInfo {
  param(
    $Config,
    [int]$TimeoutMs = 5000
  )
  $hosts = Get-AuthHostsForBypass -Config $Config
  foreach ($hostName in $hosts) {
    $url = "http://${hostName}/cgi-bin/rad_user_info?callback=autologin_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())&_=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
    try {
      $resp = Invoke-WebRequest -Uri $url -Method GET -TimeoutSec ([Math]::Ceiling($TimeoutMs / 1000.0)) -UseBasicParsing -ErrorAction Stop
      $body = [string]$resp.Content
      if ($body -match 'not_online_error') { return $false }
      if ($body -match '"error"\s*:\s*"ok"' -or $body -match '"res"\s*:\s*"ok"') { return $true }
    }
    catch {
      continue
    }
  }
  return $false
}

function Resolve-HostToIpv4 {
  param([string]$HostOrIp)
  $x = [string]$HostOrIp
  $ips = @()

  $ipv4Obj = $null
  if ([System.Net.IPAddress]::TryParse($x, [ref]$ipv4Obj)) {
    if ($ipv4Obj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
      return @($x)
    }
  }

  try {
    $dns = Resolve-DnsName -Name $x -Type A -ErrorAction SilentlyContinue
    if ($dns) {
      $ips = @($dns | ForEach-Object { $_.IPAddress } | Where-Object { $_ } | Select-Object -Unique)
    }
  }
  catch {}

  return $ips
}

function Get-ConfiguredRouteIpsForHost {
  param(
    $Config,
    [string]$HostName
  )
  $result = @()
  if (-not $Config) { return $result }
  if (-not ($Config.PSObject.Properties.Name -contains 'routeBypassStaticIps')) { return $result }

  $map = $Config.routeBypassStaticIps
  if (-not $map) { return $result }
  if (-not ($map.PSObject.Properties.Name -contains $HostName)) { return $result }

  $raw = $map.$HostName
  if ($null -eq $raw) { return $result }

  $items = @($raw)
  foreach ($x in $items) {
    $ip = [string]$x
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) {
      if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $result += $ip
      }
    }
  }

  return @($result | Select-Object -Unique)
}

function Is-FakeIpV4 {
  param([string]$Ip)
  $x = [string]$Ip
  return ($x -match '^198\.(18|19)\.')
}

function Add-AuthBypassRoutes {
  param(
    $Config,
    $Access
  )
  $added = @()
  if (-not $Access -or -not $Access.Gateway -or -not $Access.InterfaceIndex) { return $added }

  $hosts = Get-AuthHostsForBypass -Config $Config
  $plannedIps = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($rawHost in $hosts) {
    $authHost = [string]$rawHost
    $resolveHost = $authHost

    $ips = Get-ConfiguredRouteIpsForHost -Config $Config -HostName $authHost
    if ($ips.Count -gt 0) {
      Write-VerboseInfo "Using configured route IPs for ${authHost}: $($ips -join ', ')"
    }
    else {
      $ips = Resolve-HostToIpv4 -HostOrIp $resolveHost
    }
    foreach ($ip in $ips) {
      if (-not $plannedIps.Add($ip)) {
        Write-VerboseInfo "Skip duplicate bypass route target in current run: $ip (host=$authHost)"
        continue
      }
      if (Is-FakeIpV4 -Ip $ip) {
        Write-VerboseInfo "Skip fake-ip route target: $ip (host=$authHost)"
        continue
      }
      try {
        $routeOutput = & route.exe ADD $ip MASK 255.255.255.255 $Access.Gateway IF $Access.InterfaceIndex METRIC 5 2>&1
        if ($LASTEXITCODE -eq 0) {
          Write-VerboseInfo "Added auth bypass route: $ip via $($Access.Gateway) if=$($Access.InterfaceIndex) (host=$authHost)"
          $added += $ip
        }
        else {
          $msg = [string]($routeOutput -join ' ')
          if ($msg -match 'already exists|object already exists') {
            Write-VerboseInfo "Bypass route already exists, skip add: $ip"
          }
          elseif (-not [string]::IsNullOrWhiteSpace($msg)) {
            Write-Info "Add route failed for $ip(host=$authHost): $msg"
          }
        }
      }
      catch {
        Write-Info "Add route failed for $ip(host=$authHost): $($_.Exception.Message)"
      }
    }
  }

  return @($added | Select-Object -Unique)
}

function Remove-AuthBypassRoutes {
  param(
    [string[]]$Ips
  )
  if (-not $Ips -or $Ips.Count -eq 0) { return }
  foreach ($ip in $Ips) {
    try {
      $null = & route.exe DELETE $ip
      Write-VerboseInfo "Removed auth bypass route: $ip"
    }
    catch {
      Write-Info "Remove route failed for ${ip}: $($_.Exception.Message)"
    }
  }
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

# Detect Fake-IP mode:
# - prioritize non-hardware adapters with 198.18/198.19 address
# - fallback to proxy-like virtual adapter signature (Up + non-hardware)
$fakeIpMode = 'false'
try {
  $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
  $allIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue

  $fakeIpByIP = @($allIPs | Where-Object { $_.IPAddress -match '^198\.(18|19)\.' })
  if ($fakeIpByIP.Count -gt 0) {
    $fakeIpByVirtualIp = @(
      $fakeIpByIP | Where-Object {
        $ifx = $_.InterfaceIndex
        $ad = $allAdapters | Where-Object { $_.InterfaceIndex -eq $ifx } | Select-Object -First 1
        $ad -and $ad.Status -eq 'Up' -and $ad.HardwareInterface -ne $true
      }
    )
    if ($fakeIpByVirtualIp.Count -gt 0) {
      $fakeIpByIP = $fakeIpByVirtualIp
    }
  }
  if ($fakeIpByIP) {
    $fakeIpMode = 'true'
    $matchedAdapter = $fakeIpByIP | Select-Object -First 1
    Write-Info "Fake-IP detected: adapter='$($matchedAdapter.InterfaceAlias)' ip=$($matchedAdapter.IPAddress)"
  }
  else {
    $proxyAdapters = @(
      $allAdapters | Where-Object {
        $_.Status -eq 'Up' -and
        $_.HardwareInterface -ne $true -and
        (
          $_.InterfaceDescription -match 'Meta Tunnel|Mihomo|Clash|Sing-box|Wintun|TAP-Windows|WireGuard|tailscale' -or
          $_.Name -match 'Mihomo|Clash|sing-?box|WireGuard|tailscale'
        )
      }
    )
    if ($proxyAdapters.Count -eq 0) {
      # Additional virtual-only fallback: "tun/tap" with non-hardware + Up and Fake-IP address
      $proxyAdapters = @(
        $allAdapters | Where-Object {
          $_.Status -eq 'Up' -and
          $_.HardwareInterface -ne $true -and
          ($_.InterfaceDescription -match 'TUN|TAP' -or $_.Name -match 'TUN|TAP')
        }
      )
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
    Write-VerboseInfo "Physical adapter: name='$($pa.Name)' desc='$($pa.InterfaceDescription)' ip=[$paIPs]"
  }
}
else {
  Write-VerboseInfo "No physical adapter in Up state found yet."
}

# ── Step 2: Network Readiness Check (wait for campus network) ──
Write-Stage "Network Readiness Check"
$start = Get-Date
$deadline = $start.AddSeconds($waitMaxSec)
$lastStateMsg = ''
$lastReport = $start.AddSeconds(-30)
$ok = $false

Write-VerboseInfo "Rules: WLAN -> SSID must match [$($prefixes -join ', ')]; Wired -> IP must match '$ipPrefix'. Max wait ${waitMaxSec}s."

while ((Get-Date) -lt $deadline) {
  $elapsedSec = [int]((Get-Date) - $start).TotalSeconds
  $access = Get-PrimaryAccessInterface -GatewayPrefix $gwPrefix -Adapters $allAdapters -IPs $allIPs
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
        Write-VerboseInfo $stateMsg
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
        Write-VerboseInfo $stateMsg
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
        Write-VerboseInfo $stateMsg
        $lastStateMsg = $stateMsg
        $lastReport = Get-Date
      }
    }
  }
  else {
    $stateMsg = "No physical default route yet, elapsed=${elapsedSec}s/${waitMaxSec}s"
    if ($stateMsg -ne $lastStateMsg -or ((Get-Date) - $lastReport).TotalSeconds -ge 10) {
      Write-VerboseInfo $stateMsg
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
$addedBypassRouteIps = @()
$tempHostsApplied = $false
$needAuth = $true

$useRouteBypass = $true
if ($cfg.PSObject.Properties.Name -contains 'useRouteBypassDuringAuth') {
  $useRouteBypass = [bool]$cfg.useRouteBypassDuringAuth
}

$useTemporaryHosts = $false
if ($cfg.PSObject.Properties.Name -contains 'useTemporaryHostsDuringAuth') {
  $useTemporaryHosts = [bool]$cfg.useTemporaryHostsDuringAuth
}

try {
  # Pre-auth quick online check in PowerShell: if already online, skip hosts/routes/login.
  $onlineCheckTimeoutMs = 5000
  if ($cfg.PSObject.Properties.Name -contains 'onlineCheckTimeoutMs' -and $cfg.onlineCheckTimeoutMs) {
    $onlineCheckTimeoutMs = [int]$cfg.onlineCheckTimeoutMs
  }
  $isOnline = Test-OnlineByRadUserInfo -Config $cfg -TimeoutMs $onlineCheckTimeoutMs
  if ($isOnline) {
    Write-Info "Pre-auth online check: already online, skip hosts/routes changes."
    $needAuth = $false
  }
  else {
    Write-Info "Pre-auth online check: offline, continue auth preparation."
  }

  if ($needAuth) {
    if ($fakeIpMode -eq 'true' -and $useTemporaryHosts) {
      $hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
      try {
        $maps = Get-TemporaryHostsMappings -Config $cfg
        $tempHostsApplied = Add-TempHostsEntries -HostsPath $hostsPath -Mappings $maps
        if ($tempHostsApplied) {
          Write-Info "Temporary hosts mappings applied for auth."
          foreach ($mapName in $maps.PSObject.Properties.Name) {
            $mapIp = [string]$maps.$mapName
            if (-not [string]::IsNullOrWhiteSpace($mapIp)) {
              Write-VerboseInfo "Applied hosts mapping: ${mapName} -> ${mapIp}"
            }
          }
        }
      }
      catch {
        Write-Info "Temporary hosts mapping failed (admin may be required): $($_.Exception.GetType().Name): $($_.Exception.Message)"
      }
    }

    if ($fakeIpMode -eq 'true' -and $useRouteBypass -and $access) {
      Write-Info "Preparing auth bypass routes on physical adapter."
      $addedBypassRouteIps = Add-AuthBypassRoutes -Config $cfg -Access $access
      Write-Info "Auth bypass route targets added: $($addedBypassRouteIps.Count)"
    }

    node "$scriptDir\login.js" --fake-ip-mode=$fakeIpMode
  }
}
finally {
  Remove-AuthBypassRoutes -Ips $addedBypassRouteIps
  if ($addedBypassRouteIps.Count -gt 0) {
    Write-Info "Auth bypass routes cleaned: $($addedBypassRouteIps.Count)"
  }
  if ($useTemporaryHosts) {
    try {
      $hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
      Remove-TempHostsEntries -HostsPath $hostsPath
      if ($tempHostsApplied) {
        Write-Info "Temporary hosts mappings removed."
      }
      else {
        Write-VerboseInfo "Temporary hosts cleanup checked (no applied marker, stale entries removed if any)."
      }
    }
    catch {
      Write-Info "Temporary hosts cleanup failed: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
  }
}
