$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$taskName = 'CampusNetAutoLogin'
$runName = 'CampusNetAutoLogin'

$wscript = "$env:WINDIR\System32\wscript.exe"
$hiddenLauncher = "$scriptDir\run-campus-login-hidden.vbs"
$action = "`"$wscript`" `"$hiddenLauncher`""

try {
  $null = & schtasks /Query /TN $taskName 2>$null
} catch {}
if ($LASTEXITCODE -eq 0) {
  try {
    & schtasks /Delete /TN $taskName /F 2>$null | Out-Null
  } catch {}
}

try {
  $null = & schtasks /Create /TN $taskName /SC ONLOGON /TR $action /RL LIMITED /F 2>$null
} catch {}
try {
  $null = & schtasks /Query /TN $taskName 2>$null
} catch {}
if ($LASTEXITCODE -eq 0) {
  Write-Host "Task installed: $taskName"
  Write-Host "Run now to test: powershell -ExecutionPolicy Bypass -File $scriptDir\run-campus-login.ps1"
  exit 0
}

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
try {
  if (-not (Test-Path $runKey)) {
    New-Item -Path $runKey -Force | Out-Null
  }
  Set-ItemProperty -Path $runKey -Name $runName -Value $action
  Write-Host "Task Scheduler create failed, fallback to HKCU Run startup entry installed: $runName"
  Write-Host "Startup command: $action"
} catch {
  Write-Host "Failed to install Task Scheduler entry and failed to write HKCU Run fallback."
  Write-Host "Please run this script in an elevated PowerShell window."
  exit 1
}
