$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$taskName = 'CampusNetAutoLogin'
$runName = 'CampusNetAutoLogin'

$wscript = "$env:WINDIR\System32\wscript.exe"
$hiddenLauncher = "$scriptDir\run-campus-login-hidden.vbs"
# schtasks /TR needs the entire command in one quoted string with escaped inner quotes
$trValue = """$wscript"" ""$hiddenLauncher"""

try {
  $null = & schtasks /Query /TN $taskName 2>$null
}
catch {}
if ($LASTEXITCODE -eq 0) {
  try {
    & schtasks /Delete /TN $taskName /F 2>$null | Out-Null
  }
  catch {}
}

try {
  $null = & schtasks /Create /TN $taskName /SC ONLOGON /TR $trValue /RL LIMITED /F 2>$null
}
catch {}
try {
  $null = & schtasks /Query /TN $taskName 2>$null
}
catch {}
if ($LASTEXITCODE -eq 0) {
  # Fix battery settings so the task runs on laptops
  try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
      $task.Settings.DisallowStartIfOnBatteries = $false
      $task.Settings.StopIfGoingOnBatteries = $false
      $task | Set-ScheduledTask | Out-Null
    }
  }
  catch {}
  Write-Host "Task installed: $taskName (runs on battery, hidden window)"
  Write-Host "Run now to test: powershell -ExecutionPolicy Bypass -File $scriptDir\run-campus-login.ps1"
  exit 0
}

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
try {
  if (-not (Test-Path $runKey)) {
    New-Item -Path $runKey -Force | Out-Null
  }
  Set-ItemProperty -Path $runKey -Name $runName -Value $trValue
  Write-Host "Task Scheduler create failed, fallback to HKCU Run startup entry installed: $runName"
  Write-Host "Startup command: $trValue"
}
catch {
  Write-Host "Failed to install Task Scheduler entry and failed to write HKCU Run fallback."
  Write-Host "Please run this script in an elevated PowerShell window."
  exit 1
}
