$ErrorActionPreference = 'Stop'
$taskName = 'CampusNetAutoLogin'
$runName = 'CampusNetAutoLogin'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

function Remove-ScheduledTaskSafe {
  param([string]$Name)
  try {
    $null = & schtasks /Query /TN $Name 2>$null
  } catch {}

  if ($LASTEXITCODE -eq 0) {
    try {
      $null = & schtasks /Delete /TN $Name /F 2>$null
      if ($LASTEXITCODE -eq 0) {
        Write-Host "Deleted scheduled task: $Name"
      } else {
        Write-Host "Failed to delete scheduled task: $Name"
      }
    } catch {
      Write-Host "Failed to delete scheduled task: $Name"
    }
  } else {
    Write-Host "Scheduled task not found: $Name"
  }
}

function Remove-RunEntrySafe {
  param(
    [string]$Key,
    [string]$Name
  )
  try {
    $item = Get-ItemProperty -Path $Key -Name $Name -ErrorAction Stop
    if ($null -ne $item) {
      Remove-ItemProperty -Path $Key -Name $Name -ErrorAction Stop
      Write-Host "Deleted startup Run entry: $Name"
      return
    }
  } catch {}
  Write-Host "Startup Run entry not found: $Name"
}

Remove-ScheduledTaskSafe -Name $taskName
Remove-RunEntrySafe -Key $runKey -Name $runName

Write-Host "Uninstall complete."
