# Create .env from .env.example with freshly generated secrets (Windows).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (Test-Path .env) {
  Write-Host ".env exists; synchronizing any missing keys from .env.example..."
  $existingKeys = @{}
  Get-Content .env | ForEach-Object {
    if ($_ -match '^([A-Za-z0-9_]+)=') { $existingKeys[$matches[1]] = $true }
  }
  $missing = @()
  $inMissingBlock = $false
  Get-Content .env.example | ForEach-Object {
    if ($_ -match '^#') {
      $currentComment = $_
    } elseif ($_ -match '^([A-Za-z0-9_]+)=') {
      $key = $matches[1]
      if (-not $existingKeys.ContainsKey($key)) {
        $missing += $_
      }
    }
  }
  if ($missing.Count -gt 0) {
    Add-Content -Path .env -Value "`n# ---- Synchronized from .env.example ----"
    Add-Content -Path .env -Value $missing
    Write-Host "Added $($missing.Count) missing configuration setting(s) to .env."
  } else {
    Write-Host ".env is fully up to date."
  }
  exit 0
}
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function New-Secret { $b = New-Object byte[] 32; $rng.GetBytes($b); ($b | ForEach-Object { $_.ToString("x2") }) -join "" }
$content = Get-Content .env.example | ForEach-Object {
  if ($_ -match '^POSTGRES_PASSWORD=') { "POSTGRES_PASSWORD=$(New-Secret)" }
  elseif ($_ -match '^SANDBOX_MANAGER_TOKEN=') { "SANDBOX_MANAGER_TOKEN=$(New-Secret)" }
  elseif ($_ -match '^GATEWAY_CONTROL_TOKEN=') { "GATEWAY_CONTROL_TOKEN=$(New-Secret)" }
  else { $_ }
}
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) ".env"), $content)
Write-Host "Created .env with random secrets."
