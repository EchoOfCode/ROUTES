# Create .env from .env.example with freshly generated secrets (Windows).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (Test-Path .env) { Write-Host ".env already exists; leaving it unchanged."; exit 0 }
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
