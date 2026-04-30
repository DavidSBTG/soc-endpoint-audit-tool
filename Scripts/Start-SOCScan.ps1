Write-Host ""
Write-Host "===================================="
Write-Host "   SOC Endpoint Security Scan"
Write-Host "===================================="
Write-Host ""

$scriptPath = Join-Path $PSScriptRoot "Invoke-SOCEndpointAudit.ps1"

if (Test-Path $scriptPath) {
    Write-Host "Starting SOC Audit..."
    & $scriptPath -Deep
}
else {
    Write-Host "Audit script not found!"
}