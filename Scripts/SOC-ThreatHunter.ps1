param(
    [string]$LogPath = "C:\Windows\System32\winevt\Logs\Security.evtx",
    [switch]$LiveMode,
    [switch]$VerboseMode
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " SOC Threat Hunting Engine (Level 3)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# -------------------------------------------------
# Detection Rules (MITRE mapped)
# -------------------------------------------------
$Detections = @(

    @{
        Name = "Multiple Failed Logins"
        EventID = 4625
        Threshold = 5
        MITRE = "T1110 - Brute Force"
    }

    @{
        Name = "New User Created"
        EventID = 4720
        MITRE = "T1136 - Create Account"
    }

    @{
        Name = "Privilege Escalation"
        EventID = 4672
        MITRE = "T1068 - Privilege Escalation"
    }

    @{
        Name = "Suspicious Process Execution"
        Keyword = "powershell"
        MITRE = "T1059 - Command Execution"
    }

    @{
        Name = "Defender Disabled"
        Keyword = "RealTimeProtectionEnabled False"
        MITRE = "T1562 - Defense Evasion"
    }

)

# -------------------------------------------------
# Event Collector
# -------------------------------------------------
function Get-Events {
    param($EventID)

    try {
        return Get-WinEvent -FilterHashtable @{LogName="Security"; ID=$EventID} -MaxEvents 200
    } catch {
        return @()
    }
}

# -------------------------------------------------
# Detection Engine
# -------------------------------------------------
$Findings = @()

foreach ($rule in $Detections) {

    if ($rule.EventID) {

        $events = Get-Events -EventID $rule.EventID

        if ($events.Count -gt ($rule.Threshold ? $rule.Threshold : 0)) {

            $Findings += [pscustomobject]@{
                Type = $rule.Name
                Count = $events.Count
                MITRE = $rule.MITRE
                Severity = "HIGH"
            }
        }
    }

    if ($rule.Keyword) {

        $processes = Get-Process | Where-Object {
            $_.ProcessName -match $rule.Keyword
        }

        if ($processes) {
            $Findings += [pscustomobject]@{
                Type = $rule.Name
                Count = $processes.Count
                MITRE = $rule.MITRE
                Severity = "MEDIUM"
            }
        }
    }
}

# -------------------------------------------------
# Output
# -------------------------------------------------
Write-Host ""
Write-Host "==== Threat Hunting Results ====" -ForegroundColor Yellow

if ($Findings.Count -eq 0) {
    Write-Host "No suspicious activity detected." -ForegroundColor Green
}
else {
    foreach ($f in $Findings) {
        Write-Host "[ALERT] $($f.Type)" -ForegroundColor Red
        Write-Host " MITRE: $($f.MITRE)"
        Write-Host " Count: $($f.Count)"
        Write-Host " Severity: $($f.Severity)"
        Write-Host ""
    }
}

Write-Host "Scan complete." -ForegroundColor Cyan