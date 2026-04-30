param(
    [switch]$Deep,
    [switch]$Hashes,
    [switch]$VerboseMode,
    [int]$LookbackDays = 7,
    [string]$OutputDir = "$env:TEMP\SOC_Audit_Enhanced"
)

if ($VerboseMode) { $VerbosePreference = 'Continue' }
$ErrorActionPreference = 'SilentlyContinue'

function Write-Section {
    param([string]$Text)
    Write-Host "`n==== $Text ====" -ForegroundColor Cyan
}

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileHashSafe {
    param([string]$Path)
    try {
        if (Test-Path $Path -PathType Leaf) {
            return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
        }
    } catch {}
    return $null
}

function Add-Finding {
    param(
        [ref]$List,
        [string]$Category,
        [string]$Severity,
        [string]$Title,
        [string]$Details,
        [object]$Data = $null
    )
    $List.Value.Add([pscustomobject]@{
        TimeUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Category = $Category
        Severity = $Severity
        Title    = $Title
        Details  = $Details
        Data     = $Data
    }) | Out-Null
}

function Get-SystemSummary {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        Domain = $env:USERDOMAIN
        Caption = $os.Caption
        Version = $os.Version
        BuildNumber = $os.BuildNumber
        InstallDate = $os.InstallDate
        LastBootUpTime = $os.LastBootUpTime
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        BIOSVersion = (($bios.SMBIOSBIOSVersion -join ', '))
        SecureBoot = (Confirm-SecureBootUEFI 2>$null)
        DeviceGuardSecurityServicesConfigured = ($dg.SecurityServicesConfigured -join ', ')
        DeviceGuardSecurityServicesRunning = ($dg.SecurityServicesRunning -join ', ')
        VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
    }
}

function Get-WmiPersistence {
    $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding

    [pscustomobject]@{
        Filters = $filters | Select-Object Name, Query, EventNamespace
        Consumers = $consumers | Select-Object Name, CommandLineTemplate, ExecutablePath
        Bindings = $bindings | Select-Object Filter, Consumer
    }
}

function Get-SuspiciousServices {
    $suspiciousPatterns = 'temp','appdata','powershell','cmd.exe','wscript','cscript','rundll32','users\\','programdata'
    $services = Get-CimInstance Win32_Service | ForEach-Object {
        $suspicious = $false
        foreach ($pattern in $suspiciousPatterns) {
            if ($_.PathName -match $pattern) { $suspicious = $true; break }
        }
        [pscustomobject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            State = $_.State
            StartMode = $_.StartMode
            PathName = $_.PathName
            StartName = $_.StartName
            Suspicious = $suspicious
            SHA256 = if ($Hashes -and $_.PathName) {
                $cleanPath = ($_.PathName -replace '^"|"$','') -replace '\s+-.+$',''
                Get-FileHashSafe -Path $cleanPath
            } else { $null }
        }
    }
    $services
}

function Get-SuspiciousDrivers {
    $drivers = Get-CimInstance Win32_SystemDriver | ForEach-Object {
        $path = $_.PathName
        $flag = $false
        if ($path -match 'temp|appdata|users\\|programdata') { $flag = $true }
        [pscustomobject]@{
            Name = $_.Name
            State = $_.State
            StartMode = $_.StartMode
            PathName = $path
            Suspicious = $flag
            SHA256 = if ($Hashes -and $path) {
                $cleanPath = ($path -replace '^"|"$','') -replace '\s+-.+$',''
                Get-FileHashSafe -Path $cleanPath
            } else { $null }
        }
    }
    $drivers
}

function Get-RecentEvents {
    param([datetime]$StartTime)

    $eventMap = @(
        @{Log='Security'; Id=4625; Label='Failed logons'},
        @{Log='Security'; Id=4624; Label='Successful logons'},
        @{Log='Security'; Id=4672; Label='Special privileges assigned'},
        @{Log='Security'; Id=4688; Label='Process creation'},
        @{Log='Security'; Id=4720; Label='User account created'},
        @{Log='Security'; Id=4728; Label='User added to privileged global group'},
        @{Log='Security'; Id=4732; Label='User added to privileged local group'},
        @{Log='Microsoft-Windows-Windows Defender/Operational'; Id=$null; Label='Windows Defender'},
        @{Log='Microsoft-Windows-Sysmon/Operational'; Id=$null; Label='Sysmon'}
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $eventMap) {
        try {
            if ($null -ne $entry.Id) {
                $events = Get-WinEvent -FilterHashtable @{LogName=$entry.Log; Id=$entry.Id; StartTime=$StartTime} -MaxEvents 200
            } else {
                $events = Get-WinEvent -FilterHashtable @{LogName=$entry.Log; StartTime=$StartTime} -MaxEvents 200
            }
            foreach ($event in $events) {
                $results.Add([pscustomobject]@{
                    Label = $entry.Label
                    LogName = $event.LogName
                    Id = $event.Id
                    TimeCreated = $event.TimeCreated
                    ProviderName = $event.ProviderName
                    LevelDisplayName = $event.LevelDisplayName
                    Message = $event.Message
                }) | Out-Null
            }
        } catch {}
    }
    $results
}

function Get-ScheduledTasksAudit {
    $tasks = Get-ScheduledTask | ForEach-Object {
        $actions = $_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }
        $suspicious = $false
        foreach ($a in $actions) {
            if ($a -match 'powershell|cmd.exe|wscript|cscript|rundll32|appdata|temp|downloadstring|iex\s') {
                $suspicious = $true
                break
            }
        }
        [pscustomobject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State = $_.State
            Author = $_.Author
            UserId = $_.Principal.UserId
            RunLevel = $_.Principal.RunLevel
            Actions = ($actions -join '; ')
            Suspicious = $suspicious
        }
    }
    $tasks
}

function Get-RegistryPersistence {
    $runPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $items = foreach ($path in $runPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch '^PS') {
                    $value = [string]$p.Value
                    [pscustomobject]@{
                        Path = $path
                        Name = $p.Name
                        Value = $value
                        Suspicious = ($value -match 'appdata|temp|powershell|cmd.exe|wscript|cscript|rundll32|mshta|bitsadmin|certutil')
                    }
                }
            }
        }
    }
    $items
}

function Get-NetworkAudit {
    $connections = Get-NetTCPConnection | ForEach-Object {
        $proc = $null
        try { $proc = Get-Process -Id $_.OwningProcess } catch {}
        [pscustomobject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            OwningProcess = $_.OwningProcess
            ProcessName = $proc.ProcessName
            Suspicious = (
                $_.State -eq 'Established' -and
                $_.RemoteAddress -notmatch '^(127\.|0\.0\.0\.0|::1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.)'
            )
        }
    }
    $connections
}

function Get-DefenderStatus {
    $mp = Get-MpComputerStatus
    [pscustomobject]@{
        AMServiceEnabled = $mp.AMServiceEnabled
        AntispywareEnabled = $mp.AntispywareEnabled
        AntivirusEnabled = $mp.AntivirusEnabled
        BehaviorMonitorEnabled = $mp.BehaviorMonitorEnabled
        IoavProtectionEnabled = $mp.IoavProtectionEnabled
        NISEnabled = $mp.NISEnabled
        RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
        DefenderSignaturesOutOfDate = $mp.DefenderSignaturesOutOfDate
        QuickScanAge = $mp.QuickScanAge
        FullScanAge = $mp.FullScanAge
        EngineVersion = $mp.AMEngineVersion
        SignatureVersion = $mp.AntivirusSignatureVersion
    }
}

$admin = Test-Admin
$start = (Get-Date).AddDays(-$LookbackDays)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()

Write-Section 'Collecting system summary'
$system = Get-SystemSummary

Write-Section 'Checking WMI persistence'
$wmi = Get-WmiPersistence
if (($wmi.Filters | Measure-Object).Count -gt 0 -or ($wmi.Consumers | Measure-Object).Count -gt 0) {
    Add-Finding -List ([ref]$findings) -Category 'Persistence' -Severity 'Medium' -Title 'WMI subscription objects found' -Details 'Review WMI EventFilter / Consumer / Binding entries. Some are legitimate, but attackers often abuse them for persistence.' -Data $wmi
}

Write-Section 'Auditing services'
$services = Get-SuspiciousServices
$suspiciousServices = $services | Where-Object { $_.Suspicious }
foreach ($svc in $suspiciousServices) {
    Add-Finding -List ([ref]$findings) -Category 'Persistence' -Severity 'Medium' -Title "Suspicious service path: $($svc.Name)" -Details $svc.PathName -Data $svc
}

Write-Section 'Auditing drivers'
$drivers = Get-SuspiciousDrivers
$suspiciousDrivers = $drivers | Where-Object { $_.Suspicious }
foreach ($drv in $suspiciousDrivers) {
    Add-Finding -List ([ref]$findings) -Category 'Kernel' -Severity 'High' -Title "Suspicious driver path: $($drv.Name)" -Details $drv.PathName -Data $drv
}

Write-Section 'Reviewing scheduled tasks'
$tasks = Get-ScheduledTasksAudit
$suspiciousTasks = $tasks | Where-Object { $_.Suspicious }
foreach ($task in $suspiciousTasks) {
    Add-Finding -List ([ref]$findings) -Category 'Persistence' -Severity 'Medium' -Title "Suspicious scheduled task: $($task.TaskName)" -Details $task.Actions -Data $task
}

Write-Section 'Reviewing registry persistence'
$registry = Get-RegistryPersistence
$suspiciousRegistry = $registry | Where-Object { $_.Suspicious }
foreach ($item in $suspiciousRegistry) {
    Add-Finding -List ([ref]$findings) -Category 'Persistence' -Severity 'Medium' -Title "Suspicious autorun registry value: $($item.Name)" -Details $item.Value -Data $item
}

Write-Section 'Reviewing network connections'
$network = Get-NetworkAudit
$suspiciousConnections = $network | Where-Object { $_.Suspicious }
foreach ($conn in $suspiciousConnections) {
    Add-Finding -List ([ref]$findings) -Category 'Network' -Severity 'Medium' -Title "External established connection by $($conn.ProcessName)" -Details "$($conn.RemoteAddress):$($conn.RemotePort)" -Data $conn
}

Write-Section 'Reviewing Defender status'
$defender = Get-DefenderStatus
if (-not $defender.RealTimeProtectionEnabled) {
    Add-Finding -List ([ref]$findings) -Category 'Defender' -Severity 'High' -Title 'Microsoft Defender Real-Time Protection disabled' -Details 'Real-time protection is not enabled.' -Data $defender
}
if ($defender.DefenderSignaturesOutOfDate) {
    Add-Finding -List ([ref]$findings) -Category 'Defender' -Severity 'Medium' -Title 'Microsoft Defender signatures are out of date' -Details 'Update signatures immediately.' -Data $defender
}

Write-Section 'Reviewing recent security events'
$events = Get-RecentEvents -StartTime $start
$failedLogons = $events | Where-Object { $_.Id -eq 4625 }
if (($failedLogons | Measure-Object).Count -ge 10) {
    Add-Finding -List ([ref]$findings) -Category 'Identity' -Severity 'Medium' -Title 'High number of failed logons detected' -Details "Failed logons in lookback window: $(($failedLogons | Measure-Object).Count)" -Data ($failedLogons | Select-Object -First 20)
}

$privilegedGroupChanges = $events | Where-Object { $_.Id -in 4728,4732,4672 }
if (($privilegedGroupChanges | Measure-Object).Count -gt 0) {
    Add-Finding -List ([ref]$findings) -Category 'Privilege' -Severity 'High' -Title 'Privileged account/group activity detected' -Details 'Review special privileges assignments and group membership changes.' -Data ($privilegedGroupChanges | Select-Object -First 20)
}

$userCreations = $events | Where-Object { $_.Id -eq 4720 }
if (($userCreations | Measure-Object).Count -gt 0) {
    Add-Finding -List ([ref]$findings) -Category 'Identity' -Severity 'High' -Title 'New local/domain user creation detected' -Details 'Review newly created accounts.' -Data ($userCreations | Select-Object -First 20)
}

$report = [pscustomobject]@{
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    Admin = $admin
    Deep = [bool]$Deep
    Hashes = [bool]$Hashes
    LookbackDays = $LookbackDays
    SystemSummary = $system
    DefenderStatus = $defender
    Findings = $findings
    WmiPersistence = $wmi
    Services = $services
    Drivers = $drivers
    ScheduledTasks = $tasks
    RegistryPersistence = $registry
    NetworkConnections = $network
    RecentEvents = $events
}

$jsonPath = Join-Path $OutputDir 'SOC_Endpoint_Audit_Enhanced.json'
$htmlPath = Join-Path $OutputDir 'SOC_Endpoint_Audit_Enhanced.html'

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

# Build HTML rows for findings
$findingsRows = ""

foreach ($f in $findings) {

    $class = switch ($f.Severity) {
        "High" { "bad-high" }
        "Medium" { "bad-medium" }
        default { "ok" }
    }

    $findingsRows += "<tr>"
    $findingsRows += "<td class='$class'>$($f.Severity)</td>"
    $findingsRows += "<td>$($f.Category)</td>"
    $findingsRows += "<td>$($f.Title)</td>"
    $findingsRows += "<td>$($f.Details)</td>"
    $findingsRows += "</tr>`n"
}
$html = @"
<html>
<head>
<title>SOC Endpoint Audit Enhanced</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0b1020; color: #e6edf3; }
h1, h2 { color: #7dd3fc; }
table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
th, td { border: 1px solid #334155; padding: 8px; vertical-align: top; }
th { background: #13203b; }
tr:nth-child(even) { background: #0f172a; }
.bad-high { color: #fca5a5; font-weight: bold; }
.bad-medium { color: #fde68a; font-weight: bold; }
.ok { color: #86efac; font-weight: bold; }
code { color: #c4b5fd; }
</style>
</head>
<body>
<h1>SOC Endpoint Audit Enhanced</h1>
<p><strong>Generated (UTC):</strong> $($report.GeneratedUtc)</p>
<p><strong>Computer:</strong> $($report.ComputerName)</p>
<p><strong>Admin:</strong> $($report.Admin)</p>
<p><strong>LookbackDays:</strong> $($report.LookbackDays)</p>

<h2>System Summary</h2>
<pre>$($system | Format-List | Out-String)</pre>

<h2>Top Findings</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>Title</th><th>Details</th></tr>
$findingsRows
</table>

<h2>Suspicious Services</h2>
<pre>$($suspiciousServices | Format-Table -AutoSize | Out-String)</pre>

<h2>Suspicious Drivers</h2>
<pre>$($suspiciousDrivers | Format-Table -AutoSize | Out-String)</pre>

<h2>Suspicious Scheduled Tasks</h2>
<pre>$($suspiciousTasks | Format-Table -AutoSize | Out-String)</pre>

<h2>Suspicious Autoruns</h2>
<pre>$($suspiciousRegistry | Format-Table -AutoSize | Out-String)</pre>

<h2>External Established Connections</h2>
<pre>$($suspiciousConnections | Format-Table -AutoSize | Out-String)</pre>

<h2>Recent Key Events</h2>
<pre>$($events | Select-Object -First 50 | Format-Table TimeCreated,LogName,Id,ProviderName,LevelDisplayName -AutoSize | Out-String)</pre>
</body>
</html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Host 'SOC Endpoint Audit Enhanced complete.' -ForegroundColor Green
Write-Host "JSON: $jsonPath"
Write-Host "HTML: $htmlPath"
Write-Host "Admin: $admin"
Write-Host "Deep: $Deep  Hashes: $Hashes"

if ($findings.Count -gt 0) {
    Write-Host "Top findings: $($findings.Count)" -ForegroundColor Yellow
    $findings | Select-Object Severity, Category, Title | Format-Table -AutoSize
} else {
    Write-Host 'No immediate high-confidence findings detected.' -ForegroundColor Green
}
