<#
.SYNOPSIS
  SOC Endpoint Audit for Windows (local host) - defensive.
  Produces JSON + HTML reports.

.DESIGN GOAL
  Cover typical SOC Analyst endpoint checks:
  - Posture/Hardening (Defender, ASR, Exploit Protection, Firewall, VBS/HVCI, LSA, UAC, BitLocker, SecureBoot, TPM)
  - Exposure (RDP/WinRM/SMB, listeners, shares)
  - Threat hunting indicators (persistence, suspicious processes, unsigned binaries sample, drivers, WMI subscriptions, autoruns paths)
  - Log signals (Security, Defender Operational; Sysmon optional)
  - Network config indicators (proxy, hosts, DNS, routes)

.USAGE
  powershell.exe -ExecutionPolicy Bypass -File .\Invoke-SOCEndpointAudit.ps1 -OutputDir "$env:USERPROFILE\Desktop\SOC_Audit" -Days 7 -Deep

.PARAMETERS
  -Days : number of days back for event logs
  -Deep : more expensive checks (signatures, hashes sample, startup enumeration)
  -IncludeHashes : compute SHA256 for suspicious files found (can be slow)
#>

[CmdletBinding()]
param(
  [string]$OutputDir = (Join-Path $env:TEMP "SOC_Audit"),
  [int]$Days = 7,
  [switch]$Deep,
  [switch]$IncludeHashes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# -----------------------------
# Helpers
# -----------------------------
function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Get-RegValue {
  param([string]$Path,[string]$Name)
  try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function New-Finding {
  param(
    [Parameter(Mandatory)] [string]$Category,
    [Parameter(Mandatory)] [string]$Title,
    [ValidateSet("OK","INFO","WARN","HIGH","CRIT","NA")] [string]$Severity = "INFO",
    [string]$Details = "",
    [hashtable]$Data
  )
  [pscustomobject]@{
    time     = (Get-Date).ToString("s")
    category = $Category
    title    = $Title
    severity = $Severity
    details  = $Details
    data     = $Data
  }
}

function Add-Finding {
  param([object]$Finding)
  $script:Report.findings.Add($Finding) | Out-Null
  switch ($Finding.severity) {
    "CRIT" { $script:Report.summary.crit++ }
    "HIGH" { $script:Report.summary.high++ }
    "WARN" { $script:Report.summary.warn++ }
    "INFO" { $script:Report.summary.info++ }
    "OK"   { $script:Report.summary.ok++ }
    "NA"   { $script:Report.summary.na++ }
  }
}

function Add-Section {
  param([string]$Name,[object]$Value)
  $script:Report.sections[$Name] = $Value
}

function Try-Run([scriptblock]$sb) {
  try { & $sb } catch { $null }
}

function Get-SHA256([string]$Path) {
  if (-not (Test-Path $Path)) { return $null }
  try { (Get-FileHash -Algorithm SHA256 -Path $Path -ErrorAction Stop).Hash } catch { $null }
}

function Test-SuspiciousPath([string]$s) {
  if (-not $s) { return $false }
  $lc = $s.ToLowerInvariant()
  return ($lc -match "\\appdata\\") -or ($lc -match "\\temp\\") -or ($lc -match "\\programdata\\") -or
         ($lc -match "\.ps1") -or ($lc -match "\.vbs") -or ($lc -match "\.js") -or ($lc -match "\.bat") -or
         ($lc -match "\.scr") -or ($lc -match "\.dll") -or ($lc -match "rundll32") -or ($lc -match "powershell")
}

function Try-GetEvents($FilterHashtable) {
  try { Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Stop } catch { $null }
}

# -----------------------------
# Report skeleton
# -----------------------------
$IsAdmin = Test-IsAdmin
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Report = [ordered]@{
  meta = [ordered]@{
    generatedAt = (Get-Date).ToString("s")
    computer    = $env:COMPUTERNAME
    user        = "$env:USERDOMAIN\$env:USERNAME"
    isAdmin     = $IsAdmin
    days        = $Days
    deep        = [bool]$Deep
    includeHashes = [bool]$IncludeHashes
  }
  summary = [ordered]@{ crit = 0; high = 0; warn = 0; info = 0; ok = 0; na = 0 }
  findings = New-Object System.Collections.Generic.List[object]
  sections = [ordered]@{}
}

$Since = (Get-Date).AddDays(-1 * $Days)

# -----------------------------
# 1) System / OS / Patch posture
# -----------------------------
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

Add-Section "system" ([ordered]@{
  osCaption    = $os.Caption
  osVersion    = $os.Version
  buildNumber  = $os.BuildNumber
  installDate  = $os.InstallDate
  lastBoot     = $os.LastBootUpTime
  manufacturer = $cs.Manufacturer
  model        = $cs.Model
  biosVendor   = $bios.Manufacturer
  biosVersion  = $bios.SMBIOSBIOSVersion
})

$hotfix = Try-Run { Get-HotFix | Sort-Object InstalledOn -Descending } 
Add-Section "hotfixes" ($hotfix | Select-Object -First 50)

if (-not $hotfix) {
  Add-Finding (New-Finding "Patching" "Hotfix history unavailable" "WARN" "Get-HotFix returned no results (WMI/Update history restricted).")
} else {
  $lastPatch = ($hotfix | Select-Object -First 1).InstalledOn
  if ($lastPatch -and $lastPatch -lt (Get-Date).AddDays(-45)) {
    Add-Finding (New-Finding "Patching" "Patches appear outdated" "WARN" "Last recorded hotfix older than ~45 days." @{ lastPatch="$lastPatch" })
  } else {
    Add-Finding (New-Finding "Patching" "Patch history present" "OK" "Recent hotfix history exists." @{ lastPatch="$lastPatch" })
  }
}

# Windows Update policy indicators
$wuAU = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
$wuWUServer = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
Add-Section "windowsUpdatePolicy" @{ NoAutoUpdate=$wuAU; WUServer=$wuWUServer }

# -----------------------------
# 2) Defender / Firewall / ASR / Exploit Protection
# -----------------------------
$mp = Try-Run { Get-MpComputerStatus }
$mpPref = $null

try {
    $service = Get-Service WinDefend -ErrorAction Stop

    if ($service.Status -eq "Running") {
        $mpPref = Get-MpPreference -ErrorAction Stop
    }
}
catch {
    Write-Host "[INFO] Defender preferences could not be read."
}

Add-Section "defenderStatus" $mp
Add-Section "defenderPreference" ($mpPref | Select-Object -Property * -ExcludeProperty Cim* )

if ($mp) {
  if (-not $mp.RealTimeProtectionEnabled -or -not $mp.AntispywareEnabled) {
    Add-Finding (New-Finding "Endpoint" "Defender not fully enabled" "HIGH" "Antispyware/Realtime protection OFF." @{
      AntispywareEnabled=$mp.AntispywareEnabled; RTP=$mp.RealTimeProtectionEnabled; AVEnabled=$mp.AntivirusEnabled
    })
  } else {
    Add-Finding (New-Finding "Endpoint" "Defender active" "OK" "Defender and real-time protection enabled.")
  }
} else {
  Add-Finding (New-Finding "Endpoint" "Defender status unavailable" "NA" "Defender cmdlets unavailable or Defender disabled.")
}

# ASR rules (if present)
$asr = $null
if ($mpPref) {
  $asr = [pscustomobject]@{
    AttackSurfaceReductionRules_Ids    = $mpPref.AttackSurfaceReductionRules_Ids
    AttackSurfaceReductionRules_Actions= $mpPref.AttackSurfaceReductionRules_Actions
    AttackSurfaceReductionOnlyExclusions= $mpPref.AttackSurfaceReductionOnlyExclusions
  }
}
Add-Section "asr" $asr

if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) {
  # Simple scoring: warn if none enabled (action 1=Block, 2=Audit, 6=Warn)
  $enabled = @()
  for ($i=0; $i -lt $mpPref.AttackSurfaceReductionRules_Ids.Count; $i++) {
    $enabled += [pscustomobject]@{
      Id = $mpPref.AttackSurfaceReductionRules_Ids[$i]
      Action = $mpPref.AttackSurfaceReductionRules_Actions[$i]
    }
  }
  $blockCount = ($enabled | Where-Object { $_.Action -eq 1 }).Count
  if ($blockCount -lt 3) {
    Add-Finding (New-Finding "Hardening" "ASR rules not strongly enforced" "WARN" "Few ASR rules in Block mode. Consider enabling key ASR rules." @{ blockCount=$blockCount })
  } else {
    Add-Finding (New-Finding "Hardening" "ASR rules present" "INFO" "ASR rules configured." @{ blockCount=$blockCount })
  }
} else {
  Add-Finding (New-Finding "Hardening" "ASR rules not available" "NA" "No ASR configuration found (depends on Defender/edition/policies).")
}

# Exploit Protection (system)
$exploit = Try-Run { Get-ProcessMitigation -System }
Add-Section "exploitProtectionSystem" $exploit
if ($exploit) {
  Add-Finding (New-Finding "Hardening" "Exploit Protection data collected" "INFO" "System mitigations retrieved.")
}

# Firewall profiles + inbound rules overview
$fwProfiles = Try-Run { Get-NetFirewallProfile }
$fwRulesInboundAllow = Try-Run { Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Select-Object -First 300 }
Add-Section "firewallProfiles" $fwProfiles
Add-Section "firewallInboundAllow_sample" $fwRulesInboundAllow

if ($fwProfiles) {
  $fwOff = $fwProfiles | Where-Object { $_.Enabled -ne $true }
  if ($fwOff) {
    Add-Finding (New-Finding "Network" "Windows Firewall disabled on a profile" "HIGH" "Enable firewall for Domain/Private/Public." @{ disabledProfiles = ($fwOff.Name -join ", ") })
  } else {
    Add-Finding (New-Finding "Network" "Windows Firewall enabled" "OK" "")
  }
}

# -----------------------------
# 3) Platform Security: Secure Boot / BitLocker / TPM / VBS-HVCI / Credential Guard
# -----------------------------
$secureBoot = Try-Run { Confirm-SecureBootUEFI }
Add-Section "secureBoot" $secureBoot

if ($secureBoot -eq $true) { Add-Finding (New-Finding "Platform" "Secure Boot ON" "OK") }
elseif ($secureBoot -eq $false) { Add-Finding (New-Finding "Platform" "Secure Boot OFF" "WARN" "Enable Secure Boot if supported.") }
else { Add-Finding (New-Finding "Platform" "Secure Boot unknown" "NA" "Not supported or not UEFI.") }

$bitlocker = Try-Run { Get-BitLockerVolume }
Add-Section "bitlocker" $bitlocker
if ($bitlocker) {
  $osVol = $bitlocker | Where-Object { $_.VolumeType -eq "OperatingSystem" } | Select-Object -First 1
  if ($osVol -and $osVol.ProtectionStatus -ne "On") {
    Add-Finding (New-Finding "Platform" "BitLocker OFF for OS volume" "WARN" "Disk encryption recommended." @{ MountPoint=$osVol.MountPoint; Status=$osVol.ProtectionStatus })
  } elseif ($osVol) {
    Add-Finding (New-Finding "Platform" "BitLocker ON for OS volume" "OK" @{ MountPoint=$osVol.MountPoint })
  }
} else {
  Add-Finding (New-Finding "Platform" "BitLocker status unavailable" "NA" "Requires edition/admin or BitLocker not present.")
}

$tpm = Try-Run { Get-Tpm }
Add-Section "tpm" $tpm
if ($tpm) {
  if ($tpm.TpmPresent -and $tpm.TpmReady) { Add-Finding (New-Finding "Platform" "TPM present/ready" "OK") }
  elseif ($tpm.TpmPresent -and -not $tpm.TpmReady) { Add-Finding (New-Finding "Platform" "TPM present but not ready" "WARN" "Initialize TPM if you use BitLocker/Windows Hello.") }
  else { Add-Finding (New-Finding "Platform" "No TPM detected" "INFO" "Not mandatory, but improves security features." ) }
}

# VBS / HVCI / Credential Guard signals (DeviceGuard)
$dg = Try-Run { Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard }
Add-Section "deviceGuard" $dg

if ($dg) {
  $cgRunning = ($dg.SecurityServicesRunning -contains 1) # Credential Guard
  $hvciRunning = ($dg.SecurityServicesRunning -contains 2) # HVCI
  if ($cgRunning) { Add-Finding (New-Finding "Hardening" "Credential Guard running" "OK") } else { Add-Finding (New-Finding "Hardening" "Credential Guard not running" "INFO" "Optional hardening for credential theft resistance.") }
  if ($hvciRunning) { Add-Finding (New-Finding "Hardening" "HVCI (Memory Integrity) running" "OK") } else { Add-Finding (New-Finding "Hardening" "HVCI (Memory Integrity) not running" "INFO" "Optional hardening; may be limited by drivers.") }
}

# UAC + LSA protection
$uac = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$lsa = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
Add-Section "uac" @{ EnableLUA=$uac }
Add-Section "lsaProtection" @{ RunAsPPL=$lsa }

if ($uac -eq 1) { Add-Finding (New-Finding "Hardening" "UAC enabled" "OK") }
elseif ($uac -eq 0) { Add-Finding (New-Finding "Hardening" "UAC disabled" "HIGH" "Enable UAC (EnableLUA=1).") }
else { Add-Finding (New-Finding "Hardening" "UAC unknown" "NA") }

if ($lsa -eq 1) { Add-Finding (New-Finding "Hardening" "LSA protection enabled" "OK") }
else { Add-Finding (New-Finding "Hardening" "LSA protection not enabled" "WARN" "Consider enabling RunAsPPL for LSASS protection." @{ RunAsPPL=$lsa }) }

# -----------------------------
# 4) Accounts / Privileges / Remote access exposure
# -----------------------------
$admins = Try-Run { Get-LocalGroupMember -Group "Administrators" }
$rdpUsers = Try-Run { Get-LocalGroupMember -Group "Remote Desktop Users" }
Add-Section "localAdmins" $admins
Add-Section "rdpUsers" $rdpUsers

if ($admins) {
  $c = ($admins | Measure-Object).Count
  if ($c -gt 3) { Add-Finding (New-Finding "Accounts" "Many local admins" "WARN" "Reduce admin membership to minimum." @{ count=$c }) }
  else { Add-Finding (New-Finding "Accounts" "Local admins count reasonable" "INFO" @{ count=$c }) }
} else { Add-Finding (New-Finding "Accounts" "Local admins unavailable" "NA" "Requires rights/edition.") }

# Guest account status
$guest = Try-Run { Get-LocalUser -Name "Guest" }
Add-Section "guestAccount" $guest
if ($guest) {
  if ($guest.Enabled) { Add-Finding (New-Finding "Accounts" "Guest account enabled" "HIGH" "Disable Guest account." ) }
  else { Add-Finding (New-Finding "Accounts" "Guest account disabled" "OK") }
}

# RDP enabled?
$rdp = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
Add-Section "rdpConfig" @{ fDenyTSConnections=$rdp }
if ($rdp -eq 0) { Add-Finding (New-Finding "Exposure" "RDP enabled" "WARN" "If not needed, disable. If needed: NLA + firewall scope + strong auth.") }
elseif ($rdp -eq 1) { Add-Finding (New-Finding "Exposure" "RDP disabled" "OK") }

# WinRM enabled?
$winrm = Try-Run { Get-Service WinRM }
Add-Section "winrmService" $winrm
if ($winrm) {
  if ($winrm.Status -eq "Running") { Add-Finding (New-Finding "Exposure" "WinRM running" "INFO" "Ensure firewall scope/auth hardening if you use it.") }
  else { Add-Finding (New-Finding "Exposure" "WinRM not running" "OK") }
}

# SMBv1
$smb1 = Try-Run { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State }
Add-Section "smb1" @{ state=$smb1 }
if ($smb1 -eq "Enabled") { Add-Finding (New-Finding "Exposure" "SMBv1 enabled" "HIGH" "Disable SMBv1 (legacy/high risk).") }
elseif ($smb1 -eq "Disabled") { Add-Finding (New-Finding "Exposure" "SMBv1 disabled" "OK") }

# -----------------------------
# 5) Network: listeners, connections, DNS/Proxy/Hosts, routes
# -----------------------------
$procs = Get-Process | Select-Object Id,ProcessName,Path
$listeners = Try-Run { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess }
$listenerEnriched = @()
if ($listeners) {
  foreach ($l in $listeners) {
    $p = $procs | Where-Object { $_.Id -eq $l.OwningProcess } | Select-Object -First 1
    $listenerEnriched += [pscustomobject]@{
      LocalAddress=$l.LocalAddress; LocalPort=$l.LocalPort; OwningProcess=$l.OwningProcess
      ProcessName=$p.ProcessName; Path=$p.Path
    }
  }
}
Add-Section "listeningPorts" $listenerEnriched

$riskyPorts = @(3389,445,139,5985,5986,22,80,443,21,23,3306,5432)
$exposed = $listenerEnriched | Where-Object { ($riskyPorts -contains $_.LocalPort) -and (($_.LocalAddress -eq "0.0.0.0") -or ($_.LocalAddress -eq "::")) }
if ($exposed) {
  Add-Finding (New-Finding "Exposure" "Risky common ports listening on all interfaces" "WARN" "Review/disable or restrict via firewall." @{ exposed=($exposed | Select-Object LocalPort,ProcessName,Path) })
} else {
  Add-Finding (New-Finding "Exposure" "No common risky ports listening on all interfaces" "OK")
}

# Active connections (sample for hunting)
$conns = Try-Run { Get-NetTCPConnection | Where-Object { $_.State -in @("Established","SynSent","CloseWait") } | Select-Object -First 500 }
Add-Section "tcpConnections_sample" $conns

# DNS + proxy + hosts file
$dns = Try-Run { Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses }
$proxy = @{
  WinINET_ProxyEnable = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable"
  WinINET_ProxyServer = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
  WinHTTP_Proxy       = (Try-Run { netsh winhttp show proxy }) -join "`n"
}
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hosts = Try-Run { Get-Content $hostsPath -ErrorAction Stop }
Add-Section "dnsServers" $dns
Add-Section "proxy" $proxy
Add-Section "hostsFile" $hosts

if ($proxy.WinINET_ProxyEnable -eq 1 -and $proxy.WinINET_ProxyServer) {
  Add-Finding (New-Finding "Network" "User proxy enabled" "INFO" "Verify proxy legitimacy (malware sometimes sets proxy)." @{ ProxyServer=$proxy.WinINET_ProxyServer })
}

# Routes
$routes = Try-Run { Get-NetRoute | Select-Object -First 300 }
Add-Section "routes_sample" $routes

# -----------------------------
# 6) Shares / Remote file exposure
# -----------------------------
$shares = Try-Run { Get-SmbShare | Select-Object Name,Path,Description,FolderEnumerationMode,EncryptData,ConcurrentUserLimit }
Add-Section "smbShares" $shares

# -----------------------------
# 7) Persistence / Autoruns-style checks
# -----------------------------
# Run keys
$runHKLM = Try-Run { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" }
$runHKCU = Try-Run { Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" }
Add-Section "runKeys" @{ HKLM=$runHKLM; HKCU=$runHKCU }

$suspRun = @()
foreach ($rk in @(@{Hive="HKLM";Obj=$runHKLM}, @{Hive="HKCU";Obj=$runHKCU})) {
  if ($rk.Obj) {
    $rk.Obj.PSObject.Properties | ForEach-Object {
      if ($_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
        if (Test-SuspiciousPath $_.Value) { $suspRun += [pscustomobject]@{ Hive=$rk.Hive; Name=$_.Name; Value=$_.Value } }
      }
    }
  }
}
if ($suspRun.Count -gt 0) {
  Add-Finding (New-Finding "Persistence" "Suspicious Run-key entries (heuristic)" "WARN" "Review autoruns pointing to AppData/Temp/scripts." @{ entries=$suspRun })
} else {
  Add-Finding (New-Finding "Persistence" "No obvious suspicious Run-key autoruns" "OK")
}

# Startup folders
$startup = @()
$startupPaths = @(
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($p in $startupPaths) {
  if (Test-Path $p) { $startup += Get-ChildItem $p -Force | Select-Object FullName,Name,Length,LastWriteTime }
}
Add-Section "startupFolderItems" $startup

# Scheduled tasks (deep dive if -Deep)
if ($Deep) {
  $tasks = Try-Run { Get-ScheduledTask }
  $taskDetails = @()
  foreach ($t in ($tasks | Select-Object -First 800)) {
    $ti = Try-Run { Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath }
    $act = $t.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }
    $taskDetails += [pscustomobject]@{
      TaskName=$t.TaskName; TaskPath=$t.TaskPath; State=$t.State
      Actions=($act -join " | ")
      LastRunTime=$ti.LastRunTime; NextRunTime=$ti.NextRunTime
    }
  }
  Add-Section "scheduledTasks_details" $taskDetails
}

# WMI permanent event subscriptions (classic persistence)
$wmiFilter = Try-Run { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter }
$wmiConsumer = Try-Run { Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer }
$wmiBinding = Try-Run { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding }
Add-Section "wmiSubscriptions" @{ Filters=$wmiFilter; Consumers=$wmiConsumer; Bindings=$wmiBinding }

if (($wmiFilter | Measure-Object).Count -gt 0 -or ($wmiConsumer | Measure-Object).Count -gt 0) {
  Add-Finding (New-Finding "Persistence" "WMI subscription objects present" "INFO" "WMI subscriptions can be legitimate but are also used for persistence. Review if unexpected.")
}

# Services: suspicious service paths
$services = Try-Run { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName }
Add-Section "services" ($services | Select-Object -First 800)

$suspSvc = $services | Where-Object { $_.PathName -and (Test-SuspiciousPath $_.PathName) -and $_.StartMode -in @("Auto","Automatic") } | Select-Object -First 50
if ($suspSvc) {
  Add-Finding (New-Finding "Persistence" "Suspicious auto-start service paths (heuristic)" "WARN" "Auto-start services pointing to AppData/Temp/scripts can be suspicious." @{ sample=$suspSvc })
}

# -----------------------------
# 8) Integrity: unsigned processes sample + drivers
# -----------------------------
$unsigned = @()
$running = Get-Process | Where-Object { $_.Path } | Select-Object -First 300
foreach ($p in $running) {
  $sig = Try-Run { Get-AuthenticodeSignature -FilePath $p.Path }
  if ($sig -and $sig.Status -ne "Valid") {
    $row = [ordered]@{ ProcessName=$p.ProcessName; Path=$p.Path; Signature=$sig.Status }
    if ($IncludeHashes) { $row.SHA256 = Get-SHA256 $p.Path }
    $unsigned += [pscustomobject]$row
  }
}
Add-Section "unsignedProcessSample" $unsigned

# Drivers (kernel exposure)
$drivers = Try-Run { Get-CimInstance Win32_SystemDriver | Select-Object Name,State,StartMode,PathName }
Add-Section "drivers" ($drivers | Select-Object -First 800)

# -----------------------------
# 9) Software inventory (vuln mgmt surrogate)
# -----------------------------
# Note: real Vulnerability Management requires a scanner/EDR feed.
# Here: list installed software for review + flag "old" if install date unknown.
$uninstallPaths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$apps = @()
foreach ($p in $uninstallPaths) {
  $apps += Try-Run { Get-ItemProperty $p | Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation }
}
$apps = $apps | Sort-Object DisplayName -Unique
Add-Section "installedSoftware" ($apps | Select-Object -First 1200)

Add-Finding (New-Finding "VulnMgmt" "Installed software inventory collected" "INFO" "For true vulnerability status, pair this with Defender Vulnerability Management / a scanner.")

# -----------------------------
# 10) Logs: Security + Defender + Sysmon (optional)
# -----------------------------
$logSummary = [ordered]@{}

# Security: 4625 failed logons
$e4625 = Try-GetEvents @{ LogName="Security"; Id=4625; StartTime=$Since }
if ($e4625) {
  $c = ($e4625 | Measure-Object).Count
  $logSummary["4625_failed_logons"] = $c
  if ($c -gt 50) { Add-Finding (New-Finding "Logs" "High failed logons (4625)" "WARN" "Check account + source fields for brute force vs typos." @{ count=$c }) }
  else { Add-Finding (New-Finding "Logs" "Failed logons (4625) observed" "INFO" @{ count=$c }) }
} else { Add-Finding (New-Finding "Logs" "Security log (4625) unavailable" "NA" "Run as admin / enable auditing.") }

# Security: new user / group changes
$e4720 = Try-GetEvents @{ LogName="Security"; Id=4720; StartTime=$Since }  # new local user
$e4728 = Try-GetEvents @{ LogName="Security"; Id=4728; StartTime=$Since }  # member added to security-enabled global group (domain mostly)
$e4732 = Try-GetEvents @{ LogName="Security"; Id=4732; StartTime=$Since }  # member added to local group
if ($e4720) { $logSummary["4720_new_user"] = ($e4720 | Measure-Object).Count }
if ($e4732) { $logSummary["4732_local_group_member_added"] = ($e4732 | Measure-Object).Count }

# Defender Operational (threat detections)
$defLog = Try-GetEvents @{ LogName="Microsoft-Windows-Windows Defender/Operational"; StartTime=$Since }
if ($defLog) {
  $threats = $defLog | Where-Object { $_.Id -in @(1116,1117,5007) } | Select-Object -First 200
  $logSummary["defender_operational_sampleCount"] = ($threats | Measure-Object).Count
  Add-Section "defenderOperationalEvents_sample" $threats
  if (($threats | Measure-Object).Count -gt 0) {
    Add-Finding (New-Finding "Logs" "Defender events detected (Operational)" "INFO" "Review event IDs 1116/1117/5007 in report sample.")
  }
} else {
  Add-Finding (New-Finding "Logs" "Defender Operational log unavailable" "NA" "Log not accessible/disabled.")
}

# Sysmon (if installed)
$sysmon = Try-GetEvents @{ LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=$Since }
if ($sysmon) {
  $logSummary["sysmon_present"] = $true
  $sysmonSample = $sysmon | Select-Object -First 200
  Add-Section "sysmonEvents_sample" $sysmonSample
  Add-Finding (New-Finding "Logs" "Sysmon detected" "OK" "Sysmon Operational log present (great for SOC hunting).")
} else {
  $logSummary["sysmon_present"] = $false
  Add-Finding (New-Finding "Logs" "Sysmon not detected" "INFO" "Optional: install Sysmon for deeper telemetry.")
}

Add-Section "eventLogSummary" $logSummary

# -----------------------------
# Export: JSON + HTML
# -----------------------------
$reportObj = [pscustomobject]$Report
$jsonPath = Join-Path $OutputDir "SOC_Endpoint_Audit.json"
$htmlPath = Join-Path $OutputDir "SOC_Endpoint_Audit.html"

$reportObj | ConvertTo-Json -Depth 7 | Out-File -Encoding UTF8 $jsonPath

$sevOrder = @{ CRIT=0; HIGH=1; WARN=2; INFO=3; OK=4; NA=5 }
$findingsSorted = $reportObj.findings | Sort-Object @{ Expression = { $sevOrder[$_.severity] } }, category, title

$rows = $findingsSorted | ForEach-Object {
  "<tr class='$($_.severity)'><td>$($_.severity)</td><td>$($_.category)</td><td>$($_.title)</td><td>$($_.details)</td></tr>"
}

$metaTable = ($reportObj.meta.PSObject.Properties | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Value)</td></tr>" }) -join "`n"
$sumTable  = ($reportObj.summary.PSObject.Properties | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Value)</td></tr>" }) -join "`n"

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>SOC Endpoint Audit</title>
<style>
  body{font-family:Segoe UI,Arial;margin:20px}
  table{border-collapse:collapse;width:100%;margin-bottom:18px}
  th,td{border:1px solid #ddd;padding:8px;vertical-align:top}
  th{background:#f4f4f4}
  .CRIT{background:#ffb3b3}
  .HIGH{background:#ffd1a6}
  .WARN{background:#fff0b3}
  .OK{background:#c8f7c5}
  .NA{background:#e6e6e6}
</style>
</head>
<body>
<h1>SOC Endpoint Audit</h1>

<h2>Meta</h2>
<table><tr><th>Key</th><th>Value</th></tr>
$metaTable
</table>

<h2>Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
$sumTable
</table>

<h2>Findings</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>Title</th><th>Details</th></tr>
$($rows -join "`n")
</table>

<p><b>Outputs:</b><br/>$jsonPath<br/>$htmlPath</p>
</body>
</html>
"@

$html | Out-File -Encoding UTF8 $htmlPath

Write-Host "SOC Endpoint Audit complete."
Write-Host "JSON: $jsonPath"
Write-Host "HTML: $htmlPath"
Write-Host "Admin: $IsAdmin"
Write-Host "Deep: $Deep  Hashes: $IncludeHashes"