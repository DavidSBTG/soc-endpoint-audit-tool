$since = (Get-Date).AddDays(-7)

Write-Host "==== FAILED LOGINS ===="
Get-WinEvent -FilterHashtable @{
LogName='Security'
ID=4625
StartTime=$since
} | Select TimeCreated,Message -First 20


Write-Host "==== NEW USERS ===="
Get-WinEvent -FilterHashtable @{
LogName='Security'
ID=4720
StartTime=$since
} | Select TimeCreated,Message


Write-Host "==== ADMIN PRIVILEGES ADDED ===="
Get-WinEvent -FilterHashtable @{
LogName='Security'
ID=4732
StartTime=$since
} | Select TimeCreated,Message


Write-Host "==== SUSPICIOUS PROCESS CREATION ===="
Get-WinEvent -FilterHashtable @{
LogName='Microsoft-Windows-Sysmon/Operational'
ID=1
StartTime=$since
} | Where-Object {
$_.Message -match "powershell|cmd.exe|wscript|cscript|rundll32"
} | Select TimeCreated,Message -First 20


Write-Host "==== NETWORK CONNECTIONS ===="
Get-WinEvent -FilterHashtable @{
LogName='Microsoft-Windows-Sysmon/Operational'
ID=3
StartTime=$since
} | Select TimeCreated,Message -First 20


Write-Host "==== DEFENDER ALERTS ===="
Get-WinEvent -FilterHashtable @{
LogName='Microsoft-Windows-Windows Defender/Operational'
StartTime=$since
} | Where-Object {
$_.Id -eq 1116
} | Select TimeCreated,Message