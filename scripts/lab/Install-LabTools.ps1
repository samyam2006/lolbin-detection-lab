<#
.SYNOPSIS
    One-time setup inside the lab VM: Sysmon (with sysmon-modular config),
    PowerShell script block logging, and Atomic Red Team.

.DESCRIPTION
    RUN ONLY INSIDE AN ISOLATED LAB VM. It adds a Defender exclusion for
    C:\AtomicRedTeam so the test framework isn't quarantined. Never do that on
    your everyday computer.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$work = 'C:\LabTools'
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host '[1/4] Installing Sysmon' -ForegroundColor Cyan
Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$work\Sysmon.zip"
Expand-Archive "$work\Sysmon.zip" -DestinationPath "$work\Sysmon" -Force
Invoke-WebRequest 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml' `
    -OutFile "$work\sysmonconfig.xml"
& "$work\Sysmon\Sysmon64.exe" -accepteula -i "$work\sysmonconfig.xml"

Write-Host '[2/4] Enabling PowerShell script block logging' -ForegroundColor Cyan
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -Type DWord

Write-Host '[3/4] Adding Defender exclusion for C:\AtomicRedTeam (lab VM only)' -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path 'C:\AtomicRedTeam' | Out-Null
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam'

Write-Host '[4/4] Installing Atomic Red Team' -ForegroundColor Cyan
Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

Write-Host "`nSetup complete. Take a VM snapshot named 'tools-installed' now." -ForegroundColor Green
