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
# Windows PowerShell 5.1 downloads are very slow with the progress bar on.
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = 'C:\LabTools'
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host '[1/4] Installing Sysmon' -ForegroundColor Cyan
Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$work\Sysmon.zip" -UseBasicParsing
Expand-Archive "$work\Sysmon.zip" -DestinationPath "$work\Sysmon" -Force
# sysmon-modular ships merged configs as release assets. I use the "balanced" profile
# plus one extra include: its WMIC rule matches OriginalFileName "wmic.exe", but WMIC's
# version resource reports "wmic.exe.mui", so WMIC launches were silently not logged
# (see docs/build-log.md). The "excludes-only" profile logged nothing at all in testing.
Invoke-WebRequest 'https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml' `
    -OutFile "$work\sysmonconfig-balanced.xml" -UseBasicParsing
$extra = '<RuleGroup name="lab-wmic" groupRelation="or"><ProcessCreate onmatch="include"><Image condition="end with">\WMIC.exe</Image></ProcessCreate></RuleGroup>'
(Get-Content "$work\sysmonconfig-balanced.xml" -Raw) -replace '<EventFiltering>', "<EventFiltering>`n$extra" |
    Set-Content "$work\sysmonconfig.xml" -Encoding UTF8
# Windows on ARM (e.g. a VM on an Apple Silicon Mac) needs the ARM64 build.
$sysmonExe = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'Sysmon64a.exe' } else { 'Sysmon64.exe' }
if (-not (Test-Path "$work\Sysmon\$sysmonExe")) {
    throw "Couldn't find $sysmonExe in the Sysmon download. Check $work\Sysmon for the right binary."
}
Write-Host "    Using $sysmonExe ($env:PROCESSOR_ARCHITECTURE)"
& "$work\Sysmon\$sysmonExe" -accepteula -i "$work\sysmonconfig.xml"

Write-Host '[2/4] Enabling PowerShell script block logging' -ForegroundColor Cyan
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -Type DWord

Write-Host '[3/4] Adding Defender exclusion for C:\AtomicRedTeam (lab VM only)' -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path 'C:\AtomicRedTeam' | Out-Null
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam'

Write-Host '[4/4] Installing Atomic Red Team' -ForegroundColor Cyan
# Atomic Red Team pulls a module from the PowerShell Gallery, which needs NuGet.
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

Write-Host "`nChecks:" -ForegroundColor Cyan
Get-Service -Name 'Sysmon*' | Format-Table Name, Status -AutoSize
$n = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "Sysmon events visible: $n (should be more than 0)"
Write-Host "Atomics folder present: $(Test-Path 'C:\AtomicRedTeam\atomics\T1105')"

Write-Host "`nSetup complete. Take a VM snapshot named 'tools-installed' now." -ForegroundColor Green
