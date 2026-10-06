<#
.SYNOPSIS
    Records a window of NORMAL activity so you can measure false positives.

.DESCRIPTION
    Clears the Sysmon log, waits while you use the VM like a regular person
    (browse, install an app, run Windows Update, open Office, use PowerShell for
    ordinary admin tasks), then exports the log to evtx\benign\.

    Restore your clean snapshot before running this so no attack activity leaks in.

.EXAMPLE
    .\Capture-Baseline.ps1 -Label windows-update
#>
#Requires -RunAsAdministrator
param(
    [string]$Label = 'baseline',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\evtx\benign')
)

$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Make the log big enough to hold a long session (256 MB).
wevtutil sl $SysmonLog /ms:268435456
wevtutil cl $SysmonLog

$started = Get-Date
Write-Host 'Recording normal activity. Use the VM normally, then come back here.' -ForegroundColor Cyan
Write-Host 'Ideas: browse the web, install 7-Zip or VS Code, run Windows Update,'
Write-Host '       open Control Panel applets, create a normal scheduled task in Task Scheduler.'
Read-Host 'Press Enter when you are finished'

$minutes = [math]::Round(((Get-Date) - $started).TotalMinutes)
$file = Join-Path (Resolve-Path $OutDir) ("{0}-{1:yyyyMMdd-HHmm}.evtx" -f $Label, $started)
wevtutil epl $SysmonLog $file /ow:true
$count = (Get-WinEvent -Path $file -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "Saved $count events from $minutes minutes to $file" -ForegroundColor Green
