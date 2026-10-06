<#
.SYNOPSIS
    Runs Atomic Red Team tests one technique at a time and saves a clean Sysmon
    log for each, ready for scripts/evaluate.py.

.DESCRIPTION
    RUN THIS ONLY INSIDE AN ISOLATED LAB VM THAT YOU CAN ROLL BACK.
    For each technique it:
      1. installs the test's prerequisites,
      2. clears the Sysmon log so the export contains only this test,
      3. runs the atomic test(s),
      4. exports the log to evtx\attack\<Technique>.evtx,
      5. runs the test's cleanup commands.

.EXAMPLE
    .\Run-Atomics.ps1
    .\Run-Atomics.ps1 -Techniques T1105 -TestNumbers 7
#>
#Requires -RunAsAdministrator
param(
    [string[]]$Techniques = @(
        'T1105', 'T1197', 'T1218.005', 'T1218.010',
        'T1218.011', 'T1059.001', 'T1053.005', 'T1047'
    ),
    # Optional: only run these test numbers (applies to every technique listed).
    [int[]]$TestNumbers,
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\evtx\attack'),
    [string]$AtomicModule = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1',
    [int]$SettleSeconds = 10
)

$ErrorActionPreference = 'Continue'
$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'

if (-not (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)) {
    throw 'Sysmon is not installed. Install it first (see README, Phase 2).'
}
Import-Module $AtomicModule -Force
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$runArgs = @{}
if ($TestNumbers) { $runArgs['TestNumbers'] = $TestNumbers }

foreach ($t in $Techniques) {
    Write-Host "`n=== $t ===" -ForegroundColor Cyan

    Write-Host '[1/5] Getting prerequisites'
    Invoke-AtomicTest $t @runArgs -GetPrereqs | Out-Null

    Write-Host '[2/5] Clearing Sysmon log'
    wevtutil cl $SysmonLog

    Write-Host '[3/5] Running test(s)'
    Invoke-AtomicTest $t @runArgs -TimeoutSeconds 120
    Start-Sleep -Seconds $SettleSeconds

    $file = Join-Path $OutDir "$t.evtx"
    Write-Host "[4/5] Exporting log to $file"
    wevtutil epl $SysmonLog $file /ow:true

    Write-Host '[5/5] Cleaning up'
    Invoke-AtomicTest $t @runArgs -Cleanup | Out-Null
}

Write-Host "`nDone. Copy the evtx\attack folder back to your repo and run:" -ForegroundColor Green
Write-Host '    python scripts/evaluate.py --markdown results.md --json results.json'
