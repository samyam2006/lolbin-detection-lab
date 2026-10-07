<#
.SYNOPSIS
    Runs hand-picked Atomic Red Team tests one technique at a time and saves a
    clean Sysmon log for each, ready for scripts/evaluate.py.

.DESCRIPTION
    RUN THIS ONLY INSIDE AN ISOLATED LAB VM THAT YOU CAN ROLL BACK.

    Most techniques have dozens of atomic tests, and many are irrelevant or wait
    for input (scp/sftp password prompts, GUI apps). So this script only runs the
    test numbers listed in $Plan. Find test numbers with:
        Invoke-AtomicTest T1105 -ShowDetailsBrief

    For each technique it:
      1. installs the chosen tests' prerequisites,
      2. clears the Sysmon log so the export contains only this technique,
      3. runs the chosen tests,
      4. exports the log to evtx\attack\<Technique>.evtx,
      5. runs the tests' cleanup commands.

.EXAMPLE
    .\Run-Atomics.ps1                     # run the whole plan
    .\Run-Atomics.ps1 -Only T1105         # run just one technique from the plan
#>
#Requires -RunAsAdministrator
param(
    # Technique -> atomic test numbers to run. Edit after checking -ShowDetailsBrief.
    [System.Collections.IDictionary]$Plan = [ordered]@{
        'T1105'     = @(7, 8)      # certutil urlcache, certutil verifyctl
        'T1197'     = @(1, 3)      # bitsadmin download, bitsadmin persist/download/execute
        'T1218.005' = @(1, 2, 3)   # mshta javascript:, mshta vbscript:, mshta remote HTA
        'T1218.010' = @(1, 2)      # regsvr32 local scriptlet, regsvr32 remote scriptlet
        'T1218.011' = @(1, 2)      # rundll32 javascript:, rundll32 vbscript (RunHTMLApplication)
        'T1059.001' = @(15, 17)    # -EncodedCommand variations, encoded command execution
        'T1053.005' = @(1, 2)      # schtasks onlogon task, schtasks local task
        'T1047'     = @(5)         # wmic process call create
    },
    [string[]]$Only,
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\evtx\attack'),
    [string]$AtomicModule = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1',
    [int]$SettleSeconds = 10
)

$ErrorActionPreference = 'Continue'
$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'

if (-not (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)) {
    throw 'Sysmon is not installed. Run Install-LabTools.ps1 first.'
}
Import-Module $AtomicModule -Force
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$summary = @()
foreach ($t in $Plan.Keys) {
    if ($Only -and $t -notin $Only) { continue }
    $tests = @($Plan[$t])
    if ($tests.Count -eq 0) {
        Write-Host "`n=== ${t}: no test numbers in the plan, skipping ===" -ForegroundColor DarkYellow
        continue
    }
    Write-Host "`n=== $t (tests $($tests -join ', ')) ===" -ForegroundColor Cyan

    Write-Host '[1/5] Getting prerequisites'
    Invoke-AtomicTest $t -TestNumbers $tests -GetPrereqs

    Write-Host '[2/5] Clearing Sysmon log'
    # Let Sysmon flush events from the previous technique's cleanup first;
    # otherwise they land in this technique's export after the clear.
    Start-Sleep -Seconds 5
    wevtutil cl $SysmonLog
    Start-Sleep -Seconds 2

    Write-Host '[3/5] Running test(s)'
    Invoke-AtomicTest $t -TestNumbers $tests -TimeoutSeconds 120
    Start-Sleep -Seconds $SettleSeconds

    $file = Join-Path $OutDir "$t.evtx"
    Write-Host "[4/5] Exporting log to $file"
    wevtutil epl $SysmonLog $file /ow:true
    $count = (Get-WinEvent -Path $file -ErrorAction SilentlyContinue |
              Where-Object Id -eq 1 | Measure-Object).Count

    Write-Host '[5/5] Cleaning up'
    Invoke-AtomicTest $t -TestNumbers $tests -Cleanup | Out-Null

    $summary += [pscustomobject]@{ Technique = $t; Tests = ($tests -join ','); ProcessEvents = $count }
}

Write-Host "`nSummary (Sysmon Event ID 1 = process creations captured):" -ForegroundColor Green
$summary | Format-Table -AutoSize
Write-Host "Logs are in $OutDir"
Write-Host 'Copy them to \\tsclient\lab-transfer, then into evtx\attack in the repo on your Mac.'
