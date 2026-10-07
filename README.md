# LOLBin Detection Lab

![Detection CI](https://github.com/samyam2006/lolbin-detection-lab/actions/workflows/detections.yml/badge.svg)

I'm Samyam, a senior at Towson. I built this because I wanted to understand how attackers hide in normal Windows activity.

A lot of real intrusions don't bring custom malware at all. They use tools that already ship with Windows, like certutil, mshta and rundll32, which are signed by Microsoft and run on normal machines all the time. Seeing one of them run doesn't tell you much. What I wanted to figure out was how to tell when one is being abused.

So I set up a Windows Server VM in Azure, installed Sysmon, ran attack simulations from Atomic Red Team, and wrote Sigma rules for eight techniques. Then I checked each rule two ways: does it catch the attack, and does it stay quiet when someone is just using the computer normally?

## How it went

Not the way I expected. On the first run only 4 of the 8 rules fired, and I assumed my rules were broken. They mostly weren't. When I actually looked at the logs, the certutil, mshta and rundll32 attacks never showed up, because Microsoft Defender had blocked them before they could run (7 commands in total, confirmed with `Get-MpThreatDetection`). There was nothing there for a detection rule to see.

WMIC was a different problem. The attack clearly ran, since Notepad launched through WMI, but Sysmon never logged WMIC itself. My first guess about why was wrong. After digging through the Sysmon config XML, it turned out the profile I was using only logs WMIC alongside a few specific commands like shadow copy deletion, and `process call create` wasn't one of them. One extra include rule fixed it, and the WMIC rule detected the attack on the rerun.

For the three techniques Defender blocked, I didn't want to turn protection off, so I tested those rules against public Sysmon logs from Splunk's [attack_data](https://github.com/splunk/attack_data) project instead, which were recorded from the same Atomic Red Team tests. All of them fired.

Going through every event also turned up two real misses that the totals were hiding. The mshta rule wouldn't have caught an .hta file run from the Startup folder, and the scheduled task rule missed a task that just runs `cmd.exe` with no arguments. I fixed both and added those events as test cases.

My favorite find was in the public mshta data. Whoever recorded it had copied mshta.exe to `C:\Temp\notepad.exe`, and my rule still caught it, because it checks the binary's OriginalFileName and not just its path.

For false positives, I recorded a session of normal use: browsing, installing 7-Zip, Control Panel, some admin commands, plus harmless uses of the same tools (`certutil -hashfile`, `bitsadmin /list`, `wmic os get caption`, `schtasks /query`). None of the rules fired. That baseline is small, though, only 15 process starts, because the Sysmon profile skips a lot of routine activity. A bigger baseline is the obvious next step.

The whole messy version, wrong theories included, is in [docs/build-log.md](docs/build-log.md).

## Results

| Technique | Tool | My lab | Public data | False positives |
|---|---|---|---|---|
| [T1047](https://attack.mitre.org/techniques/T1047/) WMI | wmic | detected, after fixing Sysmon logging | detected | 0 |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task | schtasks | detected (3/3 after tuning) | – | 0 |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | powershell | detected | – | 0 |
| [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | certutil | blocked by Defender | detected | 0 |
| [T1197](https://attack.mitre.org/techniques/T1197/) BITS Jobs | bitsadmin | detected | – | 0 |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) Mshta | mshta | blocked by Defender | detected | 0 |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) Regsvr32 | regsvr32 | local test detected, remote one blocked | detected | 0 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) Rundll32 | rundll32 | blocked by Defender | detected | 0 |

Raw numbers are in [results.md](results.md) and [results-public.md](results-public.md).

## What's in here

The rules are in `rules/`. `scripts/evaluate.py` scores them against attack and normal-activity logs, and `scripts/sigma_lite.py` is a small Sigma evaluator I use so I can test against .evtx files without setting up a SIEM. `scripts/inspect_log.py` dumps the process events from a log, which is how I figured out most of the misses. The PowerShell scripts I ran inside the VM are in `scripts/lab/`. GitHub Actions lints the rules, runs the tests, and checks that every rule still converts to Splunk and Elastic queries on each push.

If you want to run it yourself, use a VM you can throw away. Atomic Red Team does real attacker things.

```powershell
# inside the VM, as admin
.\scripts\lab\Install-LabTools.ps1
.\scripts\lab\Run-Atomics.ps1
.\scripts\lab\Capture-Baseline.ps1 -Label normal-use
```

```bash
# on your own machine
pip install -r requirements.txt
python scripts/evaluate.py
bash scripts/fetch_public_data.sh
python scripts/evaluate.py --attack evtx/public
```

## Things I'd still like to do

Run a much longer normal-activity baseline, actually try to sneak past my own rules in the lab, and write a rule for Defender's own detection events, so a blocked attack still shows up as an alert. These rules also only look at command lines, so someone who obfuscates the arguments or skips the LOLBin entirely would get past them.

Thanks to [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [sysmon-modular](https://github.com/olafhartong/sysmon-modular), [SigmaHQ](https://github.com/SigmaHQ/sigma), [LOLBAS](https://lolbas-project.github.io/) and Splunk's [attack_data](https://github.com/splunk/attack_data), which this all leans on.

MIT licensed.
