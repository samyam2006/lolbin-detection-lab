# LOLBin Detection Lab

![Detection CI](https://github.com/samyam2006/lolbin-detection-lab/actions/workflows/detections.yml/badge.svg)

I'm Samyam Shrestha, a senior at Towson University looking for full-time roles in cybersecurity and IT. I built this lab because I wanted to understand how attackers hide in normal Windows activity.

A lot of real intrusions don't use custom malware. Attackers use tools that already ship with Windows, like `certutil`, `mshta` and `rundll32`. They're signed by Microsoft and run on ordinary machines every day, so seeing one run tells you almost nothing. The real question is how to tell the malicious use apart from the normal use.

I'd used Splunk, PowerShell and Event Viewer before. Here I wanted to go further: run the attacks myself, read the raw [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) logs they leave behind, write my own [Sigma](https://sigmahq.io/) detection rules, and measure how each rule does against both attacks and normal activity.

## What I found

- **All 8 rules fired on real attack telemetry.** Five were confirmed in my own lab. The other three attacks were blocked by Microsoft Defender before they could run, so I validated those rules against public Sysmon datasets from Splunk's [attack_data](https://github.com/splunk/attack_data) project instead.
- **0 false positives** against a normal-use baseline that included legitimate uses of four of the same tools: `certutil -hashfile`, `bitsadmin /list`, `wmic os get caption` and `schtasks /query`.
- **Half my first-run "misses" weren't rule problems.** Defender blocked 7 attack commands outright, and my Sysmon config was silently dropping WMIC process creation. I fixed the logging gap and documented the prevention vs. detection difference instead of tuning rules to chase data that wasn't there.
- **Two real tuning fixes.** The mshta rule missed an `.hta` run from the Startup folder, and the scheduled-task rule missed a task whose action was plain `cmd.exe`. Both are fixed and covered by regression tests.
- **The renamed-binary hardening works on real data.** In the public mshta dataset, the attacker copied `mshta.exe` to `C:\Temp\notepad.exe`. My rule still caught it, because it checks the PE `OriginalFileName` and not just the file path.

The full troubleshooting story, including the wrong theories, is in [docs/build-log.md](docs/build-log.md).

## Results

| Technique | LOLBin | My lab (Atomic Red Team) | Public data (Splunk attack_data) | False positives |
|---|---|---|---|---|
| [T1047](https://attack.mitre.org/techniques/T1047/) WMI | wmic | ✅ detected (after fixing Sysmon logging) | ✅ detected | 0 |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task | schtasks | ✅ detected, 3/3 task creations after v2 tuning | – | 0 |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | powershell | ✅ detected | – | 0 |
| [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | certutil | 🛡️ blocked by Defender | ✅ detected | 0 |
| [T1197](https://attack.mitre.org/techniques/T1197/) BITS Jobs | bitsadmin | ✅ detected | – | 0 |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) Mshta | mshta | 🛡️ blocked by Defender | ✅ detected, 4 → 23 hits after v2 tuning | 0 |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) Regsvr32 | regsvr32 | ✅ local scriptlet detected (remote one blocked by Defender) | ✅ detected | 0 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) Rundll32 | rundll32 | 🛡️ blocked by Defender | ✅ detected | 0 |

"Blocked by Defender" means `Get-MpThreatDetection` showed Defender stopping the command at launch, so the LOLBin never ran and there was nothing for a detection rule to see. Raw output: [results.md](results.md) (my lab) and [results-public.md](results-public.md) (public data).

ATT&CK coverage map: load [`navigator/coverage_layer.json`](navigator/coverage_layer.json) into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## How it works

- **Rules:** one Sigma rule per technique in [`rules/`](rules/). Each matches on both the image path and `OriginalFileName`, so renaming the binary doesn't get around it.
- **Scoring:** [`scripts/evaluate.py`](scripts/evaluate.py) runs every rule against attack logs and normal-activity logs and reports what each rule caught and how many false alarms it raised.
- **No SIEM needed:** [`scripts/sigma_lite.py`](scripts/sigma_lite.py) is a small Sigma evaluator I wrote. It reads `.evtx` files directly, plus Splunk's one-event-per-line XML format.
- **Tested like code:** on every push, GitHub Actions lints the rules, runs regression tests built from real events in my lab, and checks that each rule still converts to Splunk SPL and Elastic queries.
- **Inspecting misses:** [`scripts/inspect_log.py`](scripts/inspect_log.py) prints the process events in a log so I can compare what actually ran with what a rule expects.

## The lab

- **Where:** a Windows Server 2022 VM in Azure (Azure for Students). My MacBook Air has 8 GB of RAM and not enough disk for a local VM, and I didn't want to run attack tools on a school-managed laptop.
- **Hardening:** RDP restricted to my IP only, a dedicated transfer folder instead of sharing my files with the VM, disk snapshots as restore points, and a budget alert in place of auto-shutdown, which my region didn't support.
- **Telemetry:** Sysmon with the [sysmon-modular](https://github.com/olafhartong/sysmon-modular) balanced profile, plus one extra include rule so WMIC process creation gets logged.
- **Attacks:** hand-picked [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests per technique, chosen to exercise each LOLBin without pulling in third-party offensive tools.

## Repository layout

```
rules/                  Sigma rules (one per technique)
scripts/
  sigma_lite.py         Sigma evaluator (.evtx, .jsonl, Splunk XML .log)
  evaluate.py           Scores all rules: detections + false positives
  inspect_log.py        Prints the process events in a log
  validate_rules.py     Lints rules (UUIDs, ATT&CK tags, syntax)
  build_navigator.py    Generates the ATT&CK Navigator coverage layer
  convert.sh            Converts rules to Splunk SPL and Elastic queries
  fetch_public_data.sh  Downloads the Splunk attack_data Sysmon logs
  lab/                  PowerShell scripts that run inside the lab VM
evtx/attack/            Sysmon logs from my attack runs
evtx/benign/            Sysmon logs of normal activity
tests/                  Unit tests + regression fixtures from real lab events
docs/build-log.md       Every problem I hit and how I solved it
```

## Reproduce it

Inside a **disposable** Windows VM (admin PowerShell):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\lab\Install-LabTools.ps1                    # Sysmon + Atomic Red Team
.\scripts\lab\Run-Atomics.ps1                         # attacks -> evtx\attack\
.\scripts\lab\Capture-Baseline.ps1 -Label normal-use  # normal activity -> evtx\benign\
```

Then, on your host:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/evaluate.py --markdown results.md --json results.json
bash scripts/fetch_public_data.sh
python scripts/evaluate.py --attack evtx/public --markdown results-public.md --json results-public.json
python scripts/build_navigator.py
```

> ⚠️ Atomic Red Team simulates real attacker behaviour. Only run it in a VM you can throw away, never on a personal or work machine.

## Limitations and next steps

- **Small baseline.** The balanced Sysmon profile only logs process starts it considers interesting, so my normal-use baseline had 15 process creations. A longer baseline with broader logging would give a stronger false-positive number.
- **Command-line detection is fragile.** These rules key on command lines. An attacker who obfuscates arguments, or reaches the same functionality through COM without starting a new process, needs other telemetry such as image loads (Sysmon Event ID 7) and network connections (Event ID 3).
- **Next:** systematically try to evade each rule (renamed binaries, alternate flags, unusual parent processes) in the lab, and add a rule for Defender's own detection events so prevented attacks still raise an alert.

## References

[MITRE ATT&CK](https://attack.mitre.org/) · [LOLBAS Project](https://lolbas-project.github.io/) · [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) · [SigmaHQ](https://github.com/SigmaHQ/sigma) · [sysmon-modular](https://github.com/olafhartong/sysmon-modular) · [Splunk attack_data](https://github.com/splunk/attack_data)

## License

MIT. See [LICENSE](LICENSE).
