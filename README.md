# LOLBin Detection Lab

![Detection CI](https://github.com/samyam2006/lolbin-detection-lab/actions/workflows/detections.yml/badge.svg)

I'm Samyam Shrestha, a senior at Towson University looking for full-time roles in cybersecurity and IT. I built this lab because I wanted to understand how attackers hide in normal Windows activity.

A lot of real intrusions don't use custom malware. Attackers use tools that already ship with Windows, like `certutil`, `mshta` and `rundll32`. These programs are signed by Microsoft and run on ordinary machines every day, so seeing one run tells you almost nothing. The question is how to tell the malicious use apart from the normal use.

I've worked with Splunk, PowerShell and Event Viewer before. For this project I wanted to go a step further: run the attacks myself in an isolated Windows VM, look at the raw [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) logs they leave behind, write my own [Sigma](https://sigmahq.io/) detection rules, and then measure how many attacks each rule catches and how often it fires on normal activity.

## Status

🚧 **In progress.** The detection rules, the scoring script and the automated tests are built. Next, I'm running eight attack techniques from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) in a Windows VM on my MacBook, recording a baseline of normal activity, and tuning the rules against both. I'll fill in the results and write up what I find for each technique as I go.

## How it works

Each rule targets one MITRE ATT&CK technique. `scripts/evaluate.py` runs every rule against the attack logs and the normal-activity logs, then reports which attacks it caught and how many false alarms it raised. `scripts/sigma_lite.py` is a small Sigma evaluator I use so I can test rules directly against `.evtx` files without a SIEM. On every push, GitHub Actions checks the rules for mistakes, runs the tests, and confirms each rule still converts to Splunk and Elastic queries.

## Results

Pending. I'll add these once I've run the lab.

| Technique | LOLBin | Rule | Detected | Benign FPs (before → after tuning) |
|---|---|---|---|---|
| [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | certutil | [rule](rules/windows/process_creation/proc_creation_win_certutil_download.yml) | ☐ | – |
| [T1197](https://attack.mitre.org/techniques/T1197/) BITS Jobs | bitsadmin | [rule](rules/windows/process_creation/proc_creation_win_bitsadmin_transfer.yml) | ☐ | – |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) Mshta | mshta | [rule](rules/windows/process_creation/proc_creation_win_mshta_suspicious_exec.yml) | ☐ | – |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) Regsvr32 | regsvr32 | [rule](rules/windows/process_creation/proc_creation_win_regsvr32_squiblydoo.yml) | ☐ | – |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) Rundll32 | rundll32 | [rule](rules/windows/process_creation/proc_creation_win_rundll32_proxy_exec.yml) | ☐ | – |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | powershell | [rule](rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml) | ☐ | – |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task | schtasks | [rule](rules/windows/process_creation/proc_creation_win_schtasks_suspicious_create.yml) | ☐ | – |
| [T1047](https://attack.mitre.org/techniques/T1047/) WMI | wmic | [rule](rules/windows/process_creation/proc_creation_win_wmic_process_create.yml) | ☐ | – |

ATT&CK coverage map: load [`navigator/coverage_layer.json`](navigator/coverage_layer.json) into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## Repository layout

```
rules/                  Sigma rules (one per technique)
scripts/
  sigma_lite.py         Sigma evaluator that reads .evtx and .jsonl
  evaluate.py           Scores all rules: detection rate + false positives
  validate_rules.py     Linter for rule quality (UUIDs, ATT&CK tags, syntax...)
  build_navigator.py    Generates the ATT&CK Navigator coverage layer
  convert.sh            Converts rules to Splunk SPL and Elastic queries
  lab/                  PowerShell scripts that run inside the lab VM
evtx/attack/            Sysmon logs from each attack simulation (T1105.evtx, ...)
evtx/benign/            Sysmon logs of normal activity, for false-positive testing
tests/                  Unit tests + regression fixtures for every rule
docs/techniques/        One write-up per technique: telemetry, logic, evasions
converted/              Generated SIEM queries
navigator/              ATT&CK Navigator layer
```

## Reproduce the lab

You need a computer with 16 GB of RAM (8 GB works, slowly), about 60 GB of free disk, and Python 3.10+.

> ⚠️ **Safety:** Atomic Red Team simulates real attacker behaviour. Run it **only inside a disposable VM** with snapshots. Never disable Defender or add exclusions on your everyday computer.

### Phase 1: Build the VM

1. Install a hypervisor. On a Windows or Intel host, use [VirtualBox](https://www.virtualbox.org/) or VMware Workstation Pro. On an Apple Silicon Mac (what I used), use VMware Fusion or UTM, both free for personal use.
2. Install Windows 11 and create a VM with 4 GB RAM, 2 CPUs and 60 GB disk. On Intel/AMD, use the free **Windows 11 Enterprise evaluation**. On Apple Silicon, use **Windows 11 ARM64**. The setup script picks the ARM64 build of Sysmon automatically.
3. Set its network to **NAT**. Install the guest additions so you can share a folder with your host.
4. Take a snapshot called `clean`.

### Phase 2: Install the tooling (inside the VM)

Copy `scripts/lab/` into the VM, open PowerShell **as Administrator**, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-LabTools.ps1
```

This installs Sysmon with [sysmon-modular](https://github.com/olafhartong/sysmon-modular), turns on PowerShell script-block logging, and installs Atomic Red Team. Confirm Sysmon works by opening Event Viewer → *Applications and Services Logs → Microsoft → Windows → Sysmon → Operational* and looking for Event ID 1. Then take a snapshot called `tools-installed`.

### Phase 3: Capture attack telemetry

```powershell
.\Run-Atomics.ps1
```

For each technique this clears the Sysmon log, runs the atomic tests, exports `evtx\attack\<Technique>.evtx`, and cleans up. Some atomics need internet access or fail on a given Windows build, which is expected. Note which ones ran in your technique write-ups.

### Phase 4: Capture a benign baseline

Revert to the `tools-installed` snapshot so no attack artifacts remain, then:

```powershell
.\Capture-Baseline.ps1 -Label normal-use
```

Use the VM like a normal person for 30–60 minutes: browse, install a couple of apps, run Windows Update, open Control Panel, create an ordinary scheduled task. More variety means a more honest false-positive number.

### Phase 5: Evaluate and tune (on your host)

Copy the `.evtx` files into this repo's `evtx/` folders, then:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python scripts/evaluate.py --markdown results.md --json results.json
python scripts/build_navigator.py
```

For any rule that **missed**, open its `.evtx` in Event Viewer, find the Event ID 1 record, and compare the real command line against the rule. For any **false positive**, the report prints the offending command lines. Tighten the rule or add a `filter_` selection, then re-run. Record the before and after counts in the technique write-up. Every time you fix something, copy the event into `tests/fixtures/` so CI guards against regressions.

### Phase 6: Try to evade your own rules

For each technique, attempt at least one bypass and document it in `docs/techniques/`:

- Copy the binary and rename it (`copy C:\Windows\System32\certutil.exe C:\Users\Public\cu.exe`)
- Change argument prefixes or casing (`/urlcache` vs `-URLCACHE`)
- Use an abbreviated flag (`-ec` instead of `-EncodedCommand`)
- Launch it from an unusual parent process

If a bypass works, fix the rule, add the event to the fixtures, and note it in the write-up.

### Phase 7: Convert to SIEM queries

```bash
bash scripts/convert.sh
```

This writes `converted/splunk.spl` and `converted/elastic.lucene`.

## Running the checks locally

```bash
python scripts/validate_rules.py    # lint rules
pytest -q                           # unit + regression tests
python scripts/evaluate.py --strict --attack tests/fixtures/attack --benign tests/fixtures/benign
```

## Limitations

- Command-line detection only sees what Sysmon Event ID 1 records. Process injection, or LOLBins invoked through COM without a new process, need other telemetry such as image loads or network connections.
- The benign baseline comes from a single lab VM. Real enterprise environments have far more legitimate LOLBin use, so expect to tune further in production.
- `sigma_lite.py` implements the subset of Sigma these rules use, not the full specification.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular)

## License

MIT. See [LICENSE](LICENSE).
