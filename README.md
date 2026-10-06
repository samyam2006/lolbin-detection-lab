# LOLBin Detection Lab

![Detection CI](https://github.com/samyam2006/lolbin-detection-lab/actions/workflows/detections.yml/badge.svg)

Detection engineering for **living-off-the-land binary (LOLBin) abuse** on Windows. Attackers increasingly avoid custom malware and instead misuse signed tools that ship with Windows, such as `certutil`, `mshta`, `rundll32` and `regsvr32`. This repo emulates eight of those techniques with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), captures the resulting [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) telemetry, and ships tested [Sigma](https://sigmahq.io/) rules that detect them.

What makes this more than a rule dump:

- **Every rule is measured.** `scripts/evaluate.py` replays real attack logs and a benign baseline through each rule and reports the detection rate and false-positive count.
- **Rules are tested like code.** GitHub Actions lints every rule, runs regression tests, and confirms each one still converts to Splunk SPL and Elastic queries on every push.
- **Rules are hardened against evasion.** Each rule keys on `OriginalFileName` as well as the image path, so renaming the binary doesn't bypass it. Evasion attempts are documented per technique in [`docs/techniques/`](docs/techniques/).
- **No SIEM required.** A small Sigma evaluator in [`scripts/sigma_lite.py`](scripts/sigma_lite.py) runs rules straight against `.evtx` files.

## Results

> Replace this section with your numbers after running the lab (see [results.md](results.md)).

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

ATT&CK coverage map: load [`navigator/coverage_layer.json`](navigator/coverage_layer.json) into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Add a screenshot here once your results are in.

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

1. Install [VirtualBox](https://www.virtualbox.org/) or VMware Workstation Pro (free for personal use).
2. Download the free **Windows 11 Enterprise evaluation** image from Microsoft and create a VM with 4 GB RAM, 2 CPUs and 60 GB disk.
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
