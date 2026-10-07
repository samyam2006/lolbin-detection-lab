# Detection Results

_Generated 2026-10-07 by `scripts/evaluate.py`._

- **Detection rate:** 5/8 tested techniques
- **False positives:** 0 across 0 benign events
- **Attack events scanned:** 358

| Technique | Rule | Level | Result | Attack hits | Benign FPs |
|---|---|---|---|---|---|
| [T1047](https://attack.mitre.org/techniques/T1047/) | [WMIC Spawning a Process (Local or Remote)](rules/windows/process_creation/proc_creation_win_wmic_process_create.yml) | medium | ✅ detected | 1/13 | 0 |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [Scheduled Task Created With Suspicious Action](rules/windows/process_creation/proc_creation_win_schtasks_suspicious_create.yml) | medium | ✅ detected | 2/24 | 0 |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [PowerShell Launched With Encoded Command](rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml) | medium | ✅ detected | 1/43 | 0 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | [Certutil Used to Download a Remote File](rules/windows/process_creation/proc_creation_win_certutil_download.yml) | high | ❌ missed | 0/5 | 0 |
| [T1197](https://attack.mitre.org/techniques/T1197/) | [Bitsadmin Job Created for Download or Persistence](rules/windows/process_creation/proc_creation_win_bitsadmin_transfer.yml) | medium | ✅ detected | 4/75 | 0 |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | [Mshta Executing Inline Script or Remote HTA](rules/windows/process_creation/proc_creation_win_mshta_suspicious_exec.yml) | high | ❌ missed | 0/152 | 0 |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | [Regsvr32 Loading Scriptlet or Remote Content (Squiblydoo)](rules/windows/process_creation/proc_creation_win_regsvr32_squiblydoo.yml) | high | ✅ detected | 1/35 | 0 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | [Rundll32 Proxy Execution of Script or DLL From User-Writable Path](rules/windows/process_creation/proc_creation_win_rundll32_proxy_exec.yml) | medium | ❌ missed | 0/11 | 0 |
