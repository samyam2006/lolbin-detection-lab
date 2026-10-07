# Detection Results

_Generated 2026-10-07 by `scripts/evaluate.py`._

- **Detection rate:** 5/5 tested techniques
- **False positives:** 0 across 0 benign events
- **Attack events scanned:** 43,482

| Technique | Rule | Level | Result | Attack hits | Benign FPs |
|---|---|---|---|---|---|
| [T1047](https://attack.mitre.org/techniques/T1047/) | [WMIC Spawning a Process (Local or Remote)](rules/windows/process_creation/proc_creation_win_wmic_process_create.yml) | medium | ✅ detected | 2/6571 | 0 |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [Scheduled Task Created With Suspicious Action](rules/windows/process_creation/proc_creation_win_schtasks_suspicious_create.yml) | medium | ⚪ no data | 0/0 | 0 |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [PowerShell Launched With Encoded Command](rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml) | medium | ⚪ no data | 0/0 | 0 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | [Certutil Used to Download a Remote File](rules/windows/process_creation/proc_creation_win_certutil_download.yml) | high | ✅ detected | 10/2288 | 0 |
| [T1197](https://attack.mitre.org/techniques/T1197/) | [Bitsadmin Job Created for Download or Persistence](rules/windows/process_creation/proc_creation_win_bitsadmin_transfer.yml) | medium | ⚪ no data | 0/0 | 0 |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | [Mshta Executing Inline Script or Remote HTA](rules/windows/process_creation/proc_creation_win_mshta_suspicious_exec.yml) | high | ✅ detected | 4/17946 | 0 |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | [Regsvr32 Loading Scriptlet or Remote Content (Squiblydoo)](rules/windows/process_creation/proc_creation_win_regsvr32_squiblydoo.yml) | high | ✅ detected | 7/3314 | 0 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | [Rundll32 Proxy Execution of Script or DLL From User-Writable Path](rules/windows/process_creation/proc_creation_win_rundll32_proxy_exec.yml) | medium | ✅ detected | 2/13363 | 0 |

## Cross-technique hits

Rules that also fired on another technique's test run. Often expected (an atomic for one technique may call another LOLBin), but worth a look.

- **Bitsadmin Job Created for Download or Persistence**: T1105 (1)
- **PowerShell Launched With Encoded Command**: T1047 (37), T1218.011 (37)
- **Rundll32 Proxy Execution of Script or DLL From User-Writable Path**: T1218.005 (5)
