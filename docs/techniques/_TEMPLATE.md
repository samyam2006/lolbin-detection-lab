# TXXXX – Technique Name

**LOLBin:** `binary.exe`  **Rule:** [`rule_file.yml`](../../rules/windows/process_creation/rule_file.yml)

## How attackers use it
Two or three sentences in your own words. Link a real-world report (DFIR Report, Red Canary, vendor blog) that shows this used in an intrusion.

## Simulation
- Atomic test(s) run: `Invoke-AtomicTest TXXXX -TestNumbers N`
- Tests that failed or were skipped, and why:

## Telemetry observed
| Sysmon Event ID | What it showed |
|---|---|
| 1 (process creation) | `paste the command line here` |
| 3 (network) | |
| 11 (file create) | |

Parent process:  
Notable fields (OriginalFileName, User, IntegrityLevel):

## Detection logic
Explain *why* the rule keys on what it does, and what you deliberately left out.

## Tuning
| Version | Change | Attack hits | Benign FPs |
|---|---|---|---|
| v1 | initial | | |
| v2 | | | |

## Evasion attempts
| Attempt | Bypassed v1? | Fix |
|---|---|---|
| Renamed binary | | |
| Alternate flag / casing | | |

## Blind spots
What this rule still won't catch, and which other telemetry would.
