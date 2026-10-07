#!/usr/bin/env python3
"""
Show the process-creation events (Sysmon Event ID 1) in a log file, so you can
see exactly what an attack did and compare it with your rule.

Usage:
    python scripts/inspect_log.py evtx/attack/T1105.evtx
    python scripts/inspect_log.py evtx/attack/T1105.evtx --grep certutil
    python scripts/inspect_log.py evtx/attack/T1105.evtx --ids        # count every Event ID
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_lite import iter_events  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", type=Path)
    ap.add_argument("--grep", help="only show events whose image or command line contains this text")
    ap.add_argument("--ids", action="store_true", help="just count events by Event ID")
    args = ap.parse_args()

    events = list(iter_events(args.log))
    if args.ids:
        for eid, n in sorted(Counter(e.get("EventID") for e in events).items()):
            print(f"Event ID {eid}: {n}")
        return 0

    shown = 0
    for e in events:
        if e.get("EventID") != 1:
            continue
        img = e.get("Image") or ""
        cmd = e.get("CommandLine") or ""
        if args.grep and args.grep.lower() not in (img + cmd).lower():
            continue
        shown += 1
        print(f"--- #{shown}")
        print(f"Image:            {img}")
        print(f"OriginalFileName: {e.get('OriginalFileName')}")
        print(f"CommandLine:      {cmd}")
        print(f"ParentImage:      {e.get('ParentImage')}")
    total = sum(1 for e in events if e.get("EventID") == 1)
    print(f"\n{shown} shown of {total} process-creation events ({len(events)} events total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
