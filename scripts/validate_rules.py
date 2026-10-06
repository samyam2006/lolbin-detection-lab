#!/usr/bin/env python3
"""
Lint every rule in rules/ before it can be merged.

Checks: required fields, valid UUIDs, no duplicate IDs or titles, a valid level
and status, at least one MITRE ATT&CK technique tag, snake_case file names, and
that the detection logic actually parses.
"""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_lite import ATTACK_TAG, RuleError, SigmaRule  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["title", "id", "status", "description", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
FILENAME = re.compile(r"^[a-z0-9_]+\.yml$")


def check(path: Path, seen_ids: dict, seen_titles: dict) -> list[str]:
    errs: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"invalid YAML: {exc}"]
    if not isinstance(data, dict):
        return ["file is not a YAML mapping"]

    errs += [f"missing field '{f}'" for f in REQUIRED if f not in data]
    if not FILENAME.match(path.name):
        errs.append("file name must be lowercase snake_case ending in .yml")

    rid = str(data.get("id", ""))
    try:
        uuid.UUID(rid)
    except ValueError:
        errs.append(f"id '{rid}' is not a UUID")
    if rid in seen_ids:
        errs.append(f"duplicate id (also in {seen_ids[rid]})")
    seen_ids[rid] = path.name

    title = data.get("title", "")
    if title in seen_titles:
        errs.append(f"duplicate title (also in {seen_titles[title]})")
    seen_titles[title] = path.name

    if data.get("level") not in LEVELS:
        errs.append(f"level must be one of {sorted(LEVELS)}")
    if data.get("status") not in STATUSES:
        errs.append(f"status must be one of {sorted(STATUSES)}")
    if not any(ATTACK_TAG.match(t) for t in data.get("tags", []) or []):
        errs.append("needs at least one ATT&CK technique tag like attack.t1105")
    if not data.get("falsepositives"):
        errs.append("falsepositives should list at least one entry (or 'Unlikely')")

    if "detection" in data and "condition" in (data.get("detection") or {}):
        try:
            SigmaRule(path, data)
        except (RuleError, KeyError, TypeError) as exc:
            errs.append(f"detection does not parse: {exc}")
    elif "detection" in data:
        errs.append("detection has no condition")
    return errs


def main() -> int:
    paths = sorted((ROOT / "rules").rglob("*.y*ml"))
    if not paths:
        print("no rules found under rules/")
        return 1
    seen_ids: dict = {}
    seen_titles: dict = {}
    failed = 0
    for p in paths:
        errs = check(p, seen_ids, seen_titles)
        rel = p.relative_to(ROOT)
        if errs:
            failed += 1
            print(f"FAIL {rel}")
            for e in errs:
                print(f"     - {e}")
        else:
            print(f"ok   {rel}")
    print(f"\n{len(paths) - failed}/{len(paths)} rules passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
