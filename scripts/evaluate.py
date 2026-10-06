#!/usr/bin/env python3
"""
Score every Sigma rule against attack and benign logs.

Attack logs are matched to techniques by file name: a file called
T1218.011.evtx (or T1218_011-run2.jsonl) holds telemetry for T1218.011.
Everything in the benign folder is treated as normal activity, so any rule hit
there counts as a false positive.

Usage:
    python scripts/evaluate.py                              # your real lab data
    python scripts/evaluate.py --attack tests/fixtures/attack --benign tests/fixtures/benign
    python scripts/evaluate.py --strict                     # exit 1 on misses or FPs (for CI)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_lite import iter_events, load_rules, log_files  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FILE_TECHNIQUE = re.compile(r"^(T\d{4})(?:[._](\d{3}))?", re.IGNORECASE)


def technique_from_filename(path: Path) -> str | None:
    m = FILE_TECHNIQUE.match(path.name)
    if not m:
        return None
    base = m.group(1).upper()
    return f"{base}.{m.group(2)}" if m.group(2) else base


def evaluate(rules_dir: Path, attack_dir: Path, benign_dir: Path) -> dict:
    rules = load_rules(rules_dir)

    attack_events: dict[str, list] = defaultdict(list)
    for f in log_files(attack_dir):
        tech = technique_from_filename(f)
        if tech is None:
            print(f"warning: skipping {f.name}; name it after a technique, e.g. T1105.evtx",
                  file=sys.stderr)
            continue
        attack_events[tech].extend(iter_events(f))

    benign_events = [ev for f in log_files(benign_dir) for ev in iter_events(f)]
    benign_samples: dict[str, list[str]] = defaultdict(list)

    results = []
    for rule in rules:
        own = [ev for t in rule.techniques for ev in attack_events.get(t, [])]
        has_data = any(t in attack_events for t in rule.techniques)
        true_hits = sum(rule.matches(ev) for ev in own)

        fp_hits = 0
        for ev in benign_events:
            if rule.matches(ev):
                fp_hits += 1
                if len(benign_samples[rule.id]) < 5:
                    benign_samples[rule.id].append(ev.get("CommandLine") or str(ev))

        cross = {
            t: n for t, evs in attack_events.items()
            if t not in rule.techniques and (n := sum(rule.matches(ev) for ev in evs))
        }

        if not has_data:
            status = "untested"
        elif true_hits == 0:
            status = "missed"
        else:
            status = "detected"

        results.append({
            "id": rule.id,
            "title": rule.title,
            "file": str(rule.path.relative_to(ROOT)) if rule.path.is_relative_to(ROOT) else str(rule.path),
            "level": rule.level,
            "techniques": rule.techniques,
            "status": status,
            "attack_events": len(own),
            "true_positive_hits": true_hits,
            "false_positive_hits": fp_hits,
            "false_positive_samples": benign_samples[rule.id],
            "cross_technique_hits": cross,
        })

    tested = [r for r in results if r["status"] != "untested"]
    return {
        "generated": date.today().isoformat(),
        "benign_events_scanned": len(benign_events),
        "attack_events_scanned": sum(len(v) for v in attack_events.values()),
        "techniques_with_data": sorted(attack_events),
        "summary": {
            "rules": len(results),
            "tested": len(tested),
            "detected": sum(r["status"] == "detected" for r in tested),
            "missed": sum(r["status"] == "missed" for r in tested),
            "untested": len(results) - len(tested),
            "total_false_positives": sum(r["false_positive_hits"] for r in results),
        },
        "rules": results,
    }


def to_markdown(report: dict) -> str:
    s = report["summary"]
    rate = f"{s['detected']}/{s['tested']}" if s["tested"] else "n/a"
    icon = {"detected": "✅ detected", "missed": "❌ missed", "untested": "⚪ no data"}
    lines = [
        "# Detection Results",
        "",
        f"_Generated {report['generated']} by `scripts/evaluate.py`._",
        "",
        f"- **Detection rate:** {rate} tested techniques",
        f"- **False positives:** {s['total_false_positives']} across "
        f"{report['benign_events_scanned']:,} benign events",
        f"- **Attack events scanned:** {report['attack_events_scanned']:,}",
        "",
        "| Technique | Rule | Level | Result | Attack hits | Benign FPs |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(report["rules"], key=lambda r: r["techniques"]):
        techs = ", ".join(
            f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in r["techniques"]
        )
        lines.append(
            f"| {techs} | [{r['title']}]({r['file']}) | {r['level']} | {icon[r['status']]} "
            f"| {r['true_positive_hits']}/{r['attack_events']} | {r['false_positive_hits']} |"
        )

    noisy = [r for r in report["rules"] if r["false_positive_samples"]]
    if noisy:
        lines += ["", "## False-positive samples", ""]
        for r in noisy:
            lines.append(f"**{r['title']}**")
            lines += [f"- `{c}`" for c in r["false_positive_samples"]]
            lines.append("")

    cross = [r for r in report["rules"] if r["cross_technique_hits"]]
    if cross:
        lines += ["", "## Cross-technique hits", "",
                  "Rules that also fired on another technique's test run. Often expected "
                  "(an atomic for one technique may call another LOLBin), but worth a look.", ""]
        for r in cross:
            hits = ", ".join(f"{t} ({n})" for t, n in r["cross_technique_hits"].items())
            lines.append(f"- **{r['title']}**: {hits}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=ROOT / "rules")
    ap.add_argument("--attack", type=Path, default=ROOT / "evtx" / "attack")
    ap.add_argument("--benign", type=Path, default=ROOT / "evtx" / "benign")
    ap.add_argument("--markdown", type=Path, default=None, help="write a Markdown report here")
    ap.add_argument("--json", type=Path, default=None, help="write a JSON report here")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any tested rule misses or any rule has a false positive")
    args = ap.parse_args()

    report = evaluate(args.rules, args.attack, args.benign)
    md = to_markdown(report)
    print(md)
    if args.markdown:
        args.markdown.write_text(md, encoding="utf-8")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    s = report["summary"]
    if args.strict and (s["missed"] or s["total_false_positives"]):
        print("STRICT: failing because of missed detections or false positives", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
