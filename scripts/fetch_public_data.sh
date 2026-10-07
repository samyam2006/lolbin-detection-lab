#!/usr/bin/env bash
# Download public Sysmon datasets from Splunk's attack_data project
# (https://github.com/splunk/attack_data) for techniques where Microsoft
# Defender blocked the attack in my own lab, so the rule still gets tested
# against real attack telemetry.
#
# The files are large (up to ~35 MB each) and are not committed to git.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p evtx/public

BASE="https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques"
for t in T1105 T1218.005 T1218.010 T1218.011 T1047; do
  out="evtx/public/${t}_splunk-attack-data.log"
  echo "Downloading $t ..."
  curl -fsSL -o "$out" "$BASE/$t/atomic_red_team/windows-sysmon.log"
done

echo
echo "Done. Score the rules against the public data with:"
echo "  python scripts/evaluate.py --attack evtx/public --markdown results-public.md --json results-public.json"
