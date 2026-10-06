"""
Regression tests for the detection rules.

Every rule must fire on its technique's attack fixture and stay silent on the
benign fixture. When you tune a rule, add the event that motivated the change
to tests/fixtures/ so the fix can't silently regress.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate import evaluate  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
REPORT = evaluate(ROOT / "rules", FIXTURES / "attack", FIXTURES / "benign")
RULES = REPORT["rules"]


@pytest.mark.parametrize("r", RULES, ids=[r["title"] for r in RULES])
def test_rule_has_attack_fixture(r):
    assert r["status"] != "untested", f"add tests/fixtures/attack/{r['techniques'][0]}.jsonl"


@pytest.mark.parametrize("r", RULES, ids=[r["title"] for r in RULES])
def test_rule_catches_every_attack_variant(r):
    assert r["true_positive_hits"] == r["attack_events"], (
        f"caught {r['true_positive_hits']}/{r['attack_events']} attack events")


@pytest.mark.parametrize("r", RULES, ids=[r["title"] for r in RULES])
def test_rule_is_quiet_on_benign(r):
    assert r["false_positive_hits"] == 0, f"false positives: {r['false_positive_samples']}"
