"""
sigma_lite: a small, dependency-light Sigma rule evaluator.

It supports the subset of the Sigma spec this repo uses, so rules can be tested
against real Sysmon logs (.evtx) or hand-written fixtures (.jsonl) without
standing up a SIEM:

  * selections as maps (AND across fields) or lists of maps (OR)
  * value lists (OR, or AND with the |all modifier)
  * modifiers: contains, startswith, endswith, re, all
  * * and ? wildcards in plain values
  * null values (field must be absent or empty)
  * conditions with and / or / not, parentheses, "1 of x*", "all of x*", "them"

Matching is case-insensitive, as the Sigma spec requires, except for |re.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Callable, Iterable, Iterator

import yaml

Event = dict
Matcher = Callable[[Event], bool]

# Sysmon Event IDs for the Sigma logsource categories we care about.
CATEGORY_EVENT_IDS = {
    "process_creation": {1},
    "network_connection": {3},
    "image_load": {7},
    "create_remote_thread": {8},
    "process_access": {10},
    "file_event": {11},
    "registry_event": {12, 13, 14},
    "registry_set": {13},
    "dns_query": {22},
}

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
ATTACK_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)


class RuleError(ValueError):
    """Raised when a rule uses syntax this evaluator can't handle."""


# --------------------------------------------------------------------------- #
# Field matching
# --------------------------------------------------------------------------- #

def _wildcard_to_regex(value: str) -> re.Pattern:
    return re.compile(fnmatch.translate(value), re.IGNORECASE | re.DOTALL)


def _compile_field(key: str, value) -> Matcher:
    field, *mods = key.split("|")
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise RuleError(f"unsupported modifier(s) {sorted(unknown)} on field '{field}'")

    ops = [m for m in mods if m != "all"]
    if len(ops) > 1:
        raise RuleError(f"conflicting modifiers {ops} on field '{field}'")
    op = ops[0] if ops else "eq"
    require_all = "all" in mods
    values = value if isinstance(value, list) else [value]

    tests: list[Callable[[object], bool]] = []
    for v in values:
        if v is None:
            tests.append(lambda x: x is None or x == "")
            continue
        if op == "re":
            pattern = re.compile(str(v))
            tests.append(lambda x, p=pattern: x is not None and p.search(str(x)) is not None)
            continue
        needle = str(v).lower()
        if op == "eq" and ("*" in needle or "?" in needle):
            pattern = _wildcard_to_regex(needle)
            tests.append(lambda x, p=pattern: x is not None and p.fullmatch(str(x)) is not None)
        elif op == "eq":
            tests.append(lambda x, n=needle: x is not None and str(x).lower() == n)
        elif op == "contains":
            tests.append(lambda x, n=needle: x is not None and n in str(x).lower())
        elif op == "startswith":
            tests.append(lambda x, n=needle: x is not None and str(x).lower().startswith(n))
        elif op == "endswith":
            tests.append(lambda x, n=needle: x is not None and str(x).lower().endswith(n))

    combine = all if require_all else any
    return lambda ev: combine(t(ev.get(field)) for t in tests)


def _compile_map(selection: dict) -> Matcher:
    matchers = [_compile_field(k, v) for k, v in selection.items()]
    return lambda ev: all(m(ev) for m in matchers)


def _compile_keywords(words: list) -> Matcher:
    needles = [str(w).lower() for w in words]
    return lambda ev: any(n in str(v).lower() for v in ev.values() for n in needles)


def compile_selection(selection) -> Matcher:
    if isinstance(selection, dict):
        return _compile_map(selection)
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):
            parts = [_compile_map(s) for s in selection]
            return lambda ev: any(p(ev) for p in parts)
        if all(not isinstance(s, (dict, list)) for s in selection):
            return _compile_keywords(selection)
    raise RuleError(f"unsupported selection shape: {type(selection).__name__}")


# --------------------------------------------------------------------------- #
# Condition parsing (recursive descent)
# --------------------------------------------------------------------------- #

_TOKEN = re.compile(r"\s*(\(|\)|(?:1|all)\s+of\s+[\w*]+|[\w*]+)", re.IGNORECASE)

Cond = Callable[[Callable[[str], bool]], bool]


def _tokenize(condition: str) -> list[str]:
    tokens, pos = [], 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise RuleError(f"can't parse condition near: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def parse_condition(condition: str, names: list[str]) -> Cond:
    tokens = _tokenize(condition)
    pos = 0

    def peek():
        return tokens[pos].lower() if pos < len(tokens) else None

    def take():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def resolve(pattern: str) -> list[str]:
        if pattern.lower() == "them":
            return list(names)
        hits = [n for n in names if fnmatch.fnmatchcase(n, pattern)]
        if not hits:
            raise RuleError(f"'{pattern}' in condition matches no selection")
        return hits

    def or_expr() -> Cond:
        left = and_expr()
        while peek() == "or":
            take()
            right = and_expr()
            left = (lambda l, r: lambda s: l(s) or r(s))(left, right)
        return left

    def and_expr() -> Cond:
        left = not_expr()
        while peek() == "and":
            take()
            right = not_expr()
            left = (lambda l, r: lambda s: l(s) and r(s))(left, right)
        return left

    def not_expr() -> Cond:
        if peek() == "not":
            take()
            inner = not_expr()
            return lambda s: not inner(s)
        return atom()

    def atom() -> Cond:
        tok = peek()
        if tok is None:
            raise RuleError("condition ended unexpectedly")
        if tok == "(":
            take()
            inner = or_expr()
            if peek() != ")":
                raise RuleError("missing ')' in condition")
            take()
            return inner
        raw = take()
        quant = re.fullmatch(r"(1|all)\s+of\s+([\w*]+)", raw, re.IGNORECASE)
        if quant:
            group = resolve(quant.group(2))
            agg = all if quant.group(1).lower() == "all" else any
            return lambda s: agg(s(n) for n in group)
        if raw.lower() in ("and", "or", ")"):
            raise RuleError(f"unexpected '{raw}' in condition")
        if raw not in names:
            raise RuleError(f"condition references unknown selection '{raw}'")
        return lambda s: s(raw)

    expr = or_expr()
    if pos != len(tokens):
        raise RuleError(f"unexpected trailing tokens in condition: {tokens[pos:]}")
    return expr


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

class SigmaRule:
    def __init__(self, path: Path, data: dict):
        self.path = Path(path)
        self.data = data
        self.title: str = data["title"]
        self.id: str = str(data["id"])
        self.level: str = data.get("level", "")
        self.tags: list[str] = list(data.get("tags", []))
        self.logsource: dict = data.get("logsource", {})
        self.techniques: list[str] = sorted(
            {t.split(".", 1)[1].upper() for t in self.tags if ATTACK_TAG.match(t)}
        )

        detection = dict(data["detection"])
        condition = detection.pop("condition")
        if isinstance(condition, list):
            if len(condition) != 1:
                raise RuleError("multiple conditions are not supported")
            condition = condition[0]
        self.condition: str = condition
        self.selections = {name: compile_selection(sel) for name, sel in detection.items()}
        self._cond = parse_condition(condition, list(self.selections))

        category = self.logsource.get("category")
        self.event_ids = CATEGORY_EVENT_IDS.get(category) if category else None

    def applies_to(self, event: Event) -> bool:
        if self.event_ids is None:
            return True
        try:
            return int(event.get("EventID", -1)) in self.event_ids
        except (TypeError, ValueError):
            return False

    def matches(self, event: Event) -> bool:
        if not self.applies_to(event):
            return False
        cache: dict[str, bool] = {}

        def sel(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name](event)
            return cache[name]

        return self._cond(sel)


def load_rule(path: Path) -> SigmaRule:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return SigmaRule(path, data)


def load_rules(root: Path) -> list[SigmaRule]:
    root = Path(root)
    paths = sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml")))
    return [load_rule(p) for p in paths]


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #

_EVT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _iter_evtx(path: Path) -> Iterator[Event]:
    try:
        import Evtx.Evtx as evtx  # python-evtx
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Reading .evtx needs python-evtx: pip install python-evtx") from exc
    from xml.etree import ElementTree as ET

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            eid = root.find("e:System/e:EventID", _EVT_NS)
            event: Event = {"EventID": int(eid.text) if eid is not None and eid.text else -1}
            for data in root.findall("e:EventData/e:Data", _EVT_NS):
                if data.get("Name"):
                    event[data.get("Name")] = data.text
            yield event


def _iter_jsonl(path: Path) -> Iterator[Event]:
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{n}: invalid JSON ({exc})") from exc
            event.setdefault("EventID", 1)
            yield event


def iter_events(path: Path) -> Iterator[Event]:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        yield from _iter_evtx(path)
    elif suffix in (".jsonl", ".ndjson"):
        yield from _iter_jsonl(path)
    else:
        raise SystemExit(f"Unsupported log format: {path} (use .evtx or .jsonl)")


def log_files(folder: Path) -> Iterable[Path]:
    folder = Path(folder)
    if not folder.exists():
        return []
    return sorted(
        p for p in folder.iterdir()
        if p.is_file() and p.suffix.lower() in (".evtx", ".jsonl", ".ndjson")
    )
