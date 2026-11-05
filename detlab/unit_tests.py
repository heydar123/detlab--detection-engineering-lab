"""Unit tests that live inside each rule file.

A rule ships with small, readable test cases, the same way code ships with unit tests:

    tests:
      - name: a dumping tool opens LSASS with full access
        expect: fire
        events:
          - {action: process_access, process_name: procdump.exe, target_process: lsass.exe, granted_access: "0x1fffff"}
      - name: the antivirus engine reading LSASS is allowed
        expect: no_fire
        events:
          - {action: process_access, process_name: MsMpEng.exe, target_process: lsass.exe, granted_access: "0x1fffff"}

``events`` are short. Missing times are filled in (each event one second after the previous one). An
event can say ``at: 5m`` to start later, ``repeat: 25`` to be written 25 times and ``every: 10s`` to space
the copies out. Times accept s, m, h and d. In a repeated event, ``{i}`` inside a text value becomes the
copy number, so ``user: "user{i}"`` writes twelve different users. Each case runs the rule alone, with its documented exclusions,
so a test can prove that an exclusion still lets the real attack through.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .models import fmt_ts, prepare_events

BASE_T = datetime(2026, 1, 5, 9, 0, 0, tzinfo=timezone.utc).timestamp()   # a Monday morning
MAX_REPEAT = 5000
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_TIME_RE = re.compile(r"^(\d+)([smhd]?)$")
META_KEYS = {"at", "every", "repeat"}


def parse_duration(value, where: str = "time") -> int:
    """Turn 90, "90s", "5m", "3h" or "4d" into seconds."""
    if isinstance(value, bool):
        raise ValueError(f"{where}: {value!r} is not a time")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{where}: {value!r} must not be negative")
        return value
    m = _TIME_RE.match(str(value).strip())
    if not m:
        raise ValueError(f"{where}: {value!r} is not a time (use a number of seconds, or 90s, 5m, 3h, 4d)")
    return int(m.group(1)) * _UNITS[m.group(2) or "s"]


def expand_events(items: list[dict]) -> list[dict]:
    """Turn the short test notation into full events with ids and times."""
    events: list[dict] = []
    cursor = 0
    for item in items:
        fields = {k: v for k, v in item.items() if k not in META_KEYS}
        start = parse_duration(item["at"], "at") if "at" in item else cursor
        repeat = int(item.get("repeat", 1))
        every = parse_duration(item.get("every", 1), "every")
        for i in range(repeat):
            # "{i}" in a text value becomes the copy number (0, 1, 2 ...), so one line can write
            # twelve different users: user: "user{i}".
            filled = {k: (v.replace("{i}", str(i)) if isinstance(v, str) else v) for k, v in fields.items()}
            events.append({"event_id": f"t{len(events) + 1:05d}", "ts": fmt_ts(BASE_T + start + i * every), **filled})
        cursor = start + (repeat - 1) * every + 1
    return prepare_events(events)


def check_test_shape(rule: dict, name: str) -> list[str]:
    """Lint the tests: present, well formed, and covering both a firing and a quiet case."""
    tests = rule.get("tests")
    if not isinstance(tests, list) or not tests:
        return [f"{name}: tests must be a non-empty list (every rule needs unit tests)"]
    errors: list[str] = []
    expects: list[str] = []
    for i, case in enumerate(tests, start=1):
        where = f"{name}: test #{i}"
        if not isinstance(case, dict):
            errors.append(f"{where} must be a mapping with name, expect and events")
            continue
        if not str(case.get("name", "")).strip():
            errors.append(f"{where} needs a name")
        if case.get("expect") not in ("fire", "no_fire"):
            errors.append(f"{where} ({case.get('name', '?')}): expect must be 'fire' or 'no_fire'")
        else:
            expects.append(case["expect"])
        events = case.get("events")
        if not isinstance(events, list) or not events or not all(isinstance(e, dict) and e for e in events):
            errors.append(f"{where} ({case.get('name', '?')}): events must be a non-empty list of mappings")
            continue
        if "alerts" in case and (isinstance(case["alerts"], bool) or not isinstance(case["alerts"], int)
                                 or case["alerts"] < 0):
            errors.append(f"{where} ({case.get('name', '?')}): alerts must be a whole number")
        for j, ev in enumerate(events, start=1):
            for key in ("at", "every"):
                if key in ev:
                    try:
                        parse_duration(ev[key], f"{where} event #{j} {key}")
                    except ValueError as exc:
                        errors.append(str(exc))
            rep = ev.get("repeat", 1)
            if isinstance(rep, bool) or not isinstance(rep, int) or not 1 <= rep <= MAX_REPEAT:
                errors.append(f"{where} event #{j}: repeat must be a whole number from 1 to {MAX_REPEAT}")
    if "fire" not in expects:
        errors.append(f"{name}: needs at least one test with expect: fire (proof the rule catches something)")
    if "no_fire" not in expects:
        errors.append(f"{name}: needs at least one test with expect: no_fire (proof the rule stays quiet)")
    return errors


def run_rule_tests(rules: list[dict], only: str | None = None) -> list[dict]:
    """Run every test case of every rule. One result row per case."""
    from .engine import run_rules   # imported here: engine does not need this module

    rows: list[dict] = []
    for rule in rules:
        if only and rule.get("id") != only:
            continue
        for case in rule.get("tests", []):
            row = {"rule": rule["id"], "name": case["name"], "expect": case["expect"], "passed": False,
                   "alerts": 0, "message": ""}
            try:
                events = expand_events(case["events"])
                alerts = run_rules(events, [rule], use_exclusions=True)
            except Exception as exc:  # a broken test must be reported, not crash the run
                row["message"] = f"could not run: {exc}"
                rows.append(row)
                continue
            row["alerts"] = len(alerts)
            fired = len(alerts) > 0
            wanted = case["expect"] == "fire"
            if "alerts" in case and len(alerts) != case["alerts"]:
                row["message"] = f"expected exactly {case['alerts']} alert(s), got {len(alerts)}"
            elif fired != wanted:
                row["message"] = ("expected an alert but none fired" if wanted
                                  else f"expected no alert but {len(alerts)} fired")
            else:
                row["passed"] = True
            rows.append(row)
    return rows


def exclusion_checks(rules: list[dict], only: str | None = None) -> list[dict]:
    """For every exclusion, prove that at least one test of the same rule depends on it.

    An exclusion is "exercised" when taking it away makes some test produce more alerts. An exclusion that
    no test depends on is a hole in the rule that nobody is watching.
    """
    from .engine import run_rules

    rows: list[dict] = []
    for rule in rules:
        if only and rule.get("id") != only:
            continue
        exclusions = rule.get("exclusions") or []
        if not exclusions:
            continue
        prepared: list[list[dict]] = []
        for case in rule.get("tests", []):
            try:
                prepared.append(expand_events(case["events"]))
            except Exception:  # a broken test is reported by run_rule_tests
                continue
        baseline = [len(run_rules(events, [rule], use_exclusions=True)) for events in prepared]
        for i, ex in enumerate(exclusions):
            weaker = {**rule, "exclusions": [e for j, e in enumerate(exclusions) if j != i]}
            exercised = any(len(run_rules(events, [weaker], use_exclusions=True)) > base
                            for events, base in zip(prepared, baseline))
            rows.append({"rule": rule["id"], "index": i + 1, "reason": str(ex.get("reason", "")),
                         "exercised": exercised})
    return rows


# ------------------------------------------------------------------ proving that the tests would notice a change

FILTER_KEYS = ("filter", "failure_filter", "success_filter")
COUNT_KEYS = ("threshold", "min_failures", "min_events", "max_minutes", "learning_seconds", "window_seconds")
_CHAIN_START = re.compile(r"^(\(\?[a-z]+\))?\^")


def _lookahead_chain(pattern: str):
    """(flags, parts) when the whole regex is ``^`` followed by two or more lookaheads, else None.

    ``(?i)^(?=.*A)(?=.*B)(?!.*C)`` means "A and B are present and C is not": three conditions in one pattern.
    """
    from .sigma import NotExportable, _group_end

    m = _CHAIN_START.match(pattern)
    if not m:
        return None
    body, parts = pattern[m.end():], []
    try:
        while body:
            if not body.startswith(("(?=", "(?!")):
                return None
            end = _group_end(body, 0)
            parts.append(body[:end + 1])
            body = body[end + 1:]
    except NotExportable:
        return None
    return (m.group(1) or "", parts) if len(parts) > 1 else None


def rule_mutants(rule: dict):
    """Small edits of one rule. Each one should make at least one of the rule's own tests fail.

    Yields (what was changed, the changed rule). The edits are: take out one whole branch of a filter, delete one
    condition, drop one listed value from a condition, drop one lookahead from a regular expression that is a chain of
    them (``^(?=.*A)(?!.*B)`` is two conditions), move a counting number (threshold, min_failures, min_events,
    max_minutes, learning_seconds, window_seconds) up or down by one, stop grouping by one of the group_by fields, and
    take out the alert throttling (suppress_seconds). Other changes inside a regular expression are not tried. If a
    test suite cannot tell a rule from its edited copy, nobody would notice when someone makes that edit by accident.
    """
    import copy

    for key in FILTER_KEYS:
        if key not in rule:
            continue
        flt = rule[key]
        many = isinstance(flt, list)
        for bi, branch in enumerate(flt if many else [flt]):
            where = f"{key}[{bi}]" if many else key
            if many and len(flt) > 1:
                changed = copy.deepcopy(rule)
                del changed[key][bi]
                yield f"take out branch {bi} of {key}", changed
            for cond, expected in branch.items():
                if cond == "action":
                    continue
                changed = copy.deepcopy(rule)
                del (changed[key][bi] if many else changed[key])[cond]
                yield f"delete the condition '{cond}' from {where}", changed
                if cond != "not" and isinstance(expected, list) and len(expected) > 1:
                    for vi, value in enumerate(expected):
                        changed = copy.deepcopy(rule)
                        del (changed[key][bi] if many else changed[key])[cond][vi]
                        yield f"drop the value {value!r} from '{cond}' in {where}", changed
                chain = _lookahead_chain(expected) if cond.endswith("|regex") and isinstance(expected, str) else None
                if chain:
                    flags, parts = chain
                    for pi, part in enumerate(parts):
                        changed = copy.deepcopy(rule)
                        (changed[key][bi] if many else changed[key])[cond] = flags + "^" + "".join(
                            p for i, p in enumerate(parts) if i != pi)
                        shown = part if len(part) <= 50 else part[:47] + "..."
                        yield f"drop the part {shown} from the pattern of '{cond}' in {where}", changed
    for key in COUNT_KEYS:
        value = rule.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            for new in (value - 1, value + 1):
                if new >= 1:
                    changed = copy.deepcopy(rule)
                    changed[key] = new
                    yield f"change {key} from {value} to {new}", changed
    groups = rule.get("group_by")
    if isinstance(groups, list):
        for field in groups:
            changed = copy.deepcopy(rule)
            changed["group_by"] = [g for g in groups if g != field]
            yield f"stop grouping by '{field}' (group_by {groups} becomes {changed['group_by']})", changed
    if isinstance(rule.get("suppress_seconds"), int) and rule["suppress_seconds"] > 0:
        changed = copy.deepcopy(rule)
        del changed["suppress_seconds"]
        yield f"take out the alert throttling (suppress_seconds {rule['suppress_seconds']})", changed


def mutation_checks(rules: list[dict], only: str | None = None) -> list[dict]:
    """For every small edit of every rule: does at least one test of that rule fail? One row per edit."""
    rows: list[dict] = []
    for rule in rules:
        if only and rule.get("id") != only:
            continue
        for what, changed in rule_mutants(rule):
            caught = any(not r["passed"] for r in run_rule_tests([changed]))
            rows.append({"rule": rule["id"], "edit": what, "caught": caught})
    return rows

