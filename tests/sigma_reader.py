"""A small, separate Sigma reader, used to check the exporter.

The exporter (detlab/sigma.py) turns a lab rule into Sigma text. This file reads that Sigma text again and decides,
event by event, whether the Sigma rule would alert. It shares NO matching code with the lab's engine: it only knows
how Sigma is meant to be read (field|modifier keys, a list means OR, |all means AND, a condition made of and / or / not,
and event_count / value_count correlations).

It is used to ask one question: does the Sigma file give the same fire / no-fire answer as the lab's engine, for the
unit tests of the rule, for the made-up logs, for the real recordings, and for events built from the rule itself?

What this does and does not prove:

* It checks the LOGIC of the translation: values, modifiers, AND / OR, negation, the regular expressions that were
  rewritten because Sigma back-ends have no lookahead, and the counting rules.
* It does not prove that a field name is right for a real product. To make a record from a lab event it uses the
  exporter's own table of field names. pySigma (see tools/make_sigma_queries.py) is the check for that part, and
  even that was only converted, never run on a live SIEM.
"""

from __future__ import annotations

import re
from collections import defaultdict

from detlab.sigma import SOURCES
from detlab.unit_tests import parse_duration

SYSTEM32 = "C:\\Windows\\System32\\"
# Sigma logs the full path of a program. A lab event often has only the file name, so a path is made up for it.
PATH_FIELD = {"process_name": "process_path", "parent_process": "parent_path", "target_process": "target_path"}


# ------------------------------------------------------------------ one event -> the log records it could be

def records_for(event: dict) -> list[dict]:
    """The log records a product could hold for this lab event, in Sigma's field names ([] if the kind is unknown).

    Some lab events are logged under several event ids (a change to a privileged group has three). There is one
    record per id, because a Sigma rule has to catch the event whichever id it was written under.
    """
    src = SOURCES.get(event.get("action"))
    if src is None:
        return []
    base: dict = {}
    for field, sigma_name in src["fields"].items():
        value = event.get(field)
        if value is None:
            continue
        if field in src["names"]:
            value = event.get(PATH_FIELD.get(field, "")) or SYSTEM32 + str(value)
        base[sigma_name] = value
    if "outcome_ids" in src:
        # a logon writes one id for a success and another for a failure; an unknown outcome has no id at all
        ids = [src["outcome_ids"].get(event.get("outcome"))]
    else:
        static = src["static"].get("EventID")
        ids = static if isinstance(static, list) else [static]
    records = []
    for event_id in ids:
        record = dict(base)
        if event_id is not None:
            record["EventID"] = event_id
        records.append(record)
    return records


# ------------------------------------------------------------------ one selection, one condition

_RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
_KINDS = ("contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte")


def field_matches(record: dict, key: str, expected) -> bool:
    field, *mods = key.split("|")
    value = record.get(field)
    if "exists" in mods:
        return (value not in (None, "")) == bool(expected)
    if value is None:
        return False
    kind = next((m for m in mods if m in _KINDS), "equals")
    flags = 0
    for m in mods:
        flags |= _RE_FLAGS.get(m, 0)
    wanted = expected if isinstance(expected, list) else [expected]

    def one(want) -> bool:
        if kind == "re":
            return re.search(str(want), str(value), flags) is not None
        if kind in ("gt", "gte", "lt", "lte"):
            a, b = float(value), float(want)
            return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[kind]
        a, b = str(value).casefold(), str(want).casefold()
        return {"equals": a == b, "contains": b in a, "startswith": a.startswith(b), "endswith": a.endswith(b)}[kind]

    results = [one(w) for w in wanted]
    return all(results) if "all" in mods else any(results)


def selection_matches(selection, record: dict) -> bool:
    """A mapping: every key must match. A list of mappings: any one may match."""
    if isinstance(selection, list):
        return any(selection_matches(s, record) for s in selection)
    return all(field_matches(record, key, expected) for key, expected in selection.items())


def condition_true(detection: dict, record: dict) -> bool:
    """Evaluate ``detection['condition']`` (names, and, or, not, brackets) against one record."""
    tokens = re.findall(r"\(|\)|\w+", detection["condition"])
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        token = peek()
        pos += 1
        return token

    def expr() -> bool:
        value = term()
        while peek() == "or":
            take()
            right = term()
            value = value or right
        return value

    def term() -> bool:
        value = factor()
        while peek() == "and":
            take()
            right = factor()
            value = value and right
        return value

    def factor() -> bool:
        token = take()
        if token is None:
            raise ValueError("the condition stops where a name was expected")
        if token == "not":
            return not factor()
        if token == "(":
            value = expr()
            if take() != ")":
                raise ValueError("a bracket in the condition is not closed")
            return value
        if token not in detection:
            raise ValueError(f"the condition names '{token}', which the detection does not define")
        return selection_matches(detection[token], record)

    value = expr()
    if pos != len(tokens):
        raise ValueError(f"the condition has text left over: {tokens[pos:]}")
    return value


# ------------------------------------------------------------------ one event, all the documents of a rule

def sigma_event_matches(docs: list[dict], event: dict) -> bool | None:
    """Would the detection documents (a correlation is ignored) select this one event?

    True: selected under every event id it could carry. False: under none. None: under some ids only, which means
    the rule would miss the event depending on how the product happened to log it.
    """
    records = records_for(event)
    if not records:
        return False
    logsource = SOURCES[event["action"]]["logsource"]
    answers = {any(d["logsource"] == logsource and condition_true(d["detection"], rec)
                   for d in docs if "detection" in d) for rec in records}
    return answers.pop() if len(answers) == 1 else None


# ------------------------------------------------------------------ a whole exported rule (counting included)

def correlation_fires(corr: dict, hits: list[tuple[dict, dict]]) -> bool:
    """event_count and value_count over a sliding window, per group."""
    seconds = parse_duration(corr["timespan"], "timespan")
    need = corr["condition"]["gte"]
    counted = corr["condition"].get("field")
    groups: dict[tuple, list[tuple[float, dict]]] = defaultdict(list)
    for event, rec in hits:
        groups[tuple(rec.get(f) for f in corr["group-by"])].append((event["_t"], rec))
    for items in groups.values():
        items.sort(key=lambda pair: pair[0])
        low = 0
        for high in range(len(items)):
            while items[high][0] - items[low][0] > seconds:
                low += 1
            window = items[low:high + 1]
            n = len({rec.get(counted) for _, rec in window}) if corr["type"] == "value_count" else len(window)
            if n >= need:
                return True
    return False


def sigma_fires(docs: list[dict], events: list[dict]) -> bool:
    """True when the Sigma documents of one rule would alert on these events (events need a ``_t`` time)."""
    detections = {d["name"]: d for d in docs if "detection" in d}
    correlations = [d for d in docs if "correlation" in d]
    hits: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for event in events:
        records = records_for(event)
        if not records:
            continue
        for name, doc in detections.items():
            if doc["logsource"] == SOURCES[event["action"]]["logsource"] \
                    and all(condition_true(doc["detection"], rec) for rec in records):
                hits[name].append((event, records[0]))
    if not correlations:
        return any(hits.values())
    return any(correlation_fires(c["correlation"], [h for name in c["correlation"]["rules"] for h in hits[name]])
               for c in correlations)


# ------------------------------------------------------------------ events built from the rule itself

def field_pool(event_lists, per_field: int = 3000) -> dict[str, list]:
    """Every distinct text value seen for each field, in the order first seen (used to satisfy regular expressions)."""
    seen: dict[str, set] = defaultdict(set)
    pool: dict[str, list] = defaultdict(list)
    for events in event_lists:
        for ev in events:
            for key, value in ev.items():
                if isinstance(value, str) and len(value) < 400 and value not in seen[key] and len(seen[key]) < per_field:
                    seen[key].add(value)
                    pool[key].append(value)
    return pool


def _satisfying_values(op: str, expected) -> list | None:
    """Values that satisfy one condition, one for each value the rule lists. None when none can be made up."""
    values = expected if isinstance(expected, list) else [expected]
    if op in ("equals", "in"):
        return list(values)
    if op == "contains":
        return [f"a{v}b" for v in values]
    if op == "contains_all":
        return [" ".join(str(v) for v in values)]
    if op == "startswith":
        return [f"{v}tail" for v in values]
    if op == "endswith":
        return [f"head{v}" for v in values]
    if op in ("gt", "gte"):
        return [float(expected) + 1]
    if op in ("lt", "lte"):
        return [float(expected) - 1]
    if op == "exists" and expected:
        return ["x"]
    return None


def witness_events(rule: dict, pool: dict[str, list], value_fits) -> list[dict]:
    """Events made from the rule's own filter, to test the export on every value the rule lists.

    For each branch of the filter: one event that satisfies every condition, then variations of it that use each
    listed value of each condition in turn, then one near miss per condition (that condition broken, the rest kept).
    A condition that cannot be satisfied by making up a value (a regular expression) is satisfied with a real value
    taken from ``pool`` (the unit tests and the recorded data) when one fits; the engine decides whether a pool value
    fits (``value_fits(value, op, expected)``). A branch that still has no value is left out.
    """
    from detlab.matching import parse_key, split_fields

    out: list[dict] = []
    seen: set = set()

    def add(fields: dict) -> None:
        marker = tuple(sorted((k, str(v)) for k, v in fields.items()))
        if marker not in seen:
            seen.add(marker)
            out.append(dict(fields))

    branches = rule["filter"] if isinstance(rule["filter"], list) else [rule["filter"]]
    for branch in branches:
        conditions = []                       # (fields, alternatives) where alternatives is a list of {field: value}
        for key, expected in branch.items():
            if key == "not":
                continue
            field_text, op = parse_key(str(key))
            fields = split_fields(field_text)
            alts: list[dict] = []
            for f in fields:
                values = _satisfying_values(op, expected)
                if values is None:
                    values = [v for v in pool.get(f, []) if value_fits(v, op, expected)][:3]
                alts += [{f: v} for v in values]
            if not alts:
                conditions = []
                break
            conditions.append((fields, alts))
        if not conditions:
            continue
        base: dict = {}
        for _, alts in conditions:
            base.update(alts[0])
        if "action" not in base:
            base["action"] = next(a for a, s in SOURCES.items() if all(f in s["fields"] or f == "outcome" for f in base))
        add(base)
        for fields, alts in conditions:
            for alt in alts:
                event = {k: v for k, v in base.items() if k not in fields}
                event.update(alt)
                add(event)
            miss = {k: v for k, v in base.items() if k not in fields}
            miss[fields[0]] = "zz-no-such-value"
            add(miss)
    for i, event in enumerate(out):
        event["event_id"] = f"w{i:05d}"
        event["_t"] = 1_760_000_000.0 + i
    return out
