"""Sigma-style field matching.

A filter is one of:

* a mapping of ``field`` or ``field|modifier`` keys. Every key must match (AND).
* a list of filters. Any one of them may match (OR).

A mapping may also contain the key ``not`` whose value is a filter that must NOT match.

A key may name several fields separated by commas, for example ``process_name,original_name|in``. It then
matches when ANY of those fields matches. That is how a rule recognises a tool that was renamed: the file
name changed, but the name stored inside the program file (``original_name``) did not.

Modifiers: equals (default), in, contains, contains_all, startswith, endswith, regex,
gt, gte, lt, lte (numbers), bitany and bitall (test bits of a hex or decimal number, for example
an access mask), and exists (true or false). String comparisons are
case-insensitive, except regex, which uses whatever flags the pattern sets itself
(for example ``(?i)``).
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

VALID_OPS = {"equals", "in", "contains", "contains_all", "startswith", "endswith", "regex",
             "gt", "gte", "lt", "lte", "bitany", "bitall", "exists"}
NUMERIC_OPS = {"gt", "gte", "lt", "lte"}
BIT_OPS = {"bitany", "bitall"}


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def parse_key(key: str) -> tuple[str, str]:
    field, _, op = key.partition("|")
    return field, (op or "equals")


def split_fields(field: str) -> list[str]:
    """``a,b`` -> ["a", "b"]. A plain field name comes back as a one-item list."""
    return [f.strip() for f in field.split(",")] if "," in field else [field]


def _norm(value: Any) -> str:
    return str(value).casefold()


def _as_list(expected: Any) -> list:
    return expected if isinstance(expected, list) else [expected]


def _number(value: Any):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bits(value: Any):
    """A whole number from 0x1fffff style hex text or plain decimal text; None when it is neither."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


def _condition_ok(value: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        present = value is not None and value != ""
        return present if expected else not present
    if value is None:
        return False
    if op == "equals":
        return _norm(value) == _norm(expected)
    if op == "in":
        return _norm(value) in {_norm(x) for x in _as_list(expected)}
    if op == "contains":
        text = _norm(value)
        return any(_norm(x) in text for x in _as_list(expected))
    if op == "contains_all":
        text = _norm(value)
        return all(_norm(x) in text for x in _as_list(expected))
    if op == "startswith":
        text = _norm(value)
        return any(text.startswith(_norm(x)) for x in _as_list(expected))
    if op == "endswith":
        text = _norm(value)
        return any(text.endswith(_norm(x)) for x in _as_list(expected))
    if op == "regex":
        return _compile(str(expected)).search(str(value)) is not None
    if op in NUMERIC_OPS:
        a, b = _number(value), _number(expected)
        if a is None or b is None:
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op in BIT_OPS:
        a = _bits(value)
        masks = [_bits(x) for x in _as_list(expected)]
        if a is None or any(m is None for m in masks):
            return False
        if op == "bitany":
            return any(a & m for m in masks)
        return all(a & m == m for m in masks)
    raise ValueError(f"unknown match modifier: {op!r}")


def matches(event: dict, flt: Any) -> bool:
    """True when the event satisfies the filter (a mapping, or a list meaning "any of")."""
    if isinstance(flt, list):
        return any(matches(event, one) for one in flt)
    for key, expected in flt.items():
        if key == "not":
            if matches(event, expected):
                return False
            continue
        field, op = parse_key(key)
        if "," in field:
            if not any(_condition_ok(event.get(f), op, expected) for f in split_fields(field)):
                return False
        elif not _condition_ok(event.get(field), op, expected):
            return False
    return True


def excluded(event: dict, exclusions: list[dict]) -> bool:
    """True when the event matches any documented exclusion."""
    return any(matches(event, ex["match"]) for ex in exclusions)


def validate_filter(flt: Any, where: str) -> list[str]:
    if isinstance(flt, list):
        if not flt:
            return [f"{where}: a list of filters must not be empty"]
        errors: list[str] = []
        for i, one in enumerate(flt):
            errors.extend(validate_filter(one, f"{where}[{i}]"))
        return errors
    if not isinstance(flt, dict) or not flt:
        return [f"{where}: filter must be a non-empty mapping (or a list of them)"]
    errors = []
    for key, expected in flt.items():
        if key == "not":
            errors.extend(validate_filter(expected, f"{where}.not"))
            continue
        field, op = parse_key(str(key))
        if not field or not all(split_fields(field)):
            errors.append(f"{where}: empty field name in key {key!r}")
        if "," in field and op == "exists":
            errors.append(f"{where}: {key!r} cannot combine several fields with 'exists'")
        if op not in VALID_OPS:
            errors.append(f"{where}: unknown modifier {op!r} in key {key!r}")
        if op == "regex":
            try:
                re.compile(str(expected))
            except re.error as exc:
                errors.append(f"{where}: invalid regex for {key!r}: {exc}")
        if op in NUMERIC_OPS and _number(expected) is None:
            errors.append(f"{where}: {key!r} needs a number, not {expected!r}")
        if op in BIT_OPS and any(_bits(x) is None for x in _as_list(expected)):
            errors.append(f"{where}: {key!r} needs numbers such as 0x38 or 56, not {expected!r}")
        if op == "exists" and not isinstance(expected, bool):
            errors.append(f"{where}: {key!r} must be true or false")
    return errors


def filter_fields(flt: Any) -> set[str]:
    """Every event field a filter reads."""
    if isinstance(flt, list):
        return set().union(*(filter_fields(one) for one in flt)) if flt else set()
    if not isinstance(flt, dict):
        return set()
    out: set[str] = set()
    for key, expected in flt.items():
        if key == "not":
            out |= filter_fields(expected)
        else:
            out |= {f for f in split_fields(parse_key(str(key))[0]) if f}
    return out


def filter_actions(flt: Any) -> set[str] | None:
    """The set of ``action`` values a filter can possibly match, or None when it is not limited.

    This is only used to skip events that cannot match (a speed-up); it never changes results.
    """
    if isinstance(flt, list):
        merged: set[str] = set()
        for one in flt:
            sub = filter_actions(one)
            if sub is None:
                return None
            merged |= sub
        return merged
    if not isinstance(flt, dict):
        return None
    for key, expected in flt.items():
        field, op = parse_key(str(key))
        if field == "action" and op in ("equals", "in"):
            return {_norm(x) for x in _as_list(expected)}
    return None
