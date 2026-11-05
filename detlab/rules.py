"""Loading and validating detection rules (the 'lint' step of detection-as-code)."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import yaml
except ImportError:
    # PyYAML is not installed (for example on a very new Python that has no prebuilt PyYAML
    # yet). Use the bundled pure-Python copy so the project runs with nothing to install.
    from ._vendor import yaml

from .engine import rule_actions
from .matching import filter_fields, validate_filter
from .models import SEVERITY_ORDER
from .schema import known_fields, suggest
from .unit_tests import check_test_shape

RULE_TYPES = {
    "match": ["filter"],
    "threshold": ["filter", "group_by", "window_seconds", "threshold"],
    "distinct_threshold": ["filter", "group_by", "distinct_field", "window_seconds", "threshold"],
    "sum_threshold": ["filter", "group_by", "sum_field", "window_seconds", "threshold"],
    "beaconing": ["filter", "group_by", "window_seconds", "min_events", "max_cv",
                  "min_interval_seconds", "max_interval_seconds"],
    "first_seen": ["filter", "group_by", "value_field", "learning_seconds"],
    "impossible_travel": ["filter", "max_minutes"],
    "fail_then_success": ["failure_filter", "success_filter", "group_by", "window_seconds", "min_failures"],
}
COMMON_REQUIRED = ["id", "title", "status", "severity", "attack", "description", "type", "triage", "response", "tests"]
STATUSES = ["stable", "experimental"]
# The 15 tactics of ATT&CK Enterprise v20 in matrix order. v20 replaced "Defense Evasion" with "Stealth" and
# "Defense Impairment".
TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
           "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
ID_RE = re.compile(r"^DET-\d{3}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
POSITIVE_INT_KEYS = ["window_seconds", "threshold", "max_minutes", "min_failures", "learning_seconds",
                     "min_events", "min_interval_seconds", "max_interval_seconds"]


def load_rules(path: str | Path) -> list[dict]:
    """Load every *.yml rule in a directory (or a single file), sorted by id."""
    p = Path(path)
    files = sorted(p.glob("*.yml")) if p.is_dir() else [p]
    rules = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
        if not isinstance(rule, dict):
            raise ValueError(f"{f.name}: a rule file must be a list of 'name: value' lines (a YAML mapping)")
        rule["_file"] = f.name
        rules.append(rule)
    return sorted(rules, key=lambda r: r.get("id", ""))


def parse_rule_text(text: str, filename: str = "<editor>") -> dict:
    """Parse rule text typed into an editor. Raises ValueError with a readable message."""
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"The text is not valid YAML. {str(exc).splitlines()[0] if str(exc) else ''}".strip()) from exc
    if not isinstance(rule, dict):
        raise ValueError("A rule must be a list of 'name: value' lines (a YAML mapping).")
    rule["_file"] = filename
    return rule


def rule_fields(rule: dict) -> set[str]:
    """Every event field a rule reads (filters, grouping, entity, and the counted field)."""
    used: set[str] = set()
    for key in ("filter", "failure_filter", "success_filter"):
        if key in rule:
            used |= filter_fields(rule[key])
    for ex in rule.get("exclusions", []) or []:
        if isinstance(ex, dict) and "match" in ex:
            used |= filter_fields(ex["match"])
    for key in ("group_by", "entity_fields"):
        if isinstance(rule.get(key), list):
            used |= {str(f) for f in rule[key]}
    for key in ("distinct_field", "sum_field", "value_field"):
        if isinstance(rule.get(key), str):
            used.add(rule[key])
    return used


def validate_rule(rule: dict) -> list[str]:
    errors: list[str] = []
    name = rule.get("_file", rule.get("id", "<rule>"))

    for key in COMMON_REQUIRED:
        if key not in rule:
            errors.append(f"{name}: missing required key '{key}'")
    if errors:
        return errors

    if not ID_RE.match(str(rule["id"])):
        errors.append(f"{name}: id must look like DET-001")
    if rule["severity"] not in SEVERITY_ORDER:
        errors.append(f"{name}: severity must be one of {sorted(SEVERITY_ORDER)}")
    if rule["status"] not in STATUSES:
        errors.append(f"{name}: status must be one of {STATUSES}")
    attack = rule["attack"]
    if not isinstance(attack, dict):
        return errors + [f"{name}: attack must be a mapping with tactic, technique and technique_name"]
    for key in ("tactic", "technique", "technique_name"):
        if key not in attack:
            errors.append(f"{name}: attack.{key} is required")
    if "technique" in attack and not TECHNIQUE_RE.match(str(attack["technique"])):
        errors.append(f"{name}: attack.technique must look like T1110 or T1110.001")
    if "tactic" in attack and attack["tactic"] not in TACTICS:
        errors.append(f"{name}: attack.tactic must be an ATT&CK tactic name, one of {TACTICS}")
    for extra in attack.get("also", []) or []:
        if not TECHNIQUE_RE.match(str(extra)):
            errors.append(f"{name}: attack.also entry {extra!r} must look like T1110 or T1110.001")
    for key in ("triage", "response"):
        steps = rule[key]
        if not isinstance(steps, list) or not steps:
            errors.append(f"{name}: {key} must be a non-empty list of steps")
        elif not all(isinstance(s, str) for s in steps):
            errors.append(f"{name}: every {key} step must be plain text "
                          "(a step containing ': ' must be quoted in YAML or it parses as a mapping)")

    rtype = rule["type"]
    if rtype not in RULE_TYPES:
        errors.append(f"{name}: unknown type {rtype!r} (valid: {sorted(RULE_TYPES)})")
        return errors
    for key in RULE_TYPES[rtype]:
        if key not in rule:
            errors.append(f"{name}: type '{rtype}' requires '{key}'")
    for key in POSITIVE_INT_KEYS:
        if key in rule and (isinstance(rule[key], bool) or not isinstance(rule[key], int) or rule[key] <= 0):
            errors.append(f"{name}: {key} must be a positive integer")
    if "suppress_seconds" in rule:
        if rtype != "match":
            errors.append(f"{name}: suppress_seconds only applies to match rules")
        elif isinstance(rule["suppress_seconds"], bool) or not isinstance(rule["suppress_seconds"], int) \
                or rule["suppress_seconds"] < 0:
            errors.append(f"{name}: suppress_seconds must be zero or a positive integer")
    if rtype == "beaconing":
        cv = rule.get("max_cv")
        if isinstance(cv, bool) or not isinstance(cv, (int, float)) or not 0 < cv <= 1:
            errors.append(f"{name}: max_cv must be a number above 0 and at most 1")
        lo, hi = rule.get("min_interval_seconds"), rule.get("max_interval_seconds")
        if isinstance(lo, int) and isinstance(hi, int) and lo > hi:
            errors.append(f"{name}: min_interval_seconds must not be larger than max_interval_seconds")
        win, need = rule.get("window_seconds"), rule.get("min_events")
        if all(isinstance(v, int) for v in (win, need, lo)) and win < need * lo:
            errors.append(f"{name}: window_seconds is too short for min_events at min_interval_seconds, "
                          "so this rule could never fire")
    for key in ("filter", "failure_filter", "success_filter"):
        if key in rule:
            errors.extend(validate_filter(rule[key], f"{name}.{key}"))
    if rtype == "match" and "entity_fields" not in rule:
        errors.append(f"{name}: match rules need 'entity_fields' so alerts identify who/what")

    for i, ex in enumerate(rule.get("exclusions", []) or []):
        if "match" not in ex or "reason" not in ex or not str(ex["reason"]).strip():
            errors.append(f"{name}: exclusion #{i + 1} needs both 'match' and a written 'reason'")
        else:
            errors.extend(validate_filter(ex["match"], f"{name}.exclusions[{i}]"))

    # A typo in a field name makes a rule silently match nothing, so check every field against the schema.
    if not errors:
        allowed = known_fields(rule_actions(rule))
        for field in sorted(rule_fields(rule)):
            if field not in allowed:
                errors.append(f"{name}: unknown field '{field}'{suggest(field, allowed)}")

    errors.extend(check_test_shape(rule, name))
    return errors


def validate_rules(rules: list[dict]) -> list[str]:
    errors: list[str] = []
    seen: dict[str, str] = {}
    for rule in rules:
        errors.extend(validate_rule(rule))
        rid = rule.get("id")
        if rid in seen:
            errors.append(f"{rule.get('_file')}: duplicate id {rid} (also in {seen[rid]})")
        elif rid:
            seen[rid] = rule.get("_file", "?")
    return errors
