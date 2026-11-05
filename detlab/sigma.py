"""Export detection-lab rules as Sigma rules (https://sigmahq.io), so they can be converted for other products.

Only the DETECTION LOGIC is exported. A rule's site-specific exclusions (a service account, a server name, a ticket
number) stay in the lab's own rule files, and each one is listed under ``falsepositives`` instead. That is how shared
Sigma rules are normally written: the logic is portable, the exceptions belong to one site.

Not every rule can be written in Sigma. ``export_rule`` says why, in plain words, for each one it leaves out:

* a bit test on a number (Sigma has no such test),
* a value derived by the engine (for example the parent domain of a DNS name),
* a rule that needs a baseline, a sequence, statistics or geography (first seen, beaconing, impossible travel...),
* a log source that differs between products (the same login event comes from Entra ID, a VPN and RDP).

The converter has no dependencies. Turning Sigma into Splunk or Kusto queries is done by pySigma, see
``tools/make_sigma_queries.py``.
"""

from __future__ import annotations

import itertools
import json
import re
import uuid
from pathlib import Path

from .matching import parse_key, split_fields

SIGMA_DATE = "2026-11-04"
NAMESPACE = uuid.UUID("6f0a6bd0-5d3b-4a55-9a52-0c7a2d1f6e11")

_SEC = {"product": "windows", "service": "security"}

# How each event action is written in Sigma: log source, fixed conditions, and the Sigma name of each field.
# "names" are fields that hold a program name; Sigma logs the full path, so a match becomes "ends with \name".
SOURCES: dict[str, dict] = {
    "process_create": {
        "logsource": {"category": "process_creation", "product": "windows"}, "static": {},
        "fields": {"process_name": "Image", "process_path": "Image", "original_name": "OriginalFileName",
                   "command_line": "CommandLine", "parent_process": "ParentImage", "user": "User",
                   "host": "Computer"},
        "names": {"process_name", "parent_process"}},
    "process_access": {
        "logsource": {"category": "process_access", "product": "windows"}, "static": {},
        "fields": {"process_name": "SourceImage", "process_path": "SourceImage", "target_process": "TargetImage",
                   "granted_access": "GrantedAccess", "call_trace": "CallTrace", "host": "Computer"},
        "names": {"process_name", "target_process"}},
    "registry_set": {
        "logsource": {"category": "registry_set", "product": "windows"}, "static": {},
        "fields": {"registry_key": "TargetObject", "registry_value": "Details", "process_name": "Image",
                   "host": "Computer", "user": "User"},
        "names": {"process_name"}},
    "file_create": {
        "logsource": {"category": "file_event", "product": "windows"}, "static": {},
        "fields": {"file_path": "TargetFilename", "process_name": "Image", "host": "Computer", "user": "User"},
        "names": {"process_name"}},
    "powershell_scriptblock": {
        "logsource": {"category": "ps_script", "product": "windows"}, "static": {},
        "fields": {"script_text": "ScriptBlockText", "host": "Computer"}, "names": set()},
    "service_install": {
        "logsource": _SEC, "static": {"EventID": 4697},
        "fields": {"service_name": "ServiceName", "service_path": "ServiceFileName",
                   "service_account": "ServiceAccount", "user": "SubjectUserName", "host": "Computer"},
        "names": set()},
    "scheduled_task_create": {
        "logsource": _SEC, "static": {"EventID": 4698},
        "fields": {"task_name": "TaskName", "task_command": "TaskContent", "user": "SubjectUserName",
                   "host": "Computer"}, "names": set()},
    "user_create": {
        "logsource": _SEC, "static": {"EventID": 4720},
        "fields": {"target_user": "TargetUserName", "user": "SubjectUserName", "host": "Computer"}, "names": set()},
    "group_add": {
        "logsource": _SEC, "static": {"EventID": [4728, 4732, 4756]},
        "fields": {"group": "TargetUserName", "user": "SubjectUserName", "host": "Computer"}, "names": set()},
    "directory_access": {
        "logsource": _SEC, "static": {"EventID": 4662},
        "fields": {"properties": "Properties", "user": "SubjectUserName", "host": "Computer"}, "names": set()},
    "audit_policy_change": {
        "logsource": _SEC, "static": {"EventID": 4719},
        "fields": {"user": "SubjectUserName", "host": "Computer"}, "names": set()},
    "log_clear": {
        "logsource": {"product": "windows"}, "static": {"EventID": [1102, 104]},
        "fields": {"user": "SubjectUserName", "host": "Computer"}, "names": set()},
    "dns_query": {
        "logsource": {"category": "dns_query", "product": "windows"}, "static": {},
        "fields": {"query": "QueryName", "process_name": "Image", "host": "Computer"}, "names": {"process_name"}},
    "host_logon": {
        "logsource": _SEC, "static": {"EventID": 4624}, "outcome_ids": {"success": 4624, "failure": 4625},
        "fields": {"logon_type": "LogonType", "user": "TargetUserName", "src_ip": "IpAddress", "host": "Computer"},
        "names": set()},
    "cloud_audit": {
        "logsource": {"product": "aws", "service": "cloudtrail"}, "static": {},
        "fields": {"event_name": "eventName", "src_ip": "sourceIPAddress"}, "names": set()},
}

# A rule whose filter has no "action" is placed by the fields it reads.
ACTION_HINTS = {"command_line": "process_create", "parent_process": "process_create",
                "script_text": "powershell_scriptblock"}

NOT_EXPORTED_TYPES = {
    "fail_then_success": "it needs a sequence of events (failures, then a success) and Sigma has no sequence form "
                         "for a field-level condition like this one",
    "impossible_travel": "it needs distance and time between two logins, which Sigma cannot compute",
    "beaconing": "it needs the spread of the gaps between connections, which Sigma cannot compute",
    "sum_threshold": "it needs a sum of bytes over a window, and Sigma correlations only count events and values",
    "first_seen": "it needs a baseline of what was seen before, which lives in the SIEM and not in the rule",
}

_FLAGS = re.compile(r"^\(\?([a-z]+)\)")


class NotExportable(Exception):
    """The rule cannot be written as Sigma. The message is the reason."""


def slug(rule_id: str) -> str:
    return "detlab_" + rule_id.lower().replace("-", "_")


def _action_of(branch: dict) -> list[str]:
    for key, val in branch.items():
        if parse_key(str(key))[0] == "action":
            return [str(v) for v in (val if isinstance(val, list) else [val])]
    for key in branch:
        for f in split_fields(parse_key(str(key))[0]):
            if f in ACTION_HINTS:
                return [ACTION_HINTS[f]]
    raise NotExportable("a branch of its filter does not say which kind of event it reads")


def _top_level_split(text: str) -> list[str]:
    """Split a regex on the | signs that are not inside a group, a character class or an escape."""
    parts, depth, cur, i, in_class = [], 0, [], 0, False
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            cur.append(text[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _group_end(text: str, start: int) -> int:
    """Index of the ')' that closes the '(' at ``start``."""
    depth, i, in_class = 0, start, False
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise NotExportable("a regular expression has unbalanced brackets")


def split_regex(pattern: str) -> tuple[str, list[tuple[list[str], list[str]]]]:
    """Rewrite lookahead regexes into forms that Sigma backends (RE2 engines) accept.

    ``^(?=.*A)(?=.*B)(?!.*C)`` means "A and B are present and C is not". Returns (flags, alternatives) where each
    alternative is (patterns that must all match, patterns that must not match). A pattern without lookaheads
    comes back as one alternative with one pattern.
    """
    flags = ""
    m = _FLAGS.match(pattern)
    if m and set(m.group(1)) <= set("ims"):
        flags, pattern = m.group(1), pattern[m.end():]
    if not any(token in pattern for token in ("(?=", "(?!", "(?<")):
        return flags, [([pattern], [])]                      # nothing to rewrite: keep the pattern as written
    if pattern.startswith("(") and _group_end(pattern, 0) == len(pattern) - 1 and not pattern.startswith("(?"):
        pattern = pattern[1:-1]
    alternatives: list[tuple[list[str], list[str]]] = []
    for alt in _top_level_split(pattern):
        if alt.startswith("^(?"):
            body, pos, neg = alt[1:], [], []
            while body:
                if not (body.startswith("(?=.*") or body.startswith("(?!.*")) or _group_end(body, 0) < 0:
                    raise NotExportable("a regular expression mixes lookaheads with other text in a way the exporter "
                                        "cannot split (RE2 engines, which Sigma backends use, have no lookahead)")
                close = _group_end(body, 0)
                (pos if body.startswith("(?=") else neg).append(body[5:close])
                body = body[close + 1:]
            if not pos:
                raise NotExportable("a regular expression only says what must be absent, which Sigma cannot express")
            alternatives.append((pos, neg))
        elif "(?=" in alt or "(?!" in alt or "(?<" in alt:
            raise NotExportable("a regular expression uses a lookaround the exporter cannot split")
        else:
            alternatives.append(([alt], []))
    return flags, alternatives


Alt = tuple[str, object, list]      # (Sigma key, value, [(key, value) that must NOT match])


def _value(field: str, op: str, expected, src: dict) -> list[Alt]:
    """One condition -> one or more alternatives (several means OR)."""
    if field == "outcome" and "outcome_ids" in src and expected in src["outcome_ids"]:
        return [("EventID", src["outcome_ids"][expected], [])]
    sigma_field = src["fields"].get(field)
    if sigma_field is None:
        raise NotExportable(f"the field '{field}' has no equivalent for this log source in Sigma")
    values = expected if isinstance(expected, list) else [expected]
    one = values if len(values) > 1 else values[0]
    if op in ("bitany", "bitall"):
        raise NotExportable("it tests single bits of a number (an access mask) and Sigma has no bit test")
    if field in src["names"] and op in ("contains", "contains_all", "startswith", "regex"):
        # The lab stores the file name; a Sigma log holds the whole path. "starts with" or "contains" would be tested
        # against the folders too (and "starts with" would never match a path), so the same test means something else.
        raise NotExportable(f"it tests the start or the middle of the program name in '{field}', but Sigma logs the "
                            "whole path, so the same test would also read the folder names")
    if op in ("equals", "in"):
        if field in src["names"] and all(isinstance(v, str) for v in values):
            return [(f"{sigma_field}|endswith", ["\\" + v for v in values] if len(values) > 1 else "\\" + values[0], [])]
        return [(sigma_field, one, [])]
    if op in ("contains", "startswith", "endswith"):
        return [(f"{sigma_field}|{op}", one, [])]
    if op == "contains_all":
        return [(f"{sigma_field}|contains|all", values, [])]
    if op == "regex":
        flags, alts = split_regex(str(expected))
        suffix = "".join("|" + c for c in flags)
        out: list[Alt] = []
        for pos, neg in alts:
            key = f"{sigma_field}|re{suffix}" + ("|all" if len(pos) > 1 else "")
            out.append((key, pos if len(pos) > 1 else pos[0], [(f"{sigma_field}|re{suffix}", n) for n in neg]))
        return out
    if op in ("gt", "gte", "lt", "lte"):
        return [(f"{sigma_field}|{op}", expected, [])]
    if op == "exists":
        return [(f"{sigma_field}|exists", bool(expected), [])]
    raise NotExportable(f"the modifier '{op}' has no equivalent in Sigma")


def _selection(branch: dict, src: dict) -> list[tuple[dict, list[dict]]]:
    """A mapping of conditions -> options (several means OR). Each option is (mapping, mappings that must not match)."""
    choices: list[list[Alt]] = []
    for key, expected in branch.items():
        field, op = parse_key(str(key))
        if field == "action" or key == "not":
            continue
        # one key naming several fields means "any of these fields"
        choices.append([alt for f in split_fields(field) for alt in _value(f, op, expected, src)])
    out = []
    for combo in itertools.product(*choices) if choices else [()]:
        sel, negs = dict(src["static"]), []
        for k, v, n in combo:
            if k == "EventID":
                sel[k] = v                      # an outcome chooses between the success and failure event ids
                continue
            if k in sel:
                raise NotExportable(f"two conditions on the same Sigma field '{k}' cannot be combined in one mapping")
            sel[k] = v
            negs.extend({nk: nv} for nk, nv in n)
        out.append((sel, negs))
    return out


def _branches(flt) -> list[dict]:
    return list(flt) if isinstance(flt, list) else [flt]


def _detection(branches: list[dict], src: dict) -> dict:
    det: dict = {}
    parts: list[str] = []
    n = 0
    for branch in branches:
        extra_neg: list[dict] = []
        if "not" in branch:
            for nb in _branches(branch["not"]):
                for nsel, nnegs in _selection(nb, src):
                    if nnegs:
                        raise NotExportable("a 'not' condition that itself contains a lookahead is not supported")
                    extra_neg.append(nsel)
        for sel, negs in _selection(branch, src):
            n += 1
            name = f"selection_{n}"
            det[name] = sel
            filters = []
            for k, neg in enumerate([*negs, *extra_neg], start=1):
                det[f"filter_{n}_{k}"] = neg
                filters.append(f"filter_{n}_{k}")
            if len(filters) > 1:
                parts.append(f"({name} and not ({' or '.join(filters)}))")
            elif filters:
                parts.append(f"({name} and not {filters[0]})")
            else:
                parts.append(name)
    det["condition"] = " or ".join(parts)
    return det


def _timespan(seconds: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _tags(rule: dict) -> list[str]:
    att = rule.get("attack", {})
    tactic = str(att.get("tactic", "")).lower().replace(" ", "-")
    tags = [f"attack.{tactic}"] if tactic else []
    for tid in [att.get("technique"), *att.get("also", [])]:
        if tid:
            tags.append("attack." + str(tid).lower())
    return tags


def _falsepositives(rule: dict) -> list[str]:
    out = [" ".join(str(rule.get("false_positives", "")).split())] if rule.get("false_positives") else []
    for ex in rule.get("exclusions", []):
        out.append("Known benign source at the lab site, not part of this export: " + " ".join(ex["reason"].split()))
    return out or ["Unknown"]


def export_rule(rule: dict) -> list[dict]:
    """The Sigma documents for one rule. Raises NotExportable with the reason when it cannot be written."""
    rtype = rule["type"]
    if rtype in NOT_EXPORTED_TYPES:
        raise NotExportable(NOT_EXPORTED_TYPES[rtype])
    if rtype in ("threshold", "distinct_threshold") and "login" in str(rule.get("filter")):
        raise NotExportable("the login event comes from different products (Entra ID, a VPN, RDP) that each need "
                            "their own Sigma log source")
    if rtype not in ("match", "distinct_threshold", "threshold"):
        raise NotExportable(f"the rule type '{rtype}' is not supported by the exporter")

    by_action: dict[str, list[dict]] = {}
    for branch in _branches(rule["filter"]):
        for action in _action_of(branch):
            if action not in SOURCES:
                raise NotExportable(f"no Sigma log source is defined for the event kind '{action}'")
            by_action.setdefault(action, []).append(branch)

    # Several actions can share one Sigma log source (for example the three group-change event ids).
    docs: list[dict] = []
    several = len(by_action) > 1
    for action, branches in by_action.items():
        src = SOURCES[action]
        base = {
            "title": rule["title"] + (f" [{action}]" if several else ""),
            "id": str(uuid.uuid5(NAMESPACE, rule["id"] + ":" + action)),
            "name": slug(rule["id"]) + (f"_{action}" if several else ""),
            "status": rule.get("status", "experimental"),
            "description": " ".join(str(rule.get("description", "")).split()),
            "author": "Detection Lab",
            "date": SIGMA_DATE,
            "tags": _tags(rule),
            "logsource": dict(src["logsource"]),
            "detection": _detection(branches, src),
            "falsepositives": _falsepositives(rule),
            "level": rule.get("severity", "medium"),
        }
        docs.append(base)

    if rtype in ("threshold", "distinct_threshold"):
        if len(docs) != 1:
            raise NotExportable("a counting rule over several event kinds cannot be written as one correlation")
        src = SOURCES[next(iter(by_action))]
        group = []
        for f in rule.get("group_by", []):
            if f not in src["fields"]:
                raise NotExportable(f"it groups by '{f}', which is computed by the engine and has no Sigma field")
            group.append(src["fields"][f])
        cond: dict = {"gte": rule["threshold"]}
        corr: dict = {"type": "event_count", "rules": [docs[0]["name"]], "group-by": group,
                      "timespan": _timespan(rule["window_seconds"]), "condition": cond}
        if rtype == "distinct_threshold":
            f = rule["distinct_field"]
            if f not in src["fields"]:
                raise NotExportable(f"it counts distinct '{f}', which has no Sigma field")
            corr["type"] = "value_count"
            cond["field"] = src["fields"][f]
        docs.append({"title": rule["title"] + " (correlation)", "id": str(uuid.uuid5(NAMESPACE, rule["id"] + ":corr")),
                     "name": slug(rule["id"]) + "_correlation", "status": rule.get("status", "experimental"),
                     "description": docs[0]["description"], "author": "Detection Lab", "date": SIGMA_DATE,
                     "tags": docs[0]["tags"], "correlation": corr, "falsepositives": docs[0]["falsepositives"],
                     "level": docs[0]["level"]})
    return docs


def export_all(rules: list[dict]) -> dict[str, dict]:
    """rule id -> {"status": "exported", "docs": [...]} or {"status": "not exported", "reason": "..."}."""
    out: dict[str, dict] = {}
    for rule in rules:
        try:
            out[rule["id"]] = {"status": "exported", "docs": export_rule(rule)}
        except NotExportable as exc:
            out[rule["id"]] = {"status": "not exported", "reason": str(exc)}
    return out


# ------------------------------------------------------------------ writing YAML without any library

_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.|\-]*$")


def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if _PLAIN.match(text) and text.lower() not in ("true", "false", "null", "yes", "no", "on", "off"):
        return text
    if any(ord(ch) < 32 or ch in "\x7f\x85\u2028\u2029" for ch in text):
        return json.dumps(text)          # a quoted YAML string folds a raw line break into a space; an escape keeps it
    return "'" + text.replace("'", "''") + "'"


def to_yaml(obj, indent: int = 0) -> str:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            k = _scalar(key)
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{pad}{k}:")
                lines.append(to_yaml(val, indent + 1))
            elif isinstance(val, (dict, list)):
                lines.append(f"{pad}{k}: {'{}' if isinstance(val, dict) else '[]'}")
            else:
                lines.append(f"{pad}{k}: {_scalar(val)}")
    else:
        for item in obj:
            if isinstance(item, dict):
                inner = to_yaml(item, indent + 1).split("\n")
                lines.append(f"{pad}- {inner[0].lstrip()}")
                lines.extend(inner[1:])
            elif isinstance(item, list):
                raise ValueError("nested lists are not used in Sigma rules")
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return "\n".join(lines)


def render_files(rules: list[dict]) -> tuple[dict[str, str], dict]:
    """The text of every DET-*.yml file (name -> text) and the export result. Nothing is written."""
    result = export_all(rules)
    files = {}
    for rid, info in result.items():
        if info["status"] == "exported":
            files[f"{rid}.yml"] = "\n---\n".join(to_yaml(d) for d in info["docs"]) + "\n"
    return files, result


def write_sigma(rules: list[dict], directory: str | Path = "sigma") -> dict:
    """Write one multi-document file per exported rule plus INDEX.md. Returns the export summary."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("DET-*.yml"):
        old.unlink()
    files, result = render_files(rules)
    for name, text in files.items():
        (out_dir / name).write_text(text, encoding="utf-8")
    exported = [r for r, i in result.items() if i["status"] == "exported"]
    write_index(rules, result, out_dir)
    return {"exported": exported, "not_exported": {r: i["reason"] for r, i in result.items()
                                                    if i["status"] != "exported"}}


def _read_manifest(directory: Path) -> dict:
    path = directory / "queries" / "MANIFEST.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"rules": {}, "tools": {}}


def render_index(rules: list[dict], result: dict, manifest: dict) -> str:
    """INDEX.md: which rules are exported, and what each backend did with them (from queries/MANIFEST.json)."""
    tools = manifest.get("tools", {})
    exported = [r for r, i in result.items() if i["status"] == "exported"]
    lines = ["# Sigma export", "",
             f"{len(exported)} of {len(result)} rules are exported as Sigma. These files are generated by "
             "`python -m detlab export-sigma`; do not edit them by hand.", "",
             "Only the detection logic is exported. Site-specific exclusions stay in `rules/` and are listed under "
             "`falsepositives` in each Sigma rule.", ""]
    if tools:
        names = {"splunk": "Splunk", "kusto": "Sentinel (KQL)"}
        lines += ["The queries in `queries/` were produced with pySigma: "
                  + "; ".join(f"{names.get(k, k)} with pySigma {v['pysigma']} and pysigma-backend-{'splunk' if k == 'splunk' else 'kusto'} {v['backend']}"
                              for k, v in sorted(tools.items()))
                  + ". The table shows what each tool did with each rule, including the conversions that failed or were "
                    "partial. None of the queries has been run against a live Splunk or Sentinel instance, so check the "
                    "field names and the table before using one.", ""]

    def cell(entry: dict, which: str) -> str:
        e = entry.get(which)
        if not e:
            return "-"
        if e["status"] != "ok":
            return "failed: " + e["error"].split("\n")[0][:110]
        return f"{e['queries']} quer{'y' if e['queries'] == 1 else 'ies'}" + (" (partial: " + "; ".join(n[:70] for n in e["notes"]) + ")" if e.get("notes") else "")

    lines += ["| Rule | Title | Sigma | Splunk | Sentinel (KQL) | Why not exported |", "|---|---|---|---|---|---|"]
    for rule in rules:
        info = result[rule["id"]]
        if info["status"] == "exported":
            entry = manifest["rules"].get(rule["id"], {})
            n = len(info["docs"])
            lines.append(f"| {rule['id']} | {rule['title']} | `{rule['id']}.yml` ({n} document{'s' if n != 1 else ''}) | "
                         f"{cell(entry, 'splunk')} | {cell(entry, 'kusto')} | |")
        else:
            lines.append(f"| {rule['id']} | {rule['title']} | not exported | - | - | {info['reason']} |")
    return "\n".join(lines) + "\n"


def write_index(rules: list[dict], result: dict, directory: str | Path = "sigma") -> None:
    out_dir = Path(directory)
    (out_dir / "INDEX.md").write_text(render_index(rules, result, _read_manifest(out_dir)), encoding="utf-8")


def check_sigma(rules: list[dict], directory: str | Path = "sigma") -> list[str]:
    """Problems that mean the sigma/ folder no longer matches the rules. An empty list means it is in sync.

    A rule can change while the Sigma file, the INDEX, or the Splunk and Sentinel queries made from it stay as they
    were. Then a reader copies a query that describes logic the lab no longer uses. This finds that: it regenerates
    every file in memory and compares, and it compares the SHA-256 hashes that tools/make_sigma_queries.py recorded.
    """
    import hashlib
    out_dir = Path(directory)
    problems: list[str] = []
    files, result = render_files(rules)
    on_disk = {p.name for p in out_dir.glob("DET-*.yml")}
    for name in sorted(set(files) | on_disk):
        path = out_dir / name
        if name not in files:
            problems.append(f"{name} should not exist: that rule is not exported (run: python -m detlab export-sigma)")
        elif name not in on_disk:
            problems.append(f"{name} is missing (run: python -m detlab export-sigma)")
        elif path.read_text(encoding="utf-8") != files[name]:
            problems.append(f"{name} no longer matches its rule (run: python -m detlab export-sigma)")
    manifest = _read_manifest(out_dir)
    index = out_dir / "INDEX.md"
    if not index.exists() or index.read_text(encoding="utf-8") != render_index(rules, result, manifest):
        problems.append("INDEX.md is out of date (run: python -m detlab export-sigma)")
    for name in sorted(files):
        rid = name[:-4]
        entry = (manifest.get("rules") or {}).get(rid)
        if not entry:
            problems.append(f"queries/MANIFEST.json has no entry for {rid}: make the SIEM queries with tools/make_sigma_queries.py")
            continue
        if entry.get("sigma_sha256") != hashlib.sha256(files[name].encode("utf-8")).hexdigest():
            problems.append(f"the Splunk and Sentinel queries for {rid} were made from an older Sigma file: "
                            "run tools/make_sigma_queries.py again")
            continue
        for key, folder, ext in (("splunk", "splunk", "spl"), ("kusto", "kql", "kql")):
            one = entry.get(key)
            if not one or one.get("status") != "ok":
                continue
            query = out_dir / "queries" / folder / f"{rid}.{ext}"
            if not query.exists():
                problems.append(f"queries/{folder}/{rid}.{ext} is missing")
            elif hashlib.sha256(query.read_bytes()).hexdigest() != one.get("sha256"):
                problems.append(f"queries/{folder}/{rid}.{ext} was edited by hand after it was made")
    for rid in sorted(set(manifest.get("rules") or {}) - {n[:-4] for n in files}):
        problems.append(f"queries/MANIFEST.json lists {rid}, which is not an exported rule")
    return problems
