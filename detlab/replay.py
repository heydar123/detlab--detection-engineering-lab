"""Replay real public attack recordings through the rules, and score the result honestly.

The synthetic lab shows that the method works. This module is the independent check: Windows event logs that
were recorded while real attack tools ran in a research lab (OTRF Security-Datasets, MIT license), kept exactly
as published and pinned to one commit.

The protocol that keeps the numbers honest:

1. ``replay/manifest.yml`` lists every dataset, its checksum, and which rules SHOULD fire (``expect``). The
   expectations come from the attack technique, not from looking at the rules' output.
2. The datasets are split in two by a fixed formula (sha256 of the file name). "dev" datasets may be looked at
   while tuning rules and exclusions. "holdout" datasets are run once, after the rules are frozen, and that first
   result is stored in ``replay/holdout-first-run.json`` (with a fingerprint of every rule's behaviour).
3. ``replay/labels.yml`` says which events are part of the recorded attack. An alert whose evidence contains one
   of them is labeled "attack"; every other alert is "other" (for example lab housekeeping).

Nothing in the data is executed. Fields are only read as text.
"""

from __future__ import annotations

import hashlib
import io
import json
import platform
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import realdata
from .engine import rule_actions, run_rules
from .matching import matches
from .models import fmt_ts
from .rules import load_rules, validate_rules, yaml

DEFAULT_DIR = "replay"
FIRST_RUN_FILE = "holdout-first-run.json"


# ------------------------------------------------------------------ files

def load_manifest(directory: str | Path = DEFAULT_DIR) -> dict:
    path = Path(directory) / "manifest.yml"
    with open(path, encoding="utf-8") as fh:
        manifest = yaml.safe_load(fh)
    problems = validate_manifest(manifest)
    if problems:
        raise ValueError("replay manifest is not valid:\n  " + "\n  ".join(problems))
    return manifest


def validate_manifest(manifest) -> list[str]:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("datasets"), list):
        return ["the manifest needs a 'datasets' list"]
    problems: list[str] = []
    seen: set[str] = set()
    for i, d in enumerate(manifest["datasets"], start=1):
        where = f"dataset #{i}"
        for key in ("id", "file", "sha256", "split", "expect", "title"):
            if key not in d:
                problems.append(f"{where}: missing '{key}'")
        if d.get("id") in seen:
            problems.append(f"{where}: duplicate id {d.get('id')}")
        seen.add(d.get("id"))
        if d.get("split") not in ("dev", "holdout"):
            problems.append(f"{where}: split must be dev or holdout")
        elif "file" in d and split_for(d["file"]) != d["split"]:
            problems.append(f"{where} ({d.get('id')}): split does not match the formula for {d['file']}")
        if not isinstance(d.get("expect"), list) or not d.get("expect"):
            problems.append(f"{where}: expect must be a non-empty list of rule ids")
    return problems


def split_for(file_name: str) -> str:
    """The fixed formula: an odd first byte of sha256(file name) means holdout."""
    return "holdout" if hashlib.sha256(file_name.encode()).digest()[0] % 2 else "dev"


def load_labels(directory: str | Path = DEFAULT_DIR) -> dict:
    path = Path(directory) / "labels.yml"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("datasets") or {}


def load_change_notes(directory: str | Path = DEFAULT_DIR) -> dict[str, str]:
    """Why each rule that changed after the first holdout run was changed (labels.yml, ``changes_after_first_run``)."""
    path = Path(directory) / "labels.yml"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return {str(k): " ".join(str(v).split()) for k, v in (data.get("changes_after_first_run") or {}).items()}


# Wording and labels do not change whether a rule fires, so they are left out of the fingerprint. That way the
# descriptions, triage steps, ATT&CK labels and generated queries can improve later without making the "frozen"
# rules look changed.
NON_BEHAVIOUR_KEYS = {"title", "description", "false_positives", "triage", "response", "queries", "tests",
                      "status", "references", "attack"}


def rule_fingerprints(rules: list[dict]) -> dict[str, str]:
    """A checksum per rule over everything that decides when it fires (filter, thresholds, exclusions...)."""
    out: dict[str, str] = {}
    for r in rules:
        core = {k: v for k, v in r.items() if k not in NON_BEHAVIOUR_KEYS and not str(k).startswith("_")}
        core["exclusions"] = [{"match": ex["match"]} for ex in r.get("exclusions", [])]
        out[r["id"]] = hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode()).hexdigest()
    return dict(sorted(out.items()))


def rules_fingerprint(rules_dir: str | Path) -> str:
    """One checksum over every rule's behaviour, so a later change to any rule is visible."""
    h = hashlib.sha256()
    for rid, digest in rule_fingerprints(load_rules(rules_dir)).items():
        h.update(f"{rid}:{digest}\n".encode())
    return h.hexdigest()


def compare_to_first_run(rules: list[dict], first_run: dict | None) -> dict | None:
    """Which rules differ from the rules that produced the stored first holdout run."""
    if not first_run:
        return None
    then = first_run.get("logic_fingerprints") or first_run.get("rule_fingerprints", {})
    now = rule_fingerprints(rules)
    changed = sorted(r for r in now if r in then and now[r] != then[r])
    added = sorted(r for r in now if r not in then)
    removed = sorted(r for r in then if r not in now)
    return {"unchanged": not (changed or added or removed), "changed": changed, "added": added,
            "removed": removed, "ran_at": first_run.get("ran_at")}


def file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ------------------------------------------------------------------ reading a dataset

def read_dataset(container: zipfile.ZipFile, entry: dict) -> list[dict]:
    """The translated events of one dataset, after checking its checksum against the manifest."""
    data = container.read(entry["file"])
    got = hashlib.sha256(data).hexdigest()
    if got != entry["sha256"]:
        raise ValueError(f"{entry['file']}: checksum {got} does not match the manifest ({entry['sha256']})")
    raw = realdata.read_raw_events(zipfile.ZipFile(io.BytesIO(data)))
    return realdata.translate(raw)


# ------------------------------------------------------------------ replaying

def _alert_row(alert, events_by_id: dict, attack_filter) -> dict:
    label = realdata.label_alert(alert, events_by_id, attack_filter)
    return {
        "alert_id": alert.alert_id, "rule_id": alert.rule_id, "title": alert.title, "severity": alert.severity,
        "tactic": alert.tactic, "technique": alert.technique, "entity": alert.entity,
        "first_ts": alert.first_ts, "last_ts": alert.last_ts, "fired_ts": alert.fired_ts,
        "events": len(alert.event_ids), "summary": alert.summary, "label": label,
    }


def replay_dataset(rules: list[dict], container: zipfile.ZipFile, entry: dict, labels: dict,
                   use_exclusions: bool = True) -> dict:
    events = read_dataset(container, entry)
    alerts = run_rules(events, rules, use_exclusions=use_exclusions)
    by_id = {e["event_id"]: e for e in events}
    attack_filter = (labels.get(entry["id"]) or {}).get("attack")
    rows = [_alert_row(a, by_id, attack_filter) for a in alerts]
    fired = sorted({r["rule_id"] for r in rows})
    expect = list(entry["expect"])
    counts = {"attack": 0, "other": 0, "unlabeled": 0}
    for r in rows:
        counts[r["label"]] += 1
    # A rule that did not fire is only a real miss when the recording has the kind of event the rule reads.
    # (A recording without PowerShell script block logs cannot test a rule that reads script blocks.)
    present = {e["action"] for e in events}
    by_id = {r["id"]: r for r in rules}
    no_data = []
    for rid in expect:
        if rid in fired:
            continue
        needs = rule_actions(by_id[rid]) if rid in by_id else None
        if needs and not (needs & present):
            no_data.append(rid)
    return {
        "id": entry["id"], "title": entry.get("title", entry["id"]), "split": entry["split"],
        "attack": entry.get("attack", []), "events": len(events), "alerts": rows,
        "expected": expect, "fired": fired,
        "hit": [r for r in expect if r in fired],
        "missed": [r for r in expect if r not in fired and r not in no_data],
        "no_data": no_data,
        "actions_present": sorted(present),
        "other_rules": [r for r in fired if r not in expect], "labels": counts,
    }


def summarize(results: list[dict]) -> dict:
    pairs = sum(len(r["expected"]) for r in results)
    hit = sum(len(r["hit"]) for r in results)
    no_data = sum(len(r["no_data"]) for r in results)
    counts = {"attack": 0, "other": 0, "unlabeled": 0}
    for r in results:
        for k in counts:
            counts[k] += r["labels"][k]
    labeled = counts["attack"] + counts["other"]
    return {
        "datasets": len(results),
        "datasets_fully_hit": sum(1 for r in results if not r["missed"] and not r["no_data"]),
        "datasets_with_any_hit": sum(1 for r in results if r["hit"]),
        "expectations": pairs, "expectations_hit": hit, "expectations_no_data": no_data,
        "expectations_missed": pairs - hit - no_data,
        "alerts": sum(len(r["alerts"]) for r in results),
        "labels": counts,
        "attack_share": (counts["attack"] / labeled) if labeled else None,
        "events": sum(r["events"] for r in results),
    }


def replay(rules: list[dict], directory: str | Path = DEFAULT_DIR, split: str = "all",
           only: str | None = None, use_exclusions: bool = True) -> dict:
    """Replay the selected datasets and return per-dataset results plus a summary."""
    directory = Path(directory)
    manifest = load_manifest(directory)
    labels = load_labels(directory)
    container_path = directory / manifest["source"]["container"]
    chosen = [d for d in manifest["datasets"]
              if (split == "all" or d["split"] == split) and (not only or d["id"] == only)]
    if not chosen:
        raise ValueError("no dataset matches that selection")
    with zipfile.ZipFile(container_path) as container:
        results = [replay_dataset(rules, container, d, labels, use_exclusions) for d in chosen]
    return {"results": results, "summary": summarize(results), "split": split}


# ------------------------------------------------------------------ the frozen first run

def freeze_holdout(rules_dir: str | Path, directory: str | Path = DEFAULT_DIR, force: bool = False) -> dict:
    """Run the holdout datasets once and store the result. Refuses to overwrite an earlier first run."""
    directory = Path(directory)
    target = directory / FIRST_RUN_FILE
    if target.exists() and not force:
        raise FileExistsError(f"{target} already exists. The first holdout run is stored once and not replaced.")
    rules = load_rules(rules_dir)
    errors = validate_rules(rules)
    if errors:
        raise ValueError("the rules are not valid:\n  " + "\n  ".join(errors))
    out = replay(rules, directory, split="holdout")
    record = {
        "what": "First run of the rules on the holdout datasets. Stored once; labels are added later, separately.",
        "ran_at": fmt_ts(datetime.now(timezone.utc).timestamp()),
        "python": platform.python_version(),
        "rules_fingerprint": rules_fingerprint(rules_dir),
        "rule_fingerprints": rule_fingerprints(rules),
        "rule_count": len(rules),
        "manifest_sha256": file_sha256(directory / "manifest.yml"),
        "summary": out["summary"],
        "datasets": [{k: r[k] for k in ("id", "title", "events", "expected", "fired", "hit", "missed", "no_data",
                                        "other_rules")}
                     | {"alerts": [{k: a[k] for k in ("rule_id", "entity", "first_ts", "last_ts", "events",
                                                      "summary")} for a in r["alerts"]]}
                     for r in out["results"]],
    }
    target.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def load_first_run(directory: str | Path = DEFAULT_DIR) -> dict | None:
    path = Path(directory) / FIRST_RUN_FILE
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _alert_key(dataset_id: str, alert: dict) -> tuple:
    return (dataset_id, alert["rule_id"], alert["first_ts"], json.dumps(alert["entity"], sort_keys=True))


def label_first_run(first_run: dict, current_results: list[dict], labels: dict) -> dict:
    """Label the alerts of the stored first holdout run.

    The first run was stored before any holdout label existed. An alert that the current rules still raise
    takes the label of that alert (same dataset, rule, first timestamp and entity). An alert that the current
    rules no longer raise needs a hand label under ``first_run_only`` in labels.yml; without one it stays
    "unlabeled" and the tests complain.
    """
    current = {_alert_key(r["id"], a): a["label"] for r in current_results for a in r["alerts"]}
    datasets, totals = [], {"attack": 0, "other": 0, "unlabeled": 0}
    for d in first_run["datasets"]:
        extra = (labels.get(d["id"]) or {}).get("first_run_only", [])
        counts = {"attack": 0, "other": 0, "unlabeled": 0}
        for a in d["alerts"]:
            label = current.get(_alert_key(d["id"], a))
            if label is None:
                label = next((x["label"] for x in extra
                              if x["rule_id"] == a["rule_id"] and x["first_ts"] == a["first_ts"]), "unlabeled")
            counts[label] += 1
        datasets.append({"id": d["id"], "alerts": len(d["alerts"]), "labels": counts})
        for k in totals:
            totals[k] += counts[k]
    labeled = totals["attack"] + totals["other"]
    return {"datasets": datasets, "labels": totals,
            "attack_share": (totals["attack"] / labeled) if labeled else None}


def attack_events_of(entry_labels: dict | None, events: list[dict]) -> list[dict]:
    """The events of a dataset that its labels call part of the attack (used by the report and the app)."""
    flt = (entry_labels or {}).get("attack")
    return [e for e in events if flt and matches(e, flt)]
