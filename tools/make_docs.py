"""Rewrite the measured parts of the documentation, so that a number in the docs cannot go stale.

    python tools/make_docs.py            write the generated files and the generated blocks
    python tools/make_docs.py --check    change nothing; name every file that is out of date and exit 1

Two kinds of generated text:

* Whole files: docs/rule-catalogue.md, docs/event-schema.md and the five sample reports in docs/.
* Blocks inside text written by hand: everything between "<!-- generated: NAME -->" and "<!-- /generated -->"
  (in README.md, docs/CASE-STUDY.md and docs/replay-results.md). Edit the words around a block freely; the block is
  rewritten from the measured results.

Every number comes from the same code the web page uses (detlab.app.Lab) and from the pinned recordings. Nothing
is typed in by hand. tests/test_docs.py runs the same code and fails when a file differs.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detlab.app import Lab                                     # noqa: E402
from detlab.report import _dur, render_case                    # noqa: E402
from detlab.rules import RULE_TYPES                            # noqa: E402
from detlab.schema import ACTIONS, COMMON_FIELDS               # noqa: E402

SEED, DAYS = 7, 14
BLOCK = re.compile(r"(?P<open><!-- generated: (?P<name>[a-z0-9-]+) -->\n)(?P<body>.*?)(?P<close><!-- /generated -->)", re.S)

TYPE_MEANING = {
    "match": "one event that matches the filter raises an alert (optionally at most one alert per entity in a pause)",
    "threshold": "N matching events for the same group inside a time window",
    "distinct_threshold": "N different values of one field (for example accounts or hosts) for the same group inside a window",
    "sum_threshold": "the sum of a number field (for example bytes sent) for the same group passes a limit inside a window",
    "beaconing": "events from one group repeat at a steady rhythm, the way a program checking in with its controller does",
    "first_seen": "a value (for example a network provider) is seen for the first time for an account, after a learning period",
    "impossible_travel": "successful sign-ins from two countries closer together in time than a person could travel",
    "fail_then_success": "enough failures, then a success, for the same group inside a window",
}


# ------------------------------------------------------------------ small helpers

def pct(x) -> str:
    return f"{x * 100:.0f}%"


def num(x: int) -> str:
    return f"{x:,}"


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c).replace("|", "/") for c in row) + " |" for row in rows]
    return "\n".join(out)


# ------------------------------------------------------------------ the measured facts

def facts(lab: Lab) -> dict:
    """Every number the documentation states, measured now. Text is used by the generated blocks and by the tests."""
    p = lab.payload()                       # built once; the blocks below read it from f["_p"]
    overall, replay = p["overall"], p["replay"]
    tuned, untuned = overall["tuned"], overall["untuned"]
    cs, rt, cov, sg, ts = p["case_summary"], p["redteam"], p["coverage"], p["sigma_summary"], p["tests_summary"]
    dev, hold, first = replay["by_split"]["dev"], replay["by_split"]["holdout"], replay["first_run"]
    summary = replay["summary"]
    ttds = [a["ttd_seconds"] for a in p["attacks"] if a["ttd_seconds"] is not None]
    slowest = max(p["attacks"], key=lambda a: a["ttd_seconds"] or 0)
    fp_rules = sorted(r["id"] for r in p["rules"] if r["stats"]["tuned"]["fp"])
    used = {e["action"] for e in lab.events}
    kql_partial = sorted(r["id"] for r in p["rules"]
                         if r.get("query_status", {}).get("kql", {}).get("status") == "ok"
                         and r["query_status"]["kql"].get("notes"))
    kql_failed = sorted(r["id"] for r in p["rules"] if r.get("query_status", {}).get("kql", {}).get("status") == "failed")
    stable = sum(1 for r in p["rules"] if r["status"] == "stable")
    levels = {int(k): v for k, v in cov["summary"]["by_level"].items()}      # keys are numbers here, text in the JSON
    top = min(p["cases"], key=lambda c: c["rank"])
    f = {
        "_p": p, "seed": p["meta"]["seed"], "days": p["meta"]["days"], "start": p["meta"]["start"],
        "events": p["meta"]["events"], "users": p["meta"]["users"], "attacks": len(p["attacks"]),
        "rules": len(p["rules"]), "rules_stable": stable, "rules_experimental": len(p["rules"]) - stable,
        "rule_tests": ts["total"], "rule_tests_passed": ts["passed"],
        "exclusions": ts["exclusions"], "exclusions_proven": ts["exclusions_proven"],
        "edits": ts["edits"], "edits_caught": ts["edits_caught"],
        "tuned_alerts": tuned["alerts"], "tuned_tp": tuned["tp"], "tuned_fp": tuned["fp"],
        "tuned_precision": tuned["precision"], "recall": tuned["recall"],
        "untuned_alerts": untuned["alerts"], "untuned_fp": untuned["fp"], "untuned_precision": untuned["precision"],
        "fp_rules": fp_rules,
        "cases": cs["cases"], "cases_attacks": cs["attacks_found"], "cases_split": cs["split"],
        "cases_merged": cs["merged"], "cases_false": cs["false_positive_cases"],
        "top_case": top["id"], "top_case_account": top["accounts"][0], "top_case_alerts": len(top["alert_ids"]),
        "ranking_ordered": p["ranking"]["pairs_ordered"], "ranking_false_ranks": p["ranking"]["false_case_ranks"],
        "redteam_caught": rt["caught"], "redteam_total": rt["total"], "redteam_open": rt["total"] - rt["caught"],
        "redteam_false": rt["false_positives"],
        "ttd_zero": sum(1 for t in ttds if t == 0), "ttd_median": median(ttds), "ttd_max": max(ttds),
        "ttd_max_id": slowest["id"], "ttd_max_name": slowest["name"],
        "replay_datasets": summary["datasets"], "replay_expectations": summary["expectations"],
        "replay_hit": summary["expectations_hit"], "replay_missed": summary["expectations_missed"],
        "replay_no_data": summary["expectations_no_data"], "replay_alerts": summary["alerts"],
        "replay_attack_alerts": summary["labels"]["attack"], "replay_other_alerts": summary["labels"]["other"],
        "replay_share": summary["attack_share"], "replay_events": summary["events"],
        "dev_datasets": dev["datasets"], "dev_expectations": dev["expectations"], "dev_hit": dev["expectations_hit"],
        "dev_missed": dev["expectations_missed"], "dev_no_data": dev["expectations_no_data"],
        "dev_alerts": dev["alerts"], "dev_attack_alerts": dev["labels"]["attack"], "dev_share": dev["attack_share"],
        "hold_datasets": hold["datasets"], "hold_expectations": hold["expectations"], "hold_hit": hold["expectations_hit"],
        "hold_missed": hold["expectations_missed"], "hold_alerts": hold["alerts"],
        "hold_attack_alerts": hold["labels"]["attack"], "hold_share": hold["attack_share"],
        "first_datasets": first["summary"]["datasets"], "first_expectations": first["summary"]["expectations"],
        "first_hit": first["summary"]["expectations_hit"], "first_missed": first["summary"]["expectations_missed"],
        "first_alerts": first["summary"]["alerts"], "first_attack_alerts": first["labeled"]["labels"]["attack"],
        "first_share": first["labeled"]["attack_share"], "first_ran_at": first["ran_at"],
        "first_changed": first["changes"]["changed"], "replay_commit": replay["source"]["commit"],
        "attack_version": cov["attack"]["version"], "attack_techniques": cov["attack"]["techniques"],
        "mapped_ids": cov["summary"]["mapped_ids"], "parents": cov["summary"]["parents"],
        "parents_with_rule": cov["summary"]["parents_with_any"],
        "level1": levels.get(1, 0), "level2": levels.get(2, 0), "level3": levels.get(3, 0),
        "sigma_exported": sg["exported"], "sigma_total": sg["total"],
        "splunk_ok": sg["queries"]["splunk"]["ok"], "kql_ok": sg["queries"]["kql"]["ok"],
        "kql_failed": sg["queries"]["kql"]["failed"], "kql_failed_rules": kql_failed, "kql_partial_rules": kql_partial,
        "actions": len(ACTIONS), "actions_used": len(used), "actions_unused": sorted(set(ACTIONS) - used),
    }
    return f


# ------------------------------------------------------------------ blocks inside text written by hand

def block_results(lab: Lab, f: dict) -> str:
    if f["fp_rules"] != ["DET-027"]:
        raise SystemExit(f"The README sentence about the remaining false positive names DET-027, but the lab now has "
                         f"false positives from {f['fp_rules']}. Rewrite that sentence in tools/make_docs.py first.")
    if f["ranking_false_ranks"] != [f["cases"]] or f["ranking_ordered"] != 1.0:
        raise SystemExit("The README says the false-alarm case ranks last by risk score, but the ranking changed "
                         f"(false-alarm ranks {f['ranking_false_ranks']}, ordered pairs {f['ranking_ordered']}). "
                         "Rewrite that sentence in tools/make_docs.py first.")
    split_text = ("no attack is split across cases and no case mixes two attacks"
                  if not (f["cases_split"] or f["cases_merged"])
                  else f"{f['cases_split']} split across cases, {f['cases_merged']} merged")
    lines = [
        "### On made-up logs",
        "",
        f"Seed {f['seed']}, {f['days']} days: {num(f['events'])} events, {f['users']} users and {f['attacks']} planted attacks, "
        "hidden in ordinary noise that includes deliberate false-alarm sources (a vulnerability scanner, a backup job, "
        "a corporate VPN, an approved administrator). The same author wrote the attacks and the rules, so these scores "
        "show that the method works. They do not predict what the rules would do on a real network.",
        "",
        table(["", "Alerts", "False positives", "Precision", "Recall"], [
            ["Every rule, no exclusions", f["untuned_alerts"], f["untuned_fp"], pct(f["untuned_precision"]), pct(f["recall"])],
            [f"With the {f['exclusions']} documented exclusions", f["tuned_alerts"], f["tuned_fp"],
             pct(f["tuned_precision"]), pct(f["recall"])],
        ]),
        "",
        f"- The {f['tuned_alerts']} alerts become {f['cases']} incident cases: the {f['cases_attacks']} attacks "
        f"({split_text}) and {plural(f['cases_false'], 'false alarm')}, which ranks last by risk score.",
        f"- Time to detect, counted from the attack's first malicious event: {f['ttd_zero']} of {f['attacks']} attacks fire "
        f"on that very event, the median is {_dur(f['ttd_median'])} and the slowest is {_dur(f['ttd_max'])} "
        f"({f['ttd_max_id']}, {f['ttd_max_name'][0].lower() + f['ttd_max_name'][1:]}).",
        f"- The {plural(f['tuned_fp'], 'false positive')} that remains comes from DET-027 (a person signing in from a "
        "network provider they have not used before). It is accepted at low severity and written down in the rule.",
        f"- Red team: {f['redteam_caught']} of {f['redteam_total']} evasion variants are caught. The {f['redteam_open']} that "
        "get through are listed, each with what would close it.",
        "",
        f"### On {f['replay_datasets']} real public attack recordings",
        "",
        f"Recordings of real attack tools (Mimikatz, PsExec, Empire, Covenant and others) from the OTRF Security-Datasets "
        f"project: {num(f['replay_events'])} Windows events. Which rules should fire was written down from each attack "
        "technique, for the holdout half before any rule was run on it. The recordings were split in two by a formula on "
        "the file name. The holdout half was run once after the rules were frozen, and that first result is stored in "
        "the repository.",
        "",
        table(["Set", "Recordings", "Expected detections that fired", "Alerts that belong to the attack"], [
            ["Development (looked at while writing rules)", f["dev_datasets"],
             f"{f['dev_hit']} of {f['dev_expectations']} ({plural(f['dev_missed'], 'miss', 'misses')}, "
             f"{f['dev_no_data']} not testable)", f"{f['dev_attack_alerts']} of {f['dev_alerts']} ({pct(f['dev_share'])})"],
            ["Holdout, first run (before any fix)", f["first_datasets"],
             f"{f['first_hit']} of {f['first_expectations']} ({plural(f['first_missed'], 'miss', 'misses')})",
             f"{f['first_attack_alerts']} of {f['first_alerts']} ({pct(f['first_share'])})"],
            [f"Holdout, now ({plural(len(f['first_changed']), 'rule')} changed after the first run, written up)",
             f["hold_datasets"], f"{f['hold_hit']} of {f['hold_expectations']} ({plural(f['hold_missed'], 'miss', 'misses')})",
             f"{f['hold_attack_alerts']} of {f['hold_alerts']} ({pct(f['hold_share'])})"],
            [f"All {f['replay_datasets']}, now", f["replay_datasets"],
             f"{f['replay_hit']} of {f['replay_expectations']} ({plural(f['replay_missed'], 'miss', 'misses')}, "
             f"{f['replay_no_data']} not testable)",
             f"{f['replay_attack_alerts']} of {f['replay_alerts']} ({pct(f['replay_share'])})"],
        ]),
        "",
        "The full protocol, every recording, and every miss are in [docs/replay-results.md](docs/replay-results.md).",
        "",
        "### About the rules themselves",
        "",
        table(["Check", "Result"], [
            ["Unit tests written inside the rule files", f"{f['rule_tests_passed']} of {f['rule_tests']} pass"],
            ["Exclusions that a test proves are needed (the test fails without the exclusion)",
             f"{f['exclusions_proven']} of {f['exclusions']}"],
            ["Small edits to a rule that some test notices (a condition deleted, a number moved by one, ...)",
             f"{f['edits_caught']} of {f['edits']}"],
            ["Rules that can be exported as Sigma",
             f"{f['sigma_exported']} of {f['sigma_total']} (the others need logic Sigma cannot express; each reason is in "
             "[sigma/INDEX.md](sigma/INDEX.md))"],
            ["Sigma files converted to queries", f"Splunk {f['splunk_ok']} of {f['sigma_exported']}; Microsoft Sentinel (KQL) "
             f"{f['kql_ok']} of {f['sigma_exported']}, {len(f['kql_partial_rules'])} of those only in part. "
             "None was run on a live SIEM"],
            [f"ATT&CK v{f['attack_version']} parent techniques with at least one rule",
             f"{f['parents_with_rule']} of {f['parents']} ({pct(f['parents_with_rule'] / f['parents'])}); "
             f"{f['mapped_ids']} technique IDs mapped, {f['level3']} of them seen in a real recording"],
        ]),
        "",
    ]
    return "\n".join(lines)


def block_replay_summary(lab: Lab, f: dict) -> str:
    return "\n".join([
        table(["Set", "Recordings", "Expected detections", "Fired", "Missed", "Not testable", "Alerts", "Part of the attack"], [
            ["Development", f["dev_datasets"], f["dev_expectations"], f["dev_hit"], f["dev_missed"], f["dev_no_data"],
             f["dev_alerts"], f"{f['dev_attack_alerts']} ({pct(f['dev_share'])})"],
            ["Holdout, first run", f["first_datasets"], f["first_expectations"], f["first_hit"], f["first_missed"], 0,
             f["first_alerts"], f"{f['first_attack_alerts']} ({pct(f['first_share'])})"],
            ["Holdout, now", f["hold_datasets"], f["hold_expectations"], f["hold_hit"], f["hold_missed"], 0,
             f["hold_alerts"], f"{f['hold_attack_alerts']} ({pct(f['hold_share'])})"],
            ["All, now", f["replay_datasets"], f["replay_expectations"], f["replay_hit"], f["replay_missed"],
             f["replay_no_data"], f["replay_alerts"], f"{f['replay_attack_alerts']} ({pct(f['replay_share'])})"],
        ]),
        "",
        f"The holdout first run was stored on {f['first_ran_at']} in `replay/holdout-first-run.json`. "
        f"The recordings are pinned to commit `{f['replay_commit']}` of the OTRF Security-Datasets repository.",
        "",
    ])


def block_replay_datasets(lab: Lab, f: dict) -> str:
    rows = []
    for ds in sorted(f["_p"]["replay"]["datasets"], key=lambda d: (d["split"], d["id"])):
        parts = []
        if ds["hit"]:
            parts.append("fired: " + ", ".join(ds["hit"]))
        if ds["missed"]:
            parts.append("MISSED: " + ", ".join(ds["missed"]))
        if ds["no_data"]:
            parts.append("not testable: " + ", ".join(ds["no_data"]))
        result = "; ".join(parts) or "no expectation"
        rows.append([f"`{ds['id']}`", ds["split"], num(ds["events"]), ", ".join(ds["expected"]) or "-", result,
                     f"{ds['labels']['attack']} / {ds['labels']['other']}"])
    return table(["Recording", "Set", "Events", "Expected", "Result", "Alerts: attack / other"], rows) + "\n\n"


def block_replay_misses(lab: Lab, f: dict) -> str:
    out = []
    for ds in sorted(f["_p"]["replay"]["datasets"], key=lambda d: d["id"]):
        for rid in ds["missed"] + ds["no_data"]:
            note = ds["notes"].get(rid, "").strip()           # each note starts by saying "Missed" or "Not testable"
            out.append(f"- **{rid} on `{ds['id']}` ({ds['split']}).** {note}")
    return "\n".join(out) + "\n\n"


def block_replay_changes(lab: Lab, f: dict) -> str:
    first = f["_p"]["replay"]["first_run"]
    out = []
    for rid in first["changes"]["changed"]:
        out.append(f"- **{rid}.** {first['change_notes'][rid]}")
    return "\n".join(out) + "\n\n"


def block_time_to_detect(lab: Lab, f: dict) -> str:
    rows = []
    for a in f["_p"]["attacks"]:
        rows.append([a["id"], a["name"], a["first_rule"] or "-", _dur(a["ttd_seconds"])])
    return table(["Attack", "What it is", "First rule to fire", "Time to detect"], rows) + "\n\n"


BLOCKS = {
    "README.md": {"results": block_results},
    "docs/CASE-STUDY.md": {"time-to-detect": block_time_to_detect},
    "docs/replay-results.md": {"summary": block_replay_summary, "recordings": block_replay_datasets,
                               "misses": block_replay_misses, "changes": block_replay_changes},
}


# ------------------------------------------------------------------ whole files

def whole_catalogue(lab: Lab, f: dict) -> str:
    p = f["_p"]
    per_rule: dict[str, dict] = {}
    for ds in p["replay"]["datasets"]:
        for rid in ds["expected"]:
            entry = per_rule.setdefault(rid, {"expected": 0, "hit": 0, "no_data": 0, "alerts": 0, "attack": 0})
            entry["expected"] += 1
            entry["hit"] += rid in ds["hit"]
            entry["no_data"] += rid in ds["no_data"]
        for alert in ds["alerts"]:
            entry = per_rule.setdefault(alert["rule_id"], {"expected": 0, "hit": 0, "no_data": 0, "alerts": 0, "attack": 0})
            entry["alerts"] += 1
            entry["attack"] += alert["label"] == "attack"

    rows = []
    for r in p["rules"]:
        made = r["stats"]
        real = per_rule.get(r["id"], {"expected": 0, "hit": 0, "no_data": 0, "alerts": 0, "attack": 0})
        if real["expected"]:
            untestable = f" ({real['no_data']} not testable)" if real["no_data"] else ""
            on_real = (f"hit {real['hit']} of {real['expected']}{untestable}; "
                       f"{plural(real['alerts'], 'alert')} ({real['attack']} attack)")
        elif real["alerts"]:
            on_real = f"no expectation; {plural(real['alerts'], 'alert')} ({real['attack']} attack)"
        else:
            on_real = "-"
        qs = r.get("query_status") or {}
        if r["sigma"]["status"] != "exported":
            sigma = "not exported"
        else:
            kql = qs.get("kql", {})
            sigma = "Sigma, Splunk" + {"failed": " (Sentinel failed)", "ok": ", Sentinel" + (" (partial)" if kql.get("notes") else "")
                                        }.get(kql.get("status"), "")
        rows.append([f"[{r['id']}](../rules/{r['id']}.yml)", r["title"], r["severity"], r["status"],
                     f"{r['technique']} {r['technique_name']}", r["type"], len(r["tests"]),
                     f"{made['untuned']['alerts']} to {made['tuned']['alerts']} "
                     f"({made['untuned']['fp']} to {made['tuned']['fp']} false)", on_real, sigma])
    types = [[f"`{t}`", TYPE_MEANING[t], sum(1 for r in p["rules"] if r["type"] == t)] for t in RULE_TYPES]
    return "\n".join([
        "# Rule catalogue",
        "",
        f"All {f['rules']} detection rules, one row per file in [`rules/`](../rules/). This page is generated by "
        "`python tools/make_docs.py` from the rule files and the lab's measured results. Do not edit it by hand.",
        "",
        "- **Status.** The first eight rules are `stable`: they went through the most rounds of testing and tuning. "
        f"The other {f['rules_experimental']} are `experimental`: newer, with less time against noise.",
        "- **Made-up logs.** Alerts on the synthetic logs (seed 7, 14 days) without exclusions, then with them, and how many "
        "of those alerts were false alarms.",
        "- **Real recordings.** How many recordings expected this rule and how many it fired on, and how many alerts it "
        "raised on all the recordings (and how many of those belong to the recorded attack).",
        "- **Sigma.** Whether the rule's logic could be exported to Sigma and converted to Splunk and Microsoft Sentinel "
        "queries. Nothing was run on a live SIEM; see [sigma/INDEX.md](../sigma/INDEX.md).",
        "",
        table(["Rule", "Detects", "Severity", "Status", "ATT&CK", "Type", "Tests", "Made-up logs: alerts", "Real recordings",
               "Sigma"], rows),
        "",
        "## Rule types",
        "",
        table(["Type", "Fires when", "Rules"], types),
        "",
    ])


def whole_event_schema(lab: Lab, f: dict) -> str:
    out = [
        "# Event schema",
        "",
        "Rules never read vendor field names. Every log, from the made-up generator or from a real Windows recording, is "
        "first translated into one small shared vocabulary, and the rule files use only those names. It is the same idea "
        "as Elastic's ECS or Sigma's field mappings, in miniature, and it is why one rule file runs unchanged on both "
        "kinds of data.",
        "",
        "This page is generated from `detlab/schema.py` by `python tools/make_docs.py`, so it lists exactly what the code "
        "accepts. The validator rejects a rule that uses a field name that is not listed here, and suggests the closest "
        "one.",
        "",
        "## Fields any event can have",
        "",
        table(["Field", "Meaning"], [[f"`{k}`", v] for k, v in COMMON_FIELDS.items()]),
        "",
        f"## The {f['actions']} kinds of event",
        "",
        f"The made-up logs use {f['actions_used']} of them."
        + ((" The other one (" if len(f["actions_unused"]) == 1 else " The others (")
           + ", ".join(f"`{a}`" for a in f["actions_unused"])
           + (") appears" if len(f["actions_unused"]) == 1 else ") appear")
           + " only in the real recordings and in rule tests." if f["actions_unused"] else ""),
        "",
    ]
    for name, spec in ACTIONS.items():
        out += [f"### `{name}`", "", f"{spec['about']} Windows source: {spec['windows']}", "",
                table(["Field", "Meaning"], [[f"`{k}`", v] for k, v in spec["fields"].items()]), ""]
    out += [
        "## How a real recording becomes these events",
        "",
        "`detlab/realdata.py` reads a recording (Windows event logs as JSON lines), looks at the Windows event ID, and "
        "writes one event of the matching kind above with the matching field names. Sysmon event 1 becomes "
        "`process_create`, Security 4698 becomes `scheduled_task_create`, and so on; the table above names the Windows "
        "source of each kind. A recorded event that has no kind in this list is skipped. Nothing in a recording is ever "
        "executed: fields are only read as text.",
        "",
    ]
    return "\n".join(out)


def whole_samples(lab: Lab, f: dict) -> dict[str, str]:
    top = next(c for c in f["_p"]["cases"] if c["id"] == f["top_case"])
    return {
        "docs/sample-detection-report.md": lab.report("detection_report.md"),
        "docs/sample-evasion-report.md": lab.report("evasion_report.md"),
        "docs/sample-case-report.md": lab.case_report(top["id"]),
        "docs/sample-incident-report.md": render_case(top["accounts"][0], lab.events, lab.tuned_alerts, lab.rules),
    }


# ------------------------------------------------------------------ putting it together

def render_all(lab: Lab, root: Path = ROOT) -> dict[str, str]:
    """The finished text of every generated file, keyed by its path inside the repository."""
    f = facts(lab)
    out = {"docs/rule-catalogue.md": whole_catalogue(lab, f), "docs/event-schema.md": whole_event_schema(lab, f)}
    out.update(whole_samples(lab, f))
    for path, blocks in BLOCKS.items():
        text = read(root / path)
        found = {m.group("name") for m in BLOCK.finditer(text)}
        if found != set(blocks):
            raise SystemExit(f"{path} has the generated blocks {sorted(found)} but the generator makes {sorted(blocks)}. "
                             "Add the missing '<!-- generated: NAME -->' ... '<!-- /generated -->' pair, or remove the extra one.")
        out[path] = BLOCK.sub(lambda m: m.group("open") + blocks[m.group("name")](lab, f) + m.group("close"), text)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="change nothing; exit 1 if a document is out of date")
    args = parser.parse_args(argv)

    lab = Lab(ROOT / "rules", SEED, DAYS)
    wanted = render_all(lab)
    stale = [path for path, text in wanted.items()
             if not (ROOT / path).exists() or read(ROOT / path) != text]
    if args.check:
        if stale:
            print("These documents are out of date:\n  " + "\n  ".join(stale) + "\nRun: python tools/make_docs.py")
            return 1
        print(f"OK: {len(wanted)} generated documents are up to date")
        return 0
    for path in stale:
        target = ROOT / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(wanted[path])
    print(f"Rewrote {len(stale)} of {len(wanted)} generated documents" + (":\n  " + "\n  ".join(stale) if stale else "."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
