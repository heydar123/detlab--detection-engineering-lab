"""The Detection Lab web app: a small local server plus a browser interface.

It runs on your own computer only (127.0.0.1) and needs nothing beyond Python itself.

Safety, because this is a security project:
  - the server listens on 127.0.0.1 only, never on the network;
  - every request must carry a random token that only the page it served knows, and a Host header
    that matches the local address (this blocks other websites and DNS-rebinding tricks);
  - it never writes files and only reads the rules folder;
  - the page escapes everything it shows, so text inside logs cannot run as code.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import replay as replay_mod
from . import sigma as sigma_mod
from .cases import (ACCOUNT_POINTS, ASSET_POINTS, BREADTH_POINTS, CASE_WINDOW_SECONDS, CRITICAL_HOST_PREFIXES,
                    PRIVILEGED_ACCOUNT_PREFIXES, RISK_LEVELS, SEVERITY_POINTS, build_cases, evaluate_cases,
                    evaluate_ranking, rank_cases, risk)
from .coverage import compute as compute_coverage
from .engine import run_rules
from .evaluate import evaluate
from .evasion import run_evasion
from .generate import MIN_DAYS, generate
from .models import fmt_ts, parse_ts, prepare_events
from .report import render_evasion_report, render_report, render_untuned_fp_table
from .rules import load_rules, parse_rule_text, validate_rule, validate_rules
from .timeline import build_timeline
from .unit_tests import exclusion_checks, mutation_checks, run_rule_tests

WEB_DIR = Path(__file__).resolve().parent / "web"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 64 * 1024
MAX_RULE_CHARS = 20_000
MAX_SEED = 1_000_000
MAX_DAYS = 30
EVIDENCE_LIMIT = 60


class BadRequest(Exception):
    """The request was wrong in a way the person can fix; the message is shown to them."""


# ------------------------------------------------------------------------------ the lab

class Lab:
    """Everything the page shows, computed from one seed and one set of rules."""

    def __init__(self, rules_dir, seed: int = 7, days: int = MIN_DAYS, with_replay: bool = True):
        self.rules_dir = Path(rules_dir)
        self.root = self.rules_dir.resolve().parent          # the project folder: rules/, sigma/, replay/ live in it
        self.rules = load_rules(self.rules_dir)
        errors = validate_rules(self.rules)
        if errors:
            raise ValueError("The rules are not valid:\n  " + "\n  ".join(errors))
        self.raw = {r["id"]: (self.rules_dir / r["_file"]).read_text(encoding="utf-8") for r in self.rules}
        self.rule_tests = run_rule_tests(self.rules)
        self.exclusion_proofs = exclusion_checks(self.rules)
        self.mutation_proofs = mutation_checks(self.rules)
        self.sigma = sigma_mod.export_all(self.rules)
        self.query_manifest = self._load_query_manifest()
        self.replay = self._replay() if with_replay else None
        self.run(seed, days)

    # -------------------------------------------------------------------- computing
    def run(self, seed: int, days: int) -> None:
        self.seed, self.days = seed, days
        events, truth = generate(seed, days)
        self.events = prepare_events(events)
        self.truth = truth
        self.by_id = {e["event_id"]: e for e in self.events}

        self.tuned_alerts = run_rules(self.events, self.rules, use_exclusions=True)
        self.untuned_alerts = run_rules(self.events, self.rules, use_exclusions=False)
        for alert in self.untuned_alerts:          # keep the two lists' IDs apart: A-0001 vs U-0001
            alert.alert_id = "U-" + alert.alert_id[2:]
        self.tuned = evaluate(self.tuned_alerts, truth, self.rules)
        self.untuned = evaluate(self.untuned_alerts, truth, self.rules)

        self.cases = build_cases(self.tuned_alerts)
        self.case_eval = evaluate_cases(self.cases, truth)
        self.ranking = evaluate_ranking(self.cases, self.case_eval)
        self.ranked = {c.case_id: (n, r) for n, (c, r) in enumerate(rank_cases(self.cases), start=1)}
        self.evasion = run_evasion(self.rules, seed, days)
        self.alert_index = {a.alert_id: a for a in self.tuned_alerts + self.untuned_alerts}
        lab_rules = {rid for rid, row in self.tuned["per_rule"].items() if row["tp"] > 0}
        real_rules = {rid for d in (self.replay or {}).get("datasets", []) for rid in d["hit"]}
        self.coverage = compute_coverage(self.rules, lab_rules, real_rules)

    # -------------------------------------------------------------------- real recordings
    def _replay(self) -> dict | None:
        """Replay the public attack recordings (replay/) through the current rules. None when the folder is absent."""
        directory = self.root / "replay"
        if not (directory / "manifest.yml").exists():
            return None
        manifest = replay_mod.load_manifest(directory)
        labels = replay_mod.load_labels(directory)
        out = replay_mod.replay(self.rules, directory, split="all")
        titles = {r["id"]: r["title"] for r in self.rules}
        datasets = []
        for r in sorted(out["results"], key=lambda r: (r["split"], r["id"])):
            entry = next(d for d in manifest["datasets"] if d["id"] == r["id"])
            datasets.append({
                "id": r["id"], "title": r["title"], "split": r["split"], "events": r["events"],
                "expected": r["expected"], "hit": r["hit"], "missed": r["missed"], "no_data": r["no_data"],
                "other_rules": r["other_rules"], "labels": r["labels"], "attack": entry.get("attack", []),
                "why": " ".join(str((labels.get(r["id"]) or {}).get("why", "")).split()),
                "notes": {rid: " ".join(str(text).split())
                          for rid, text in ((labels.get(r["id"]) or {}).get("result_notes") or {}).items()},
                "alerts": [{"rule_id": a["rule_id"], "rule_title": titles.get(a["rule_id"], a["rule_id"]),
                            "severity": a["severity"], "first_ts": a["first_ts"], "summary": a["summary"],
                            "events": a["events"], "label": a["label"]} for a in r["alerts"]],
            })
        by_split = {sp: replay_mod.summarize([r for r in out["results"] if r["split"] == sp]) for sp in ("dev", "holdout")}
        first = replay_mod.load_first_run(directory)
        first_view = None
        if first:
            holdout = [r for r in out["results"] if r["split"] == "holdout"]
            first_view = {
                "ran_at": first["ran_at"], "summary": first["summary"],
                "addenda": [{"added": a.get("added", ""), "what": " ".join(str(a.get("what", "")).split())}
                            for a in first.get("addenda", [])],
                "labeled": replay_mod.label_first_run(first, holdout, labels),
                "changes": replay_mod.compare_to_first_run(self.rules, first),
                "change_notes": replay_mod.load_change_notes(directory),
                "datasets": [{"id": d["id"], "expected": d["expected"], "hit": d["hit"], "missed": d["missed"],
                              "alerts": len(d["alerts"])} for d in first["datasets"]],
            }
        source = {k: v for k, v in manifest.get("source", {}).items() if k != "container"}
        return {"source": source, "summary": out["summary"], "by_split": by_split, "datasets": datasets,
                "first_run": first_view}

    # -------------------------------------------------------------------- views
    @staticmethod
    def _stats(result: dict, rule_id: str) -> dict:
        row = result["per_rule"][rule_id]
        return {k: row[k] for k in ("alerts", "tp", "fp", "precision", "recall", "expected", "detected")}

    def _alert_view(self, alert, result: dict, case_of: dict | None = None) -> dict:
        verdict = result["verdicts"][alert.alert_id]
        return {
            "id": alert.alert_id, "rule_id": alert.rule_id, "title": alert.title, "severity": alert.severity,
            "tactic": alert.tactic, "technique": alert.technique, "entity": alert.entity,
            "first_ts": alert.first_ts, "fired_ts": alert.fired_ts, "fired_t": alert.fired_t,
            "summary": alert.summary, "events": len(alert.event_ids),
            "verdict": verdict["verdict"], "attacks": verdict["scenarios"],
            "case_id": (case_of or {}).get(alert.alert_id),
        }

    def payload(self) -> dict:
        case_of = {a.alert_id: c.case_id for c in self.cases for a in c.alerts}
        t0 = parse_ts(self.truth["meta"]["start"] + "T00:00:00Z")
        rules = []
        for r in self.rules:
            rules.append({
                "id": r["id"], "title": r["title"], "severity": r["severity"], "status": r["status"],
                "tactic": r["attack"]["tactic"], "technique": r["attack"]["technique"],
                "technique_name": r["attack"]["technique_name"], "type": r["type"],
                "description": " ".join(str(r["description"]).split()),
                "false_positives": " ".join(str(r.get("false_positives", "")).split()),
                "exclusions": [{"match": ex["match"], "reason": ex["reason"]} for ex in r.get("exclusions") or []],
                "triage": r["triage"], "response": r["response"],
                "queries": self._queries(r["id"]),
                "query_status": self._query_status(r["id"]),
                "sigma": self._sigma(r["id"]),
                "tests": [{"name": t["name"], "expect": t["expect"], "passed": t["passed"], "message": t["message"]}
                          for t in self.rule_tests if t["rule"] == r["id"]],
                "exclusion_proofs": [{"index": x["index"], "exercised": x["exercised"]}
                                     for x in self.exclusion_proofs if x["rule"] == r["id"]],
                "attack_ids": [r["attack"]["technique"], *r["attack"].get("also", [])],
                "yaml": self.raw[r["id"]],
                "stats": {"tuned": self._stats(self.tuned, r["id"]), "untuned": self._stats(self.untuned, r["id"])},
            })
        attacks = []
        for sc, res in self.tuned["scenarios"].items():
            planted = self.truth["scenarios"][sc]
            times = [self.by_id[e]["_t"] for e in planted["event_ids"] if e in self.by_id]
            attacks.append({
                "id": sc, "name": res["name"], "description": planted["description"],
                "expected": res["expected"], "detected": res["detected"], "missed": res["missed"],
                "caught": res["caught"], "first_rule": res["first_rule"], "ttd_seconds": res["ttd_seconds"],
                "first_alert_ts": res["first_alert_ts"],
                "start": min(times) if times else None, "end": max(times) if times else None,
            })
        cases = []
        for c in self.cases:
            cases.append({
                "id": c.case_id, "title": c.title, "severity": c.severity, "tactics": c.tactics,
                "multi_stage": c.kill_chain, "rules": c.rules,
                "alert_ids": [a.alert_id for a in sorted(c.alerts, key=lambda a: (a.first_t, a.fired_t))],
                "first_ts": fmt_ts(c.first_t), "last_ts": fmt_ts(c.last_t),
                "attacks": self.case_eval["case_scenarios"][c.case_id],
                "accounts": c.values("account"), "ips": c.values("ip"), "hosts": c.values("host"),
                "rank": self.ranked[c.case_id][0], "risk": self.ranked[c.case_id][1],
            })
        return {
            "meta": {**self.truth["meta"], "seed": self.seed, "days": self.days,
                     "limits": {"min_days": MIN_DAYS, "max_days": MAX_DAYS, "max_seed": MAX_SEED}},
            "timeline": {"start": t0, "end": t0 + self.days * 86400},
            "rules": rules,
            "overall": {"tuned": self.tuned["overall"], "untuned": self.untuned["overall"]},
            "alerts": {
                "tuned": [self._alert_view(a, self.tuned, case_of) for a in self.tuned_alerts],
                "untuned": [self._alert_view(a, self.untuned) for a in self.untuned_alerts],
            },
            "attacks": attacks,
            "cases": cases,
            "case_summary": {
                "alerts": self.case_eval["alerts"], "cases": self.case_eval["cases"],
                "attacks_found": self.case_eval["scenarios_found"],
                "split": len(self.case_eval["split_scenarios"]), "merged": len(self.case_eval["merged_cases"]),
                "false_positive_cases": len(self.case_eval["false_positive_cases"]),
            },
            "redteam": {
                "caught": self.evasion["caught"], "total": self.evasion["total"],
                "false_positives": self.evasion["false_positives"], "rows": self.evasion["rows"],
            },
            "ranking": self.ranking,
            "risk_method": {
                "severity_points": SEVERITY_POINTS, "breadth_points": BREADTH_POINTS, "asset_points": ASSET_POINTS,
                "account_points": ACCOUNT_POINTS, "levels": [[floor, name] for floor, name in RISK_LEVELS],
                "critical_hosts": list(CRITICAL_HOST_PREFIXES), "privileged_accounts": list(PRIVILEGED_ACCOUNT_PREFIXES),
                "window_hours": CASE_WINDOW_SECONDS // 3600,
            },
            "coverage": self.coverage,
            "replay": self.replay,
            "sigma_summary": {
                "exported": sum(1 for v in self.sigma.values() if v["status"] == "exported"),
                "total": len(self.sigma),
                "not_exported": {k: v["reason"] for k, v in self.sigma.items() if v["status"] != "exported"},
                "tools": self.query_manifest.get("tools", {}),
                "queries": self._query_counts(),
            },
            "tests_summary": {
                "total": len(self.rule_tests), "passed": sum(1 for t in self.rule_tests if t["passed"]),
                "exclusions": len(self.exclusion_proofs),
                "exclusions_proven": sum(1 for x in self.exclusion_proofs if x["exercised"]),
                "edits": len(self.mutation_proofs),
                "edits_caught": sum(1 for x in self.mutation_proofs if x["caught"]),
            },
        }

    def _load_query_manifest(self) -> dict:
        path = self.root / "sigma" / "queries" / "MANIFEST.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"rules": {}, "tools": {}}
        return data if isinstance(data, dict) else {"rules": {}, "tools": {}}

    def _query_status(self, rule_id: str) -> dict:
        """How each SIEM language came out for one rule: ok or failed, plus the converter's notes."""
        entry = (self.query_manifest.get("rules") or {}).get(rule_id, {})
        out = {}
        for kind, key in (("splunk", "splunk"), ("kql", "kusto")):
            if key not in entry:
                continue
            one = entry[key]
            out[kind] = {"status": one.get("status", "failed"),
                         "notes": [" ".join(str(n).split())[:240] for n in one.get("notes", [])],
                         "error": " ".join(str(one.get("error", "")).split())[:240]}
        return out

    def _query_counts(self) -> dict:
        counts = {"splunk": {"ok": 0, "failed": 0}, "kql": {"ok": 0, "failed": 0}}
        for rid in self.sigma:
            for kind, one in self._query_status(rid).items():
                counts[kind]["ok" if one["status"] == "ok" else "failed"] += 1
        return counts

    def _queries(self, rule_id: str) -> dict:
        found = {}
        for kind, folder, ext in (("splunk", "splunk", "spl"), ("kql", "kql", "kql")):
            path = self.root / "sigma" / "queries" / folder / f"{rule_id}.{ext}"
            if path.exists():
                found[kind] = path.read_text(encoding="utf-8")
        return found

    def _sigma(self, rule_id: str) -> dict:
        info = self.sigma[rule_id]
        if info["status"] != "exported":
            return {"status": "not exported", "reason": info["reason"], "yaml": ""}
        return {"status": "exported", "reason": "",
                "yaml": "\n---\n".join(sigma_mod.to_yaml(d) for d in info["docs"]) + "\n"}

    def alert_detail(self, alert_id: str) -> dict:
        alert = self.alert_index.get(alert_id)
        if alert is None:
            raise KeyError(alert_id)
        tuned = alert_id.startswith("A-")
        result = self.tuned if tuned else self.untuned
        case_of = {a.alert_id: c.case_id for c in self.cases for a in c.alerts} if tuned else {}
        rule = next(r for r in self.rules if r["id"] == alert.rule_id)
        shown = [{k: v for k, v in self.by_id[e].items() if not k.startswith("_")}
                 for e in alert.event_ids[:EVIDENCE_LIMIT]]
        return {"alert": self._alert_view(alert, result, case_of), "events": shown,
                "total_events": len(alert.event_ids), "triage": rule["triage"], "response": rule["response"]}

    def case_detail(self, case_id: str) -> dict:
        case = next((c for c in self.cases if c.case_id == case_id), None)
        if case is None:
            raise KeyError(case_id)
        accounts, ips, hosts = set(case.values("account")), set(case.values("ip")), set(case.values("host"))
        cited: dict[str, list[str]] = defaultdict(list)
        for a in case.alerts:
            for eid in a.event_ids:
                cited[eid].append(a.alert_id)
        lo, hi = case.first_t - 1800, case.last_t + 1800
        window = [e for e in self.events if lo <= e["_t"] <= hi and (
            e.get("user") in accounts or e.get("target_user") in accounts
            or e.get("src_ip") in ips or e.get("host") in hosts)]

        rows = build_timeline(window, cited)

        by_rule = {r["id"]: r for r in self.rules}
        order: list[str] = []
        for a in sorted(case.alerts, key=lambda a: (a.first_t, a.fired_t)):
            if a.rule_id not in order:
                order.append(a.rule_id)
        return {
            "id": case.case_id, "title": case.title, "severity": case.severity, "tactics": case.tactics,
            "multi_stage": case.kill_chain, "timeline": rows,
            "rank": self.ranked[case.case_id][0], "risk": self.ranked[case.case_id][1],
            "alerts": [self._alert_view(a, self.tuned) for a in sorted(case.alerts, key=lambda a: (a.first_t, a.fired_t))],
            "triage": [{"rule_id": rid, "steps": by_rule[rid]["triage"]} for rid in order],
            "response": [{"rule_id": rid, "steps": by_rule[rid]["response"]} for rid in order],
        }

    def report(self, name: str) -> str:
        if name == "detection_report.md":
            text = render_report(self.rules, self.tuned_alerts, self.truth, self.tuned, self.untuned,
                                 cases=self.cases, case_eval=self.case_eval)
            return text + "\n## False positives before tuning\n\n" + render_untuned_fp_table(
                self.untuned_alerts, self.untuned) + "\n"
        if name == "evasion_report.md":
            return render_evasion_report(self.evasion)
        raise KeyError(name)

    def case_report(self, case_id: str) -> str:
        """A hand-over note for one case in Markdown: risk, what happened, what to check, what to do."""
        d = self.case_detail(case_id)
        case = next(c for c in self.cases if c.case_id == case_id)
        techniques = sorted({a.technique for a in case.alerts})
        lines = [f"# {d['id']}: {d['title']}", "",
                 f"Risk {d['risk']['score']} ({d['risk']['level']}), rank {d['rank']} of {len(self.cases)} cases. "
                 f"Highest alert severity: {d['severity']}. Window: {fmt_ts(case.first_t)} to {fmt_ts(case.last_t)}.", "",
                 "## Why this risk score", ""]
        lines += [f"- {f['points']} points: {f['label']}" for f in d["risk"]["factors"]]
        lines += ["", "## ATT&CK", "", f"Tactics in the order they started: {', '.join(d['tactics'])}.",
                  f"Techniques: {', '.join(techniques)}.", "", "## Alerts", "",
                  "| Alert | Time (UTC) | Rule | Severity | Summary |", "|---|---|---|---|---|"]
        for a in d["alerts"]:
            lines.append(f"| {a['id']} | {a['first_ts']} | {a['rule_id']} {a['title']} | {a['severity']} | "
                         f"{a['summary'].replace('|', '/')} |")
        lines += ["", "## Timeline", ""]
        for row in d["timeline"][:60]:
            tag = f" [{', '.join(row['alerts'])}]" if row["alerts"] else ""
            lines.append(f"- {row['ts']} {row['text']}{tag}")
            if row.get("note"):
                lines.append(f"  - {row['note']}")
            if row.get("detail"):
                lines.append(f"  - `{row['detail']}`")
        lines += ["", "## What to check", ""]
        for block in d["triage"]:
            lines += [f"**{block['rule_id']}**", ""] + [f"- {step}" for step in block["steps"]] + [""]
        lines += ["## What to do", ""]
        for block in d["response"]:
            lines += [f"**{block['rule_id']}**", ""] + [f"- {step}" for step in block["steps"]] + [""]
        lines += ["---", "Generated by Detection Lab from synthetic data. Nothing in this note describes a real incident."]
        return "\n".join(lines) + "\n"

    def snapshot(self) -> dict:
        """Everything the page can ask for, in one object, for the static copy of the site."""
        limit = 25
        details = {}
        for aid in self.alert_index:
            d = self.alert_detail(aid)
            d["events"] = d["events"][:limit]
            details[aid] = d
        return {
            "payload": self.payload(),
            "alerts": details,
            "cases": {c.case_id: self.case_detail(c.case_id) for c in self.cases},
            "reports": {"detection_report.md": self.report("detection_report.md"),
                        "evasion_report.md": self.report("evasion_report.md"),
                        **{f"{c.case_id}.md": self.case_report(c.case_id) for c in self.cases}},
        }

    # -------------------------------------------------------------------- the playground
    def test_rule(self, rule_id: str, text: str) -> dict:
        """Try an edited rule against the same logs and the red-team attacks. Nothing is saved."""
        if rule_id not in self.raw:
            raise BadRequest("That rule does not exist.")
        if len(text) > MAX_RULE_CHARS:
            raise BadRequest(f"The rule text is too long (the limit is {MAX_RULE_CHARS:,} characters).")
        try:
            rule = parse_rule_text(text, f"{rule_id}.yml")
        except ValueError as exc:
            return {"ok": False, "errors": [str(exc)]}
        errors = validate_rule(rule)
        if rule.get("id") != rule_id:
            errors.append(f"The id must stay {rule_id}. Change the other lines, not the id.")
        if errors:
            return {"ok": False, "errors": errors}

        try:
            rules = [rule if r["id"] == rule_id else r for r in self.rules]
            alerts = run_rules(self.events, rules)
            after = evaluate(alerts, self.truth, rules)
            evasion = run_evasion(rules, self.seed, self.days)
        except Exception as exc:  # a rule that passes the checks but still cannot run
            return {"ok": False, "errors": [f"The rule could not run: {type(exc).__name__}: {exc}"]}

        before = self.tuned
        false_alarms = [
            {"fired_ts": a.fired_ts, "summary": a.summary}
            for a in alerts if a.rule_id == rule_id and after["verdicts"][a.alert_id]["verdict"] == "FP"
        ][:8]
        old_ev = {r["id"]: r["caught"] for r in self.evasion["rows"]}
        return {
            "ok": True, "rule_id": rule_id,
            "before": {"rule": self._stats(before, rule_id), "overall": before["overall"],
                       "redteam_caught": self.evasion["caught"]},
            "after": {"rule": self._stats(after, rule_id), "overall": after["overall"],
                      "redteam_caught": evasion["caught"]},
            "redteam_total": evasion["total"],
            "attacks": [{"id": sc, "name": res["name"],
                         "before": before["scenarios"][sc]["caught"], "after": res["caught"]}
                        for sc, res in after["scenarios"].items()],
            "redteam": [{"id": r["id"], "name": r["name"], "before": old_ev[r["id"]], "after": r["caught"]}
                        for r in evasion["rows"]],
            "false_alarms": false_alarms,
        }


# ------------------------------------------------------------------------------ the server

class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"   # on Windows this option lets two programs share a port

    def __init__(self, address, lab: Lab, page: str, token: str):
        super().__init__(address, Handler)
        self.lab, self.page, self.token = lab, page, token
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/"


class Handler(BaseHTTPRequestHandler):
    server_version = "DetectionLab"
    sys_version = ""

    def log_message(self, format, *args):  # keep the terminal quiet
        pass

    # ---- helpers
    def _send(self, status: int, content_type: str, body: bytes, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, "application/json; charset=utf-8", json.dumps(obj).encode("utf-8"))

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _origin_ok(self) -> bool:
        port = self.server.server_address[1]
        host_ok = (self.headers.get("Host") or "").lower() in {f"127.0.0.1:{port}", f"localhost:{port}"}
        origin = self.headers.get("Origin")
        origin_ok = origin is None or origin.lower() in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        return host_ok and origin_ok

    def _token_ok(self) -> bool:
        sent = (self.headers.get("X-Lab-Token") or "").encode("utf-8", "replace")
        return secrets.compare_digest(sent, self.server.token.encode("utf-8"))

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise BadRequest("The request was not understood.")
        if length <= 0 or length > MAX_BODY_BYTES:
            raise BadRequest("The request is empty or too large.")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BadRequest("The request was not understood.")
        if not isinstance(data, dict):
            raise BadRequest("The request was not understood.")
        return data

    # ---- routing
    def do_GET(self):
        if not self._origin_ok():
            return self._error(403, "This address is not allowed.")
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            return self._send(200, "text/html; charset=utf-8", self.server.page.encode("utf-8"))
        if not url.path.startswith("/api/"):
            return self._error(404, "Not found.")
        if not self._token_ok():
            return self._error(403, "Missing or wrong token. Reload the page.")
        query = parse_qs(url.query)
        try:
            with self.server.lock:
                lab = self.server.lab
                if url.path == "/api/lab":
                    return self._json(200, lab.payload())
                if url.path == "/api/alert":
                    return self._json(200, lab.alert_detail(query.get("id", [""])[0]))
                if url.path == "/api/case":
                    return self._json(200, lab.case_detail(query.get("id", [""])[0]))
                if url.path == "/api/case-report":
                    cid = query.get("id", [""])[0]
                    return self._send(200, "text/markdown; charset=utf-8", lab.case_report(cid).encode("utf-8"),
                                      {"Content-Disposition": f'attachment; filename="{cid}.md"'})
                if url.path == "/api/report":
                    name = query.get("name", [""])[0]
                    return self._send(200, "text/markdown; charset=utf-8", lab.report(name).encode("utf-8"),
                                      {"Content-Disposition": f'attachment; filename="{name}"'})
        except KeyError:
            return self._error(404, "That item does not exist.")
        except Exception:
            return self._error(500, "Something went wrong inside the lab.")
        return self._error(404, "Not found.")

    def do_POST(self):
        if not self._origin_ok():
            return self._error(403, "This address is not allowed.")
        url = urlparse(self.path)
        if not url.path.startswith("/api/"):
            return self._error(404, "Not found.")
        if not self._token_ok():
            return self._error(403, "Missing or wrong token. Reload the page.")
        try:
            body = self._body()
            with self.server.lock:
                lab = self.server.lab
                if url.path == "/api/run":
                    seed, days = body.get("seed"), body.get("days")
                    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= MAX_SEED:
                        raise BadRequest(f"The seed must be a whole number from 0 to {MAX_SEED:,}.")
                    if isinstance(days, bool) or not isinstance(days, int) or not MIN_DAYS <= days <= MAX_DAYS:
                        raise BadRequest(f"Days must be a whole number from {MIN_DAYS} to {MAX_DAYS}.")
                    lab.run(seed, days)
                    return self._json(200, lab.payload())
                if url.path == "/api/test-rule":
                    rule_id, text = body.get("rule_id"), body.get("yaml")
                    if not isinstance(rule_id, str) or not isinstance(text, str):
                        raise BadRequest("The request was not understood.")
                    return self._json(200, lab.test_rule(rule_id, text))
        except BadRequest as exc:
            return self._error(400, str(exc))
        except Exception:
            return self._error(500, "Something went wrong inside the lab.")
        return self._error(404, "Not found.")


def make_server(rules_dir, seed: int = 7, days: int = MIN_DAYS, port: int = DEFAULT_PORT, lab: Lab | None = None,
                with_replay: bool = True) -> LabServer:
    """Build the lab and bind a server. port=0 picks any free port (used by the tests, which can also pass a
    lab they already built, or skip the replay of the real recordings)."""
    lab = lab or Lab(rules_dir, seed, days, with_replay)
    token = secrets.token_urlsafe(24)
    page = (WEB_DIR / "index.html").read_text(encoding="utf-8").replace("__LAB_TOKEN__", token)
    candidates = [0] if port == 0 else range(port, port + 20)
    last_error: OSError | None = None
    for candidate in candidates:
        try:
            return LabServer(("127.0.0.1", candidate), lab, page, token)
        except OSError as exc:
            last_error = exc
    raise OSError(f"Could not find a free port between {port} and {port + 19}: {last_error}")


def serve(rules_dir="rules", seed: int = 7, days: int = MIN_DAYS, port: int = DEFAULT_PORT,
          open_browser: bool = True) -> int:
    print("Building the lab (this takes a moment)...")
    server = make_server(rules_dir, seed, days, port)
    print()
    print("Detection Lab is running.")
    print(f"Open this address in your browser: {server.url}")
    print("A browser tab should open by itself. To stop the lab, click here and press Ctrl+C.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(server.url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping the lab. Goodbye.")
    finally:
        server.server_close()
    return 0
