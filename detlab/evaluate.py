"""Score alerts against ground truth.

Verdicts per alert:
  TP       evidence includes a malicious event from a scenario that expects this rule
  related  evidence includes malicious events, but from scenarios that do not expect this rule
  FP       evidence contains no malicious events at all

Per rule:
  precision = TP / (TP + FP)               (related alerts are not counted either way)
  recall    = scenarios detected / scenarios that expect the rule

Time to detect (per scenario): seconds from the scenario's first malicious event to the moment
the first expected rule fired (alert.fired_t).
"""

from __future__ import annotations

from .models import Alert, fmt_ts, parse_ts


def _ratio(num: int, den: int):
    return None if den == 0 else num / den


def evaluate(alerts: list[Alert], truth: dict, rules: list[dict]) -> dict:
    scenarios = truth["scenarios"]
    malicious = {eid: sc for sc, s in scenarios.items() for eid in s["event_ids"]}

    per_rule = {
        r["id"]: {"title": r["title"], "alerts": 0, "tp": 0, "fp": 0, "related": 0,
                  "expected": 0, "detected": 0, "missed": []}
        for r in rules
    }
    verdicts: dict[str, dict] = {}
    detected_at: dict[tuple[str, str], float] = {}  # (rule, scenario) -> earliest fire time

    for a in alerts:
        row = per_rule.setdefault(a.rule_id, {"title": a.title, "alerts": 0, "tp": 0, "fp": 0,
                                              "related": 0, "expected": 0, "detected": 0, "missed": []})
        row["alerts"] += 1
        hit = sorted({malicious[e] for e in a.event_ids if e in malicious})
        if not hit:
            verdict = "FP"
            row["fp"] += 1
        elif any(a.rule_id in scenarios[sc]["expected_rules"] for sc in hit):
            verdict = "TP"
            row["tp"] += 1
            for sc in hit:
                if a.rule_id in scenarios[sc]["expected_rules"]:
                    key = (a.rule_id, sc)
                    detected_at[key] = min(detected_at.get(key, a.fired_t), a.fired_t)
        else:
            verdict = "related"
            row["related"] += 1
        verdicts[a.alert_id] = {"verdict": verdict, "scenarios": hit}

    scenario_results: dict[str, dict] = {}
    for sc, info in scenarios.items():
        found = [r for r in info["expected_rules"] if (r, sc) in detected_at]
        missed = [r for r in info["expected_rules"] if (r, sc) not in detected_at]
        first_fire = min((detected_at[(r, sc)] for r in found), default=None)
        first_rule = min(found, key=lambda r: detected_at[(r, sc)]) if found else None
        first_malicious = info.get("first_ts")
        ttd = None
        if first_fire is not None and first_malicious:
            ttd = int(first_fire - parse_ts(first_malicious))
        scenario_results[sc] = {"name": info["name"], "expected": info["expected_rules"],
                                "detected": found, "missed": missed, "caught": bool(found),
                                "first_malicious_ts": first_malicious,
                                "first_alert_ts": fmt_ts(first_fire) if first_fire is not None else None,
                                "first_rule": first_rule,
                                "ttd_seconds": ttd}
        for rid in info["expected_rules"]:
            row = per_rule.setdefault(rid, {"title": rid, "alerts": 0, "tp": 0, "fp": 0, "related": 0,
                                            "expected": 0, "detected": 0, "missed": []})
            row["expected"] += 1
            if rid in found:
                row["detected"] += 1
            else:
                row["missed"].append(sc)

    for row in per_rule.values():
        row["precision"] = _ratio(row["tp"], row["tp"] + row["fp"])
        row["recall"] = _ratio(row["detected"], row["expected"])

    total_tp = sum(r["tp"] for r in per_rule.values())
    total_fp = sum(r["fp"] for r in per_rule.values())
    total_expected = sum(r["expected"] for r in per_rule.values())
    total_detected = sum(r["detected"] for r in per_rule.values())
    return {
        "per_rule": per_rule,
        "verdicts": verdicts,
        "scenarios": scenario_results,
        "overall": {
            "alerts": len(alerts), "tp": total_tp, "fp": total_fp,
            "precision": _ratio(total_tp, total_tp + total_fp),
            "recall": _ratio(total_detected, total_expected),
        },
    }
