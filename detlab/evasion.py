"""Red-team check: run the rules against attack variants written to slip past them.

The six variants (EV-01..EV-06, defined in generate.py) were written after the first version of
the rules, specifically to get around them. Each one names the rule that SHOULD catch it, so a
miss is a measured, documented gap rather than a surprise. Nothing here is hidden from the report.
"""

from __future__ import annotations

from .engine import run_rules
from .evaluate import evaluate
from .generate import EVASION_SCENARIOS, generate
from .models import prepare_events


def run_evasion(rules: list[dict], seed: int = 7, days: int = 14) -> dict:
    events, truth = generate(seed, days, evasion=True)
    prepare_events(events)
    alerts = run_rules(events, rules)
    result = evaluate(alerts, truth, rules)

    rows = []
    for sc in EVASION_SCENARIOS:
        res = result["scenarios"][sc]
        info = truth["scenarios"][sc]
        rows.append({
            "id": sc,
            "name": info["name"],
            "description": info["description"],
            "expected": info["expected_rules"],
            "caught": res["caught"],
            "detected_by": res["detected"],
            "ttd_seconds": res["ttd_seconds"],
            "mitigation": info["mitigation"],
        })
    return {
        "rows": rows,
        "caught": sum(1 for r in rows if r["caught"]),
        "total": len(rows),
        "false_positives": result["overall"]["fp"],
        "result": result,
        "alerts": alerts,
        "truth": truth,
    }
