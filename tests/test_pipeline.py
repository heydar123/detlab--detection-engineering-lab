"""End-to-end checks: the shipped rules against the generated, labeled dataset."""

from pathlib import Path

import pytest

from detlab.engine import run_rules
from detlab.evaluate import evaluate
from detlab.generate import generate
from detlab.models import prepare_events
from detlab.rules import validate_rule, validate_rules

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# The one rule that raises a false alarm on the made-up logs even after tuning: a real traveller who signs in from
# a network provider they have not used before. It is a documented, accepted trade-off (see the rule's false_positives).
ACCEPTED_NOISY_RULE = "DET-027"
SEEDS = (1, 2, 3, 7, 11, 42)


def test_shipped_rules_are_valid(rules):
    assert validate_rules(rules) == []
    assert len(rules) == 32


def test_bundled_yaml_parses_rules_exactly_like_installed_pyyaml():
    """The bundled parser is the fallback on Pythons where PyYAML is not installed."""
    installed = pytest.importorskip("yaml")
    from detlab._vendor import yaml as bundled

    for path in sorted(RULES_DIR.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert bundled.safe_load(text) == installed.safe_load(text), path.name


def test_every_exclusion_has_a_reason(rules):
    for r in rules:
        for ex in r.get("exclusions", []):
            assert ex["reason"].strip(), r["id"]


def test_validator_rejects_bad_rules(rules):
    bad = dict(rules[0])
    bad["exclusions"] = [{"match": {"src_ip": "1.2.3.4"}}]  # no reason
    assert any("reason" in e for e in validate_rule(bad))
    bad = dict(rules[0], type="nonsense")
    assert any("unknown type" in e for e in validate_rule(bad))
    bad = dict(rules[0], attack={"tactic": "x", "technique": "1110", "technique_name": "y"})
    assert any("technique" in e for e in validate_rule(bad))
    bad = {k: v for k, v in rules[0].items() if k != "triage"}
    assert any("triage" in e for e in validate_rule(bad))
    # a YAML step containing ': ' silently becomes a dict - the validator must catch it
    bad = dict(rules[0], response=[{"Hunt for follow-on activity": "new processes"}])
    assert any("plain text" in e for e in validate_rule(bad))


def test_generator_is_deterministic():
    a, _ = generate(seed=7, days=14)
    b, _ = generate(seed=7, days=14)
    c, _ = generate(seed=8, days=14)
    assert a == b
    assert a != c


def test_generator_rejects_too_few_days():
    with pytest.raises(ValueError):
        generate(days=5)


def test_ground_truth_is_consistent(dataset):
    events, truth = dataset
    ids = {e["event_id"] for e in events}
    assert len(ids) == len(events) == 11865
    assert len(truth["scenarios"]) == 13
    for sc in truth["scenarios"].values():
        assert sc["event_ids"] and set(sc["event_ids"]) <= ids


def test_every_generated_event_follows_the_schema(dataset):
    """The schema is the contract between the generator, the rules and the real-data translator."""
    from detlab.schema import ACTIONS, COMMON_FIELDS

    events, _ = dataset
    for e in events:
        assert e["action"] in ACTIONS, f"{e['event_id']}: unknown action {e['action']!r}"
        allowed = set(COMMON_FIELDS) | set(ACTIONS[e["action"]]["fields"])
        stray = {k for k in e if not k.startswith("_")} - allowed
        assert not stray, f"{e['event_id']} ({e['action']}) has fields the schema does not list: {sorted(stray)}"
    assert len(ACTIONS) == 18
    assert {e["action"] for e in events} == set(ACTIONS) - {"audit_policy_change"}


def test_tuned_rules_catch_every_attack_and_raise_one_known_false_alarm(rules, dataset):
    events, truth = dataset
    result = evaluate(run_rules(events, rules, use_exclusions=True), truth, rules)
    overall = result["overall"]
    assert (overall["alerts"], overall["tp"], overall["fp"]) == (54, 48, 1)
    assert overall["recall"] == 1.0 and round(overall["precision"], 4) == 0.9796
    for rid, row in result["per_rule"].items():
        assert row["recall"] in (1.0, None), f"{rid} missed {row['missed']}"
        if row["fp"]:
            assert rid == ACCEPTED_NOISY_RULE, f"{rid} has {row['fp']} false positives after tuning"
    assert all(s["caught"] for s in result["scenarios"].values())


def test_untuned_rules_are_noisy_but_still_catch_everything(rules, dataset):
    events, truth = dataset
    result = evaluate(run_rules(events, rules, use_exclusions=False), truth, rules)
    overall = result["overall"]
    assert (overall["alerts"], overall["tp"], overall["fp"]) == (143, 48, 90)
    assert overall["recall"] == 1.0 and overall["precision"] < 0.35
    noisy = {rid for rid, row in result["per_rule"].items() if row["fp"] > 0}
    assert {"DET-001", "DET-002", "DET-003", "DET-004", "DET-006", "DET-007", "DET-008"} <= noisy


@pytest.mark.parametrize("days", [14, 30])
def test_detection_holds_across_seeds(rules, days):
    """Every attack is found at every seed. The only false alarms are the accepted one, and there are few."""
    for seed in SEEDS:
        events, truth = generate(seed=seed, days=days)
        prepare_events(events)
        result = evaluate(run_rules(events, rules), truth, rules)
        assert result["overall"]["recall"] == 1.0, f"seed {seed}, {days} days"
        assert all(s["caught"] for s in result["scenarios"].values()), f"seed {seed}, {days} days"
        noisy = {rid: row["fp"] for rid, row in result["per_rule"].items() if row["fp"]}
        assert set(noisy) <= {ACCEPTED_NOISY_RULE}, f"seed {seed}, {days} days: {noisy}"
        assert result["overall"]["fp"] <= 2, f"seed {seed}, {days} days"


def test_genuine_traveller_is_not_flagged_by_impossible_travel(rules, dataset):
    events, _ = dataset
    alerts = run_rules(events, rules)
    assert not [a for a in alerts if a.rule_id == "DET-003" and a.entity.get("user") == "t.brown"]


def test_the_accepted_false_alarm_is_the_traveller(rules, dataset):
    events, truth = dataset
    alerts = run_rules(events, rules)
    noisy = [a for a in alerts if a.rule_id == ACCEPTED_NOISY_RULE and a.entity.get("user") == "t.brown"]
    assert noisy, "the lab's one accepted false alarm should still be the traveller"
    planted = {e for sc in truth["scenarios"].values() for e in sc["event_ids"]}
    assert not planted & {e for a in noisy for e in a.event_ids}


def test_backup_user_on_another_host_would_still_alert(rules):
    """The DET-004 exclusion is pinned to user AND host, so it can't be abused elsewhere."""
    cmd = "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAZQBzAHQAJwA="
    ev = [{"event_id": "e1", "_t": 1.0, "action": "process_create", "user": "svc_backup", "host": "WS-005",
           "process_name": "powershell.exe", "command_line": cmd}]
    alerts = run_rules(ev, rules)
    assert [a.rule_id for a in alerts] == ["DET-004"]
