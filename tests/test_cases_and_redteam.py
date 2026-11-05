"""Case correlation, the case risk score, time to detect, the discovery rule, and the red-team (evasion) pack."""

import json
from collections import Counter
from pathlib import Path

import pytest

from detlab.cases import (ACCOUNT_POINTS, ASSET_POINTS, BREADTH_POINTS, CASE_WINDOW_SECONDS, RISK_LEVELS,
                          SEVERITY_POINTS, build_cases, evaluate_cases, evaluate_ranking, rank_cases, risk)
from detlab.cli import main
from detlab.engine import run_rules
from detlab.evaluate import evaluate
from detlab.evasion import run_evasion
from detlab.generate import EVASION_SCENARIOS, generate
from detlab.models import Alert, prepare_events

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SEEDS = (1, 2, 3, 11, 42)

# Red-team attacks that the rules catch today, and the ones that are open gaps with a written explanation.
# A closed gap does not break a test (it makes the docs test ask for new numbers); a regression does.
MUST_STAY_CAUGHT = {"EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-06", "EV-10", "EV-12", "EV-14"}
KNOWN_OPEN_GAPS = {"EV-07", "EV-08", "EV-09", "EV-11", "EV-13", "EV-15"}


def make_alert(rule_id, tactic, first, user=None, ip=None, host=None, target=None, severity="low"):
    entity = {k: v for k, v in {"user": user, "src_ip": ip, "host": host, "target_user": target}.items() if v}
    return Alert(rule_id=rule_id, title=rule_id, severity=severity, tactic=tactic, technique="T1000",
                 entity=entity, first_t=float(first), last_t=float(first), event_ids=[f"{rule_id}-{first}"],
                 fired_t=float(first))


def one_case(*parts, **kw):
    """One case from alerts that all share the account 'eve'. Each part is (rule_id, severity) or (rule_id, severity, tactic)."""
    alerts = [make_alert(p[0], p[2] if len(p) > 2 else "Execution", i, user=kw.get("user", "eve"),
                         host=kw.get("host"), severity=p[1]) for i, p in enumerate(parts)]
    cases = build_cases(alerts)
    assert len(cases) == 1
    return cases[0]


# ------------------------------------------------------------------ case grouping

def test_alerts_sharing_an_account_become_one_case():
    cases = build_cases([make_alert("A", "Execution", 0, user="eve"), make_alert("B", "Persistence", 60, user="eve")])
    assert len(cases) == 1 and len(cases[0].alerts) == 2


def test_different_accounts_stay_separate():
    cases = build_cases([make_alert("A", "Execution", 0, user="eve"), make_alert("B", "Execution", 60, user="bob")])
    assert len(cases) == 2


def test_gap_longer_than_the_window_splits_a_case_but_exactly_the_window_does_not():
    first = make_alert("A", "Execution", 0, user="eve")
    at_limit = make_alert("B", "Execution", CASE_WINDOW_SECONDS, user="eve")
    too_late = make_alert("B", "Execution", CASE_WINDOW_SECONDS + 1, user="eve")
    assert len(build_cases([first, at_limit])) == 1
    assert len(build_cases([first, too_late])) == 2


def test_actor_and_target_count_as_the_same_kind_of_identity():
    actor = make_alert("A", "Persistence", 0, user="admin", target="eve")
    victim = make_alert("B", "Execution", 30, user="eve")
    assert len(build_cases([actor, victim])) == 1


def test_links_chain_through_different_identity_types():
    a = make_alert("A", "Credential Access", 0, user="eve", ip="1.2.3.4")
    b = make_alert("B", "Execution", 60, ip="1.2.3.4", host="WS-1")
    c = make_alert("C", "Discovery", 120, host="WS-1")
    assert len(build_cases([a, b, c])) == 1


def test_case_severity_tactic_order_and_multi_stage_flag():
    alerts = [make_alert("B", "Execution", 100, user="eve", severity="high"),
              make_alert("A", "Credential Access", 0, user="eve", severity="medium"),
              make_alert("C", "Persistence", 200, user="eve", severity="critical")]
    case = build_cases(alerts)[0]
    assert case.severity == "critical"
    assert case.tactics == ["Credential Access", "Execution", "Persistence"]
    assert case.kill_chain
    assert not build_cases(alerts[:2])[0].kill_chain


def test_case_ids_follow_start_time_and_empty_input_is_fine():
    cases = build_cases([make_alert("B", "Execution", 9000, user="bob"), make_alert("A", "Execution", 0, user="eve")])
    assert [c.case_id for c in cases] == ["CASE-001", "CASE-002"]
    assert cases[0].title == "eve"
    assert build_cases([]) == []


# ------------------------------------------------------------------ the risk score

def test_risk_adds_points_once_per_distinct_rule_at_its_highest_severity():
    case = one_case(("R1", "low"), ("R1", "high"), ("R1", "medium"))
    assert risk(case)["score"] == SEVERITY_POINTS["high"]
    assert [f["label"] for f in risk(case)["factors"]] == ["R1 (high)"]
    two = one_case(("R1", "high"), ("R2", "medium"))
    assert risk(two)["score"] == SEVERITY_POINTS["high"] + SEVERITY_POINTS["medium"]


def test_risk_rewards_an_attack_that_moves_through_more_tactics():
    one_stage = one_case(("R1", "low", "Execution"), ("R2", "low", "Execution"))
    three_stages = one_case(("R1", "low", "Execution"), ("R2", "low", "Discovery"), ("R3", "low", "Persistence"))
    assert risk(one_stage)["score"] == 2
    assert risk(three_stages)["score"] == 3 + BREADTH_POINTS * 2


@pytest.mark.parametrize("host,points", [("DC-01", ASSET_POINTS), ("srv-app-01", ASSET_POINTS), ("BACKUP-2", ASSET_POINTS),
                                         ("WS-007", 0), ("LAPTOP-DC", 0)])
def test_risk_counts_a_critical_host_by_its_name_prefix(host, points):
    plain = risk(one_case(("R1", "low")))["score"]
    assert risk(one_case(("R1", "low"), host=host))["score"] == plain + points


@pytest.mark.parametrize("account,points", [("adm.rossi", ACCOUNT_POINTS), ("svc_deploy", ACCOUNT_POINTS),
                                            ("Administrator", ACCOUNT_POINTS), ("it.admin2", ACCOUNT_POINTS),
                                            ("eve", 0), ("madam", 0)])
def test_risk_counts_a_privileged_account_by_its_name_prefix(account, points):
    assert risk(one_case(("R1", "low"), user=account))["score"] == 1 + points


@pytest.mark.parametrize("parts,score,level", [
    ((("R1", "high"), ("R2", "low")), 7, "low"),
    ((("R1", "high"), ("R2", "low"), ("R3", "low")), 8, "medium"),
    ((("R1", "critical"), ("R2", "high"), ("R3", "low")), 17, "medium"),
    ((("R1", "critical"), ("R2", "high"), ("R3", "low"), ("R4", "low")), 18, "high"),
    ((("R1", "critical"), ("R2", "critical"), ("R3", "high"), ("R4", "medium")), 29, "high"),
    ((("R1", "critical"), ("R2", "critical"), ("R3", "critical")), 30, "critical"),
])
def test_risk_level_boundaries(parts, score, level):
    result = risk(one_case(*parts))
    assert (result["score"], result["level"]) == (score, level)


def test_the_published_levels_match_the_code():
    assert RISK_LEVELS == ((30, "critical"), (18, "high"), (8, "medium"), (0, "low"))
    assert SEVERITY_POINTS == {"low": 1, "medium": 3, "high": 6, "critical": 10}


def test_ranking_puts_the_highest_score_first_and_breaks_ties_by_age():
    old = make_alert("R1", "Execution", 0, user="old", severity="high")
    new = make_alert("R1", "Execution", 99999, user="new", severity="high")
    big = make_alert("R2", "Execution", 50000, user="big", severity="critical")
    ranked = rank_cases(build_cases([old, new, big]))
    assert [c.title for c, _ in ranked] == ["big", "old", "new"]
    assert [r["score"] for _, r in ranked] == [10, 6, 6]


def test_ranking_quality_is_none_when_there_is_no_false_case():
    cases = build_cases([make_alert("R1", "Execution", 0, user="eve", severity="high")])
    truth = {"scenarios": {"SC-1": {"event_ids": ["R1-0"]}}}
    quality = evaluate_ranking(cases, evaluate_cases(cases, truth))
    assert quality["pairs_ordered"] is None and quality["false_cases"] == 0 and quality["attack_cases"] == 1


# ----------------------------------------------- cases against the labeled dataset

def test_fifty_four_alerts_become_fourteen_cases_one_per_attack_and_one_false_alarm(rules, dataset):
    events, truth = dataset
    cases = build_cases(run_rules(events, rules))
    result = evaluate_cases(cases, truth)
    assert (result["alerts"], result["cases"]) == (54, 14)
    assert result["scenarios_found"] == 13
    assert result["split_scenarios"] == {} and result["merged_cases"] == {}
    assert result["false_positive_cases"] == ["CASE-004"]
    assert next(c for c in cases if c.case_id == "CASE-004").title == "t.brown"


def test_the_takeover_case_is_flagged_multi_stage_in_order(rules, dataset):
    events, _ = dataset
    case = next(c for c in build_cases(run_rules(events, rules)) if c.title == "d.okafor")
    assert case.tactics == ["Credential Access", "Execution", "Discovery", "Persistence"]
    assert case.kill_chain and case.severity == "critical"


def test_the_full_intrusion_is_one_case_that_uses_the_current_attack_tactic_names(rules, dataset):
    events, _ = dataset
    case = max(build_cases(run_rules(events, rules)), key=lambda c: len(c.alerts))
    assert case.title == "adm.rossi" and len(case.alerts) == 13
    assert len(case.tactics) == 7 and "Defense Impairment" in case.tactics
    assert "Defense Evasion" not in case.tactics, "ATT&CK v20 retired that tactic name"


def test_the_risk_score_ranks_every_attack_above_the_false_alarm(rules, dataset):
    events, truth = dataset
    cases = build_cases(run_rules(events, rules))
    case_eval = evaluate_cases(cases, truth)
    quality = evaluate_ranking(cases, case_eval)
    assert quality == {"attack_cases": 13, "false_cases": 1, "pairs_ordered": 1.0, "pairs_tied": 0,
                       "false_case_ranks": [14], "top_k_all_attacks": True}
    top = rank_cases(cases)[0]
    assert (top[0].title, top[1]["score"], top[1]["level"]) == ("adm.rossi", 115, "critical")


@pytest.mark.parametrize("days", [14, 30])
def test_case_grouping_and_ranking_hold_across_seeds(rules, days):
    for seed in SEEDS:
        events, truth = generate(seed=seed, days=days)
        prepare_events(events)
        cases = build_cases(run_rules(events, rules))
        result = evaluate_cases(cases, truth)
        where = f"seed {seed}, {days} days"
        assert result["scenarios_found"] == 13, where
        assert not result["split_scenarios"] and not result["merged_cases"], where
        assert len(result["false_positive_cases"]) <= 2, where
        quality = evaluate_ranking(cases, result)
        assert quality["pairs_ordered"] == 1.0 and quality["top_k_all_attacks"], where


# ------------------------------------------------------------------ time to detect

def test_takeover_alert_fires_before_the_attacker_gets_in(rules, dataset):
    events, truth = dataset
    by_id = {e["event_id"]: e for e in events}
    success = next(by_id[i] for i in truth["scenarios"]["SC-03"]["event_ids"]
                   if by_id[i]["action"] == "login" and by_id[i]["outcome"] == "success")
    brute_force = next(a for a in run_rules(events, rules)
                       if a.rule_id == "DET-001" and a.entity["user"] == "d.okafor")
    assert brute_force.fired_t < success["_t"]


def test_time_to_detect_is_measured_and_never_negative(rules, dataset):
    events, truth = dataset
    result = evaluate(run_rules(events, rules), truth, rules)
    for sc, res in result["scenarios"].items():
        assert res["ttd_seconds"] is not None and res["ttd_seconds"] >= 0, sc
    assert result["scenarios"]["SC-04"]["ttd_seconds"] == 0       # fires on the malicious login itself
    assert result["scenarios"]["SC-01"]["ttd_seconds"] == 38      # 20th failure at ~2 s spacing
    assert result["scenarios"]["SC-08"]["first_rule"] == "DET-025"


# ------------------------------------------------------------- DET-007 (discovery)

def test_discovery_rule_needs_a_suspicious_parent(rules, dataset):
    events, _ = dataset
    helpdesk = [e for e in events if e.get("process_name") == "whoami.exe" and e["parent_process"] == "cmd.exe"]
    assert helpdesk, "dataset should contain a benign whoami from a normal command prompt"
    alerts = [a for a in run_rules(events, rules) if a.rule_id == "DET-007"]
    alerted = {e for a in alerts for e in a.event_ids}
    assert not alerted & {e["event_id"] for e in helpdesk}


def test_discovery_backup_exclusion_is_pinned_to_user_and_host(rules, dataset):
    events, _ = dataset
    assert not [a for a in run_rules(events, rules) if a.rule_id == "DET-007" and a.entity["user"] == "svc_backup"]
    assert [a for a in run_rules(events, rules, use_exclusions=False)
            if a.rule_id == "DET-007" and a.entity["user"] == "svc_backup"]
    elsewhere = [{"event_id": "e1", "_t": 1.0, "action": "process_create", "user": "svc_backup", "host": "WS-009",
                  "process_name": "whoami.exe", "parent_process": "powershell.exe", "command_line": "whoami.exe"}]
    assert [a.rule_id for a in run_rules(elsewhere, rules)] == ["DET-007"]


# ----------------------------------------------------------------- red-team pack

def test_red_team_results_are_the_documented_ones(rules):
    evasion = run_evasion(rules)
    caught = {r["id"] for r in evasion["rows"] if r["caught"]}
    assert (evasion["caught"], evasion["total"]) == (9, 15)
    assert MUST_STAY_CAUGHT <= caught                                  # nothing that was caught slipped back
    assert {r["id"] for r in evasion["rows"]} - caught <= KNOWN_OPEN_GAPS   # no NEW unexplained misses
    assert evasion["false_positives"] <= 1                              # only the accepted traveller alert


@pytest.mark.parametrize("seed", SEEDS)
def test_red_team_results_hold_across_seeds(rules, seed):
    evasion = run_evasion(rules, seed=seed)
    caught = {r["id"] for r in evasion["rows"] if r["caught"]}
    assert MUST_STAY_CAUGHT <= caught, f"seed {seed}"
    assert {r["id"] for r in evasion["rows"]} - caught <= KNOWN_OPEN_GAPS, f"seed {seed}"
    assert evasion["false_positives"] <= 2, f"seed {seed}"


def test_every_evasion_variant_has_an_expected_rule_and_a_mitigation():
    assert len(EVASION_SCENARIOS) == 15
    for sc, info in EVASION_SCENARIOS.items():
        assert info["expected_rules"] and info["mitigation"].strip(), sc


def test_the_written_status_of_each_attack_agrees_with_the_measured_one(rules):
    """The mitigation text says "Not fixed." for an open gap. If a rule change closes a gap (or opens one), the text must follow."""
    for row in run_evasion(rules)["rows"]:
        says_open = "not fixed" in EVASION_SCENARIOS[row["id"]]["mitigation"].lower()
        assert says_open == (not row["caught"]), f"{row['id']}: the text and the measurement disagree"


def test_evasion_data_only_adds_events_and_leaves_the_core_dataset_unchanged():
    base, base_truth = generate(seed=7, days=14)
    extra, extra_truth = generate(seed=7, days=14, evasion=True)

    def key(e):
        return json.dumps({k: v for k, v in e.items() if k != "event_id"}, sort_keys=True)

    base_counts, extra_counts = Counter(map(key, base)), Counter(map(key, extra))
    assert all(extra_counts[k] >= n for k, n in base_counts.items())
    assert len(extra) > len(base)
    assert not any(sc.startswith("EV-") for sc in base_truth["scenarios"])
    assert set(EVASION_SCENARIOS) <= set(extra_truth["scenarios"])


# ------------------------------------------------------------------ command line

def test_run_command_end_to_end(tmp_path, capsys):
    assert main(["run", "--rules", str(RULES_DIR), "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Generated 11865 events (14 days, seed 7)" in out
    assert "INCIDENT CASES: 54 alerts grouped into 14 cases (13 attacks, none split, none merged, 1 false-positive case)" in out
    assert "RED TEAM: 9 of 15" in out
    assert "TIME TO DETECT" in out
    for name in ("detection_report.md", "evasion_report.md", "alerts.jsonl", "events.jsonl", "ground_truth.json"):
        assert (tmp_path / name).exists(), name
    assert "fired_ts" in (tmp_path / "alerts.jsonl").read_text().splitlines()[0]


def test_cases_and_evasion_commands(tmp_path, capsys):
    main(["run", "--rules", str(RULES_DIR), "--out", str(tmp_path)])
    capsys.readouterr()
    assert main(["cases", "--data", str(tmp_path)]) == 0
    assert "54 alerts grouped into 14 incident cases" in capsys.readouterr().out
    assert main(["evasion", "--rules", str(RULES_DIR), "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "OPEN GAPS" in out and "EV-07" in out


def test_report_wording_is_correct_for_a_count_of_one(tmp_path):
    main(["run", "--rules", str(RULES_DIR), "--out", str(tmp_path)])
    text = (tmp_path / "detection_report.md").read_text(encoding="utf-8")
    assert "1 false-positive case." in text and "1 false-positive cases" not in text

def test_every_report_says_one_false_positive_and_not_one_false_positives(tmp_path):
    main(["run", "--rules", str(RULES_DIR), "--out", str(tmp_path)])
    for name in ("detection_report.md", "evasion_report.md"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert "1 false positive" in text and "1 false positives" not in text, name
    assert "(48 true positives, 1 false positive)" in (tmp_path / "detection_report.md").read_text(encoding="utf-8")


def test_the_case_file_describes_every_kind_of_event_in_words_and_never_by_its_internal_name(tmp_path):
    """The case file of the full intrusion holds a script block, a registry change, a log clear, a service install and
    a directory read. Each must read as a sentence, as it does on the web page."""
    from detlab.schema import ACTIONS
    main(["run", "--rules", str(RULES_DIR), "--out", str(tmp_path)])
    out = tmp_path / "case.md"
    assert main(["case", "--user", "adm.rossi", "--data", str(tmp_path), "--rules", str(RULES_DIR), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    timeline = text.split("## Timeline")[1].split("## Triage questions")[0]
    cells = [line.split(" | ")[1] for line in timeline.splitlines() if line.startswith("| 2026-")]
    assert len(cells) == 13 and not [c for c in cells if c in ACTIONS], cells
    assert "adm.rossi cleared the " in timeline and " event log on WS-ADM-01" in timeline
    assert "The service PSEXESVC was installed on SRV-FILE-01 by adm.rossi" in timeline
    assert "PowerShell on WS-ADM-01 ran a script block for adm.rossi" in timeline
