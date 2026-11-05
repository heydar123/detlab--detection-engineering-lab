"""The matching language (every modifier), the newer rule types, and the speed-up that must never change a result."""

import json

import pytest

from detlab.engine import RUNNERS, rule_actions, run_rules
from detlab.matching import (excluded, filter_actions, filter_fields, matches, parse_key, split_fields,
                             validate_filter)
from detlab.models import prepare_events

ATTACK = {"tactic": "Command and Control", "technique": "T1071", "technique_name": "Application Layer Protocol"}


# ------------------------------------------------------------------ the modifiers

@pytest.mark.parametrize("flt,event,expected", [
    ({"user": "EVE"}, {"user": "eve"}, True),                                             # equals ignores case
    ({"user|in": ["a", "B"]}, {"user": "b"}, True),
    ({"user|in": ["a", "b"]}, {"user": "c"}, False),
    ({"command_line|contains": "-enc"}, {"command_line": "powershell -ENC AAA"}, True),
    ({"command_line|contains": ["-enc", "-e "]}, {"command_line": "powershell -e AAA"}, True),     # a list means any
    ({"command_line|contains_all": ["-nop", "-w hidden"]}, {"command_line": "ps -nop -w hidden"}, True),
    ({"command_line|contains_all": ["-nop", "-w hidden"]}, {"command_line": "ps -nop"}, False),
    ({"path|startswith": "c:\\users\\"}, {"path": "C:\\Users\\bob\\x.exe"}, True),
    ({"path|endswith": [".js", ".vbs"]}, {"path": "run.VBS"}, True),
    ({"path|endswith": [".js", ".vbs"]}, {"path": "run.exe"}, False),
    ({"x|regex": "^a.c$"}, {"x": "abc"}, True),
    ({"x|regex": "^A.C$"}, {"x": "abc"}, False),                                          # regex keeps its own case rules
    ({"x|regex": "(?i)^A.C$"}, {"x": "abc"}, True),
    ({"n|gt": 5}, {"n": 6}, True), ({"n|gt": 5}, {"n": 5}, False), ({"n|gte": 5}, {"n": "5"}, True),
    ({"n|lt": 5}, {"n": 4.5}, True), ({"n|lte": 5}, {"n": 5}, True), ({"n|gt": 5}, {"n": "many"}, False),
    ({"mask|bitany": "0x1fffff"}, {"mask": "0x1410"}, True),
    ({"mask|bitany": "0x38"}, {"mask": "0x1400"}, False),
    ({"mask|bitany": ["0x20", "0x10"]}, {"mask": "0x1410"}, True),
    ({"mask|bitall": ["0x1000", "0x400", "0x10"]}, {"mask": "0x1410"}, True),
    ({"mask|bitall": ["0x1000", "0x2"]}, {"mask": "0x1410"}, False),
    ({"mask|bitany": "0x10"}, {"mask": 16}, True),                                        # a plain number works too
    ({"mask|bitany": "0x10"}, {"mask": "not a number"}, False),
    ({"x|exists": True}, {"x": "a"}, True), ({"x|exists": True}, {"x": ""}, False), ({"x|exists": True}, {}, False),
    ({"x|exists": False}, {}, True), ({"x|exists": False}, {"x": "a"}, False),
    ({"x": "a"}, {}, False),                                                              # a missing field never matches
])
def test_every_modifier(flt, event, expected):
    assert matches(event, flt) is expected


def test_a_mapping_means_and_a_list_means_or():
    flt = [{"user": "a", "host": "h1"}, {"user": "b"}]
    assert matches({"user": "a", "host": "h1"}, flt)
    assert not matches({"user": "a", "host": "h2"}, flt)
    assert matches({"user": "b", "host": "anything"}, flt)


def test_not_negates_a_whole_filter():
    flt = {"action": "process_create", "not": {"parent_process": "explorer.exe"}}
    assert matches({"action": "process_create", "parent_process": "winword.exe"}, flt)
    assert not matches({"action": "process_create", "parent_process": "explorer.exe"}, flt)
    assert matches({"action": "process_create"}, flt)             # no parent at all: the inner filter does not match


def test_a_key_with_several_fields_matches_when_any_of_them_does():
    """How a rule recognises a renamed tool: the file name changed, the name stored inside the program did not."""
    flt = {"process_name,original_name|in": ["psexec.exe", "psexesvc.exe"]}
    assert matches({"process_name": "totally-normal.exe", "original_name": "psexec.exe"}, flt)
    assert matches({"process_name": "PsExec.exe"}, flt)
    assert not matches({"process_name": "chrome.exe", "original_name": "chrome.exe"}, flt)
    assert not matches({"process_name": "chrome.exe"}, flt)


def test_exclusions_need_every_field_of_one_exclusion():
    ex = [{"match": {"user": "svc_backup", "host": "BACKUP-01"}, "reason": "the backup job"}]
    assert excluded({"user": "svc_backup", "host": "BACKUP-01"}, ex)
    assert not excluded({"user": "svc_backup", "host": "WS-005"}, ex)


def test_key_parsing():
    assert parse_key("user") == ("user", "equals")
    assert parse_key("a,b|in") == ("a,b", "in")
    assert split_fields("a, b") == ["a", "b"] and split_fields("a") == ["a"]


# ------------------------------------------------------------------ the checks on a filter

@pytest.mark.parametrize("flt,needle", [
    ({"user|shout": "x"}, "unknown modifier"),
    ({"x|regex": "("}, "invalid regex"),
    ({"x|gt": "many"}, "needs a number"),
    ({"x|bitany": "zzz"}, "needs numbers"),
    ({"x|exists": "yes"}, "must be true or false"),
    ({"a,b|exists": True}, "cannot combine"),
    ({}, "non-empty mapping"),
    ([], "must not be empty"),
    ({"not": {}}, "non-empty mapping"),
    ({",b": "x"}, "empty field name"),
])
def test_validate_filter_names_each_problem(flt, needle):
    assert any(needle in e for e in validate_filter(flt, "filter")), validate_filter(flt, "filter")


def test_validate_filter_accepts_good_filters():
    assert validate_filter({"a|regex": "^x", "b|gt": 3, "not": {"c|in": [1, 2]}}, "f") == []
    assert validate_filter([{"a": 1}, {"b|exists": False}], "f") == []


def test_filter_fields_sees_inside_not_lists_and_multi_field_keys():
    flt = [{"a|in": [1], "not": {"b": 2}}, {"c,d|contains": "x"}]
    assert filter_fields(flt) == {"a", "b", "c", "d"}


def test_filter_actions_only_limits_when_it_is_certain():
    assert filter_actions({"action": "process_create", "x": 1}) == {"process_create"}
    assert filter_actions({"action|in": ["Login", "mfa_prompt"]}) == {"login", "mfa_prompt"}
    assert filter_actions({"x": 1}) is None
    assert filter_actions([{"action": "a"}, {"action": "b"}]) == {"a", "b"}
    assert filter_actions([{"action": "a"}, {"x": 1}]) is None            # one branch may match any action


# ------------------------------------------------------------------ rule types added after the first version

def rule(**kw):
    base = {"id": "DET-950", "title": "t", "severity": "low", "attack": ATTACK}
    base.update(kw)
    return base


def conn(i, t, dst="203.0.113.5", host="H1", proc="p.exe", sent=0):
    return {"event_id": f"c{i:05d}", "_t": float(t), "action": "network_connect", "host": host, "process_name": proc,
            "dst_ip": dst, "dst_scope": "external", "bytes_out": sent}


SUM = rule(type="sum_threshold", filter={"action": "network_connect", "dst_scope": "external"},
           group_by=["host", "dst_ip"], sum_field="bytes_out", window_seconds=3600, threshold=1000)


def test_sum_threshold_adds_up_a_number_over_a_window():
    below = [conn(i, i * 60, sent=100) for i in range(9)]          # 900
    at = [conn(i, i * 60, sent=100) for i in range(10)]            # 1000
    assert run_rules(below, [SUM]) == []
    alerts = run_rules(at, [SUM])
    assert len(alerts) == 1 and "1000 bytes of bytes_out in 10 events" in alerts[0].summary


def test_sum_threshold_forgets_what_left_the_window():
    spread = [conn(i, i * 1000, sent=100) for i in range(10)]      # 10 events, but never more than 4 inside an hour
    assert run_rules(spread, [SUM]) == []


def test_sum_threshold_groups_are_independent_and_a_burst_is_one_alert():
    two_hosts = [conn(i, i, host="H1", sent=100) for i in range(6)] + [conn(10 + i, i, host="H2", sent=100) for i in range(6)]
    assert run_rules(two_hosts, [SUM]) == []
    burst = [conn(i, i * 10, sent=500) for i in range(20)]
    assert len(run_rules(burst, [SUM])) == 1


BEACON = rule(type="beaconing", filter={"action": "network_connect", "dst_scope": "external"},
              group_by=["host", "process_name", "dst_ip"], window_seconds=3600, min_events=12, max_cv=0.15,
              min_interval_seconds=20, max_interval_seconds=900)


def test_beaconing_fires_on_a_steady_rhythm_and_reports_it():
    alerts = run_rules([conn(i, i * 60) for i in range(15)], [BEACON])
    assert len(alerts) == 1 and "about every 60s" in alerts[0].summary and "variation 0%" in alerts[0].summary


def test_beaconing_ignores_jitter_too_few_events_and_rhythms_outside_the_limits():
    jittery = [conn(i, i * 60 + (17 if i % 2 else -17)) for i in range(15)]
    assert run_rules(jittery, [BEACON]) == []
    assert run_rules([conn(i, i * 60) for i in range(11)], [BEACON]) == []                  # one short of min_events
    assert run_rules([conn(i, i * 5) for i in range(30)], [BEACON]) == []                   # faster than min_interval
    assert run_rules([conn(i, i * 1000) for i in range(12)], [BEACON]) == []                # slower than max_interval


def test_beaconing_a_continuing_beacon_is_one_alert():
    assert len(run_rules([conn(i, i * 60) for i in range(60)], [BEACON])) == 1


def test_beaconing_looser_limit_catches_more_jitter():
    """These gaps alternate 26 s and 94 s. The variation is about 54 percent once 12 events are in the window."""
    jittery = [conn(i, i * 60 + (17 if i % 2 else -17)) for i in range(15)]
    assert run_rules(jittery, [{**BEACON, "max_cv": 0.5}]) == []
    alerts = run_rules(jittery, [{**BEACON, "max_cv": 0.6}])
    assert len(alerts) == 1 and "variation 54%" in alerts[0].summary


def login(i, t, user, asn, outcome="success"):
    return {"event_id": f"l{i:05d}", "_t": float(t), "action": "login", "user": user, "asn": asn, "outcome": outcome}


FIRST = rule(type="first_seen", filter={"action": "login", "outcome": "success"}, group_by=["user"],
             value_field="asn", learning_seconds=1000)


def test_first_seen_learns_then_flags_a_value_it_never_saw():
    events = [login(1, 0, "ann", "AS1"), login(2, 500, "ann", "AS2"),       # learning
              login(3, 2000, "ann", "AS1"),                                    # known: quiet
              login(4, 3000, "ann", "AS9")]                                    # new: alert
    alerts = run_rules(events, [FIRST])
    assert len(alerts) == 1 and alerts[0].entity == {"user": "ann", "asn": "AS9"}
    assert alerts[0].summary == "user=ann, asn=AS9: new asn AS9, not seen in the first 16 min" or \
        alerts[0].summary == "user=ann: new asn AS9, not seen in the first 16 min"


def test_first_seen_flags_each_new_value_once():
    events = [login(1, 0, "ann", "AS1"), login(2, 2000, "ann", "AS9"), login(3, 3000, "ann", "AS9")]
    assert len(run_rules(events, [FIRST])) == 1


def test_first_seen_skips_a_group_it_never_saw_while_learning_unless_told_not_to():
    events = [login(1, 0, "ann", "AS1"), login(2, 2000, "bob", "AS5")]       # bob appears only after learning
    assert run_rules(events, [FIRST]) == []
    assert len(run_rules(events, [{**FIRST, "require_baseline": False}])) == 1


# ------------------------------------------------------------------ the speed-up never changes a result

def full_scan(events, rules, use_exclusions=True):
    """The slow, obviously-correct way: every rule reads every event."""
    ordered = sorted(events, key=lambda e: (e["_t"], e["event_id"]))
    alerts = []
    for r in rules:
        stream = [e for e in ordered if not excluded(e, r["exclusions"])] if use_exclusions and r.get("exclusions") else ordered
        alerts.extend(RUNNERS[r["type"]](r, stream))
    alerts.sort(key=lambda a: (a.first_t, a.rule_id))
    return alerts


def signature(alerts):
    return [(a.rule_id, a.first_t, a.last_t, a.fired_t, json.dumps(a.entity, sort_keys=True), tuple(a.event_ids), a.summary)
            for a in alerts]


@pytest.mark.parametrize("use_exclusions", [True, False])
def test_skipping_events_a_rule_cannot_match_gives_the_same_alerts(rules, dataset, use_exclusions):
    events, _ = dataset
    fast = run_rules(events, rules, use_exclusions=use_exclusions)
    slow = full_scan(events, rules, use_exclusions=use_exclusions)
    assert len(fast) == len(slow) and signature(fast) == signature(slow)


def test_the_equivalence_also_holds_with_the_red_team_events():
    from detlab.generate import generate
    from detlab.rules import load_rules
    rules = load_rules("rules")
    events, _ = generate(seed=3, days=14, evasion=True)
    prepare_events(events)
    assert signature(run_rules(events, rules)) == signature(full_scan(events, rules))


def test_most_rules_are_limited_to_a_few_actions_and_the_rest_read_everything(rules):
    limited = [r["id"] for r in rules if rule_actions(r) is not None]
    assert len(limited) >= 28, "the speed-up only helps if most rules name the actions they read"
    for r in rules:
        acts = rule_actions(r)
        if acts is not None:
            from detlab.schema import ACTIONS
            assert acts <= set(ACTIONS), f"{r['id']} reads an action that is not in the schema: {acts - set(ACTIONS)}"
