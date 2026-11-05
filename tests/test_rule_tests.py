"""The unit-test language inside rule files, and the proof that every exclusion is needed."""

import pytest

from detlab.cli import main
from detlab.models import fmt_ts
from detlab.rules import load_rules, validate_rule, validate_rules
from detlab.unit_tests import (BASE_T, MAX_REPEAT, check_test_shape, exclusion_checks, expand_events,
                               mutation_checks, parse_duration, rule_mutants, run_rule_tests)

ATTACK = {"tactic": "Execution", "technique": "T1059", "technique_name": "Command and Scripting Interpreter"}


def toy_rule(**kw):
    """A small match rule: fires on any process named evil.exe, unless it is started by the user 'qa'."""
    rule = {"id": "DET-900", "title": "toy", "status": "experimental", "severity": "low", "attack": ATTACK,
            "description": "toy", "type": "match", "filter": {"action": "process_create", "process_name": "evil.exe"},
            "entity_fields": ["user", "host"],
            "exclusions": [{"match": {"user": "qa"}, "reason": "the test team runs it on purpose"}],
            "triage": ["Who ran it?"], "response": ["Isolate the host."],
            "tests": [
                {"name": "evil.exe fires", "expect": "fire",
                 "events": [{"action": "process_create", "process_name": "evil.exe", "user": "eve"}]},
                {"name": "the test team is excluded", "expect": "no_fire",
                 "events": [{"action": "process_create", "process_name": "evil.exe", "user": "qa"}]}]}
    rule.update(kw)
    return rule


# ------------------------------------------------------------------ durations and short notation

@pytest.mark.parametrize("value,seconds", [(0, 0), (90, 90), ("90", 90), ("90s", 90), ("5m", 300), ("3h", 10800),
                                           ("4d", 345600), (" 2m ", 120)])
def test_durations(value, seconds):
    assert parse_duration(value) == seconds


@pytest.mark.parametrize("bad", [True, -1, "5x", "m", "", "1.5m", None, [5]])
def test_bad_durations_are_refused_with_a_readable_message(bad):
    with pytest.raises(ValueError):
        parse_duration(bad, "at")


def test_events_are_one_second_apart_by_default_and_start_on_a_monday_morning():
    events = expand_events([{"action": "a"}, {"action": "b"}, {"action": "c"}])
    assert [e["_t"] for e in events] == [BASE_T, BASE_T + 1, BASE_T + 2]
    assert events[0]["ts"] == fmt_ts(BASE_T) == "2026-01-05T09:00:00Z"
    assert [e["event_id"] for e in events] == ["t00001", "t00002", "t00003"]


def test_at_repeat_every_and_the_copy_number():
    events = expand_events([{"action": "x", "user": "u{i}", "repeat": 3, "every": "10s"},
                            {"action": "y", "at": "5m"},
                            {"action": "z"}])
    assert [e["user"] for e in events[:3]] == ["u0", "u1", "u2"]
    assert [e["_t"] - BASE_T for e in events] == [0, 10, 20, 300, 301]


def test_a_repeated_event_continues_one_second_after_its_last_copy():
    events = expand_events([{"action": "x", "repeat": 5, "every": "1m"}, {"action": "y"}])
    assert events[-1]["_t"] - BASE_T == 4 * 60 + 1


# ------------------------------------------------------------------ the shape check

def test_a_well_formed_rule_has_no_shape_problems():
    assert check_test_shape(toy_rule(), "DET-900") == []
    assert validate_rule(toy_rule()) == []


@pytest.mark.parametrize("tests,needle", [
    (None, "non-empty list"),
    ([], "non-empty list"),
    ([{"name": "a", "expect": "fire", "events": [{"action": "x"}]}], "expect: no_fire"),
    ([{"name": "a", "expect": "no_fire", "events": [{"action": "x"}]}], "expect: fire"),
    ([{"expect": "fire", "events": [{"action": "x"}]}, {"name": "b", "expect": "no_fire", "events": [{"action": "x"}]}], "needs a name"),
    ([{"name": "a", "expect": "maybe", "events": [{"action": "x"}]}], "expect must be"),
    ([{"name": "a", "expect": "fire", "events": []}], "events must be"),
    ([{"name": "a", "expect": "fire", "events": ["x"]}], "events must be"),
    ([{"name": "a", "expect": "fire", "alerts": "2", "events": [{"action": "x"}]}], "alerts must be"),
    ([{"name": "a", "expect": "fire", "events": [{"action": "x", "repeat": 0}]}], "repeat must be"),
    ([{"name": "a", "expect": "fire", "events": [{"action": "x", "repeat": MAX_REPEAT + 1}]}], "repeat must be"),
    ([{"name": "a", "expect": "fire", "events": [{"action": "x", "at": "soon"}]}], "not a time"),
    ("not a list", "non-empty list"),
])
def test_the_shape_check_names_the_problem(tests, needle):
    problems = check_test_shape({"tests": tests}, "DET-900")
    assert any(needle in p for p in problems), problems


def test_the_validator_runs_the_shape_check():
    rule = toy_rule(tests=[{"name": "only fire", "expect": "fire", "events": [{"action": "process_create"}]}])
    assert any("expect: no_fire" in e for e in validate_rule(rule))


# ------------------------------------------------------------------ running the tests

def test_passing_tests_report_passed():
    rows = run_rule_tests([toy_rule()])
    assert [(r["name"], r["passed"], r["alerts"]) for r in rows] == [("evil.exe fires", True, 1),
                                                                    ("the test team is excluded", True, 0)]


def test_a_wrong_expectation_is_reported_in_plain_words():
    rule = toy_rule()
    rule["tests"][0]["events"][0]["process_name"] = "good.exe"           # the rule will not fire
    rule["tests"][1]["events"][0]["user"] = "eve"                         # the rule will fire
    rows = run_rule_tests([rule])
    assert [r["passed"] for r in rows] == [False, False]
    assert rows[0]["message"] == "expected an alert but none fired"
    assert rows[1]["message"] == "expected no alert but 1 fired"


def test_an_exact_alert_count_can_be_demanded():
    rule = toy_rule()
    rule["tests"][0]["alerts"] = 2
    row = run_rule_tests([rule])[0]
    assert not row["passed"] and row["message"] == "expected exactly 2 alert(s), got 1"


def test_a_broken_test_is_reported_not_raised():
    rule = toy_rule()
    rule["tests"][0]["events"][0]["at"] = "soon"
    row = run_rule_tests([rule])[0]
    assert not row["passed"] and row["message"].startswith("could not run")


def test_only_one_rule_can_be_selected():
    other = toy_rule(id="DET-901")
    assert {r["rule"] for r in run_rule_tests([toy_rule(), other], only="DET-901")} == {"DET-901"}


# ------------------------------------------------------------------ proving that an exclusion is needed

def test_an_exclusion_that_a_test_depends_on_is_exercised():
    rows = exclusion_checks([toy_rule()])
    assert rows == [{"rule": "DET-900", "index": 1, "reason": "the test team runs it on purpose", "exercised": True}]


def test_an_exclusion_that_no_test_depends_on_is_flagged():
    rule = toy_rule()
    rule["exclusions"].append({"match": {"user": "never-tested"}, "reason": "nobody checks this one"})
    rows = exclusion_checks([rule])
    assert [(r["index"], r["exercised"]) for r in rows] == [(1, True), (2, False)]


def test_rules_without_exclusions_give_no_rows():
    assert exclusion_checks([toy_rule(exclusions=[])]) == []


# ------------------------------------------------------------------ the shipped rules

def test_every_shipped_rule_test_passes(rules):
    rows = run_rule_tests(rules)
    assert len(rows) == 320
    assert [f"{r['rule']}: {r['name']}: {r['message']}" for r in rows if not r["passed"]] == []


def test_every_rule_proves_that_it_fires_and_that_it_stays_quiet(rules):
    for rule in rules:
        expects = [t["expect"] for t in rule["tests"]]
        assert "fire" in expects and "no_fire" in expects, rule["id"]


def test_every_exclusion_is_exercised(rules):
    rows = exclusion_checks(rules)
    assert len(rows) == 28
    assert [(r["rule"], r["index"]) for r in rows if not r["exercised"]] == []


def test_removing_any_exclusion_makes_a_test_fail(rules):
    """Stronger than 'exercised': for each of the 28 exclusions, take it out and a rule test must turn red."""
    unguarded = []
    for rule in rules:
        exclusions = rule.get("exclusions") or []
        for i in range(len(exclusions)):
            weaker = {**rule, "exclusions": [e for j, e in enumerate(exclusions) if j != i]}
            if all(r["passed"] for r in run_rule_tests([weaker])):
                unguarded.append((rule["id"], i + 1))
    assert unguarded == []


def test_every_exclusion_is_written_down_with_a_reason_that_says_why(rules):
    for rule in rules:
        for ex in rule.get("exclusions") or []:
            assert len(ex["reason"].split()) >= 6, f"{rule['id']}: the reason is too short to explain anything"


def test_the_test_rules_command(capsys):
    assert main(["test-rules"]) == 0
    out = capsys.readouterr().out
    assert "320" in out and "28" in out


def test_the_test_rules_command_fails_when_a_rule_test_fails(tmp_path, capsys):
    import shutil
    folder = tmp_path / "rules"
    shutil.copytree("rules", folder)
    broken = (folder / "DET-004.yml").read_text(encoding="utf-8").replace("expect: fire", "expect: no_fire", 1)
    (folder / "DET-004.yml").write_text(broken, encoding="utf-8")
    assert main(["test-rules", "--rules", str(folder), "--rule", "DET-004"]) == 1
    assert "DET-004" in capsys.readouterr().out
    assert validate_rules(load_rules(folder)) == []        # the rule is still valid: only its test is wrong


# ------------------------------------------------------------------ small edits of a rule: would a test notice?

def counting_rule(**kw):
    """Fires when one user fails three times inside a minute over rdp or ssh."""
    rule = toy_rule(type="threshold", filter={"action": "login", "outcome": "failure", "service|in": ["rdp", "ssh"]},
                    group_by=["user"], window_seconds=60, threshold=3, exclusions=[],
                    tests=[{"name": "three failures fire", "expect": "fire",
                            "events": [{"action": "login", "outcome": "failure", "service": "rdp", "user": "u", "repeat": 3}]},
                           {"name": "two failures stay quiet", "expect": "no_fire",
                            "events": [{"action": "login", "outcome": "failure", "service": "rdp", "user": "u", "repeat": 2}]}])
    rule.pop("entity_fields")
    rule.update(kw)
    return rule


def test_the_edits_made_to_a_rule_are_the_ones_described():
    what = [w for w, _ in rule_mutants(counting_rule())]
    assert what == ["delete the condition 'outcome' from filter",
                    "delete the condition 'service|in' from filter",
                    "drop the value 'rdp' from 'service|in' in filter",
                    "drop the value 'ssh' from 'service|in' in filter",
                    "change threshold from 3 to 2",
                    "change threshold from 3 to 4",
                    "change window_seconds from 60 to 59",
                    "change window_seconds from 60 to 61",
                    "stop grouping by 'user' (group_by ['user'] becomes [])"]


def test_making_the_edits_never_changes_the_rule_itself():
    rule = counting_rule(filter=[{"action": "login", "service|in": ["rdp", "ssh"]}, {"action": "login", "user": "x"}])
    before = repr(rule)
    list(rule_mutants(rule))
    assert repr(rule) == before


def test_each_edit_really_changes_the_rule():
    rule = counting_rule(filter=[{"action": "login", "outcome": "failure", "service|in": ["rdp", "ssh"]},
                                 {"action": "login", "user": "x", "not": {"service": "vpn"}}])
    for what, changed in rule_mutants(rule):
        assert changed != rule, what


def test_branches_of_a_list_filter_can_be_taken_out_but_the_last_branch_cannot():
    rule = counting_rule(filter=[{"action": "login", "user": "a"}, {"action": "login", "user": "b"}])
    what = [w for w, _ in rule_mutants(rule)]
    assert "take out branch 0 of filter" in what and "take out branch 1 of filter" in what
    assert "delete the condition 'user' from filter[1]" in what
    single = [w for w, _ in rule_mutants(counting_rule(filter=[{"action": "login", "user": "a"}]))]
    assert not any(w.startswith("take out branch") for w in single), "taking out the only branch leaves no rule at all"


def test_a_list_of_one_value_and_a_not_condition_get_no_value_drops():
    rule = counting_rule(filter={"action": "login", "service|in": ["rdp"], "not": [{"user": "a"}, {"user": "b"}]})
    what = [w for w, _ in rule_mutants(rule)]
    assert not any(w.startswith("drop the value") for w in what), what
    assert "delete the condition 'not' from filter" in what


def test_a_counting_number_is_never_moved_below_one():
    rule = counting_rule(threshold=1, window_seconds=1)
    assert [w for w, _ in rule_mutants(rule) if w.startswith("change")] == ["change threshold from 1 to 2",
                                                                            "change window_seconds from 1 to 2"]


def test_every_group_by_field_can_be_dropped_one_at_a_time():
    rule = counting_rule(group_by=["src_ip", "user"])
    changed = {w: r["group_by"] for w, r in rule_mutants(rule) if w.startswith("stop grouping")}
    assert changed == {"stop grouping by 'src_ip' (group_by ['src_ip', 'user'] becomes ['user'])": ["user"],
                       "stop grouping by 'user' (group_by ['src_ip', 'user'] becomes ['src_ip'])": ["src_ip"]}
    assert not [w for w, _ in rule_mutants(counting_rule(group_by=[])) if w.startswith("stop grouping")]
    plain = counting_rule()
    del plain["group_by"]
    assert not [w for w, _ in rule_mutants(plain) if w.startswith("stop grouping")]


def test_the_alert_throttling_can_be_taken_out_only_when_there_is_one():
    assert not [w for w, _ in rule_mutants(counting_rule()) if "throttling" in w]
    rule = counting_rule(suppress_seconds=300)
    (what, changed), = [(w, r) for w, r in rule_mutants(rule) if "throttling" in w]
    assert what == "take out the alert throttling (suppress_seconds 300)" and "suppress_seconds" not in changed
    assert not [w for w, _ in rule_mutants(counting_rule(suppress_seconds=0)) if "throttling" in w]


def test_a_regex_made_of_lookaheads_gets_one_edit_per_part():
    pattern = r"(?i)^(?=.*/create\b)(?=.*powershell)(?!.*\bdelete\b)"
    rule = counting_rule(filter={"action": "login", "command_line|regex": pattern})
    changed = {w.split(" from the pattern")[0]: r["filter"]["command_line|regex"] for w, r in rule_mutants(rule) if "part" in w}
    assert changed == {r"drop the part (?=.*/create\b)": r"(?i)^(?=.*powershell)(?!.*\bdelete\b)",
                       "drop the part (?=.*powershell)": r"(?i)^(?=.*/create\b)(?!.*\bdelete\b)",
                       r"drop the part (?!.*\bdelete\b)": r"(?i)^(?=.*/create\b)(?=.*powershell)"}


def test_other_regular_expressions_are_not_taken_apart():
    for pattern in (r"(?i)powershell", r"(?i)^(?=.*a)", r"(?i)(^(?=.*a)(?=.*b)|c)", r"(?i)^(?=.*a)b"):
        rule = counting_rule(filter={"action": "login", "command_line|regex": pattern})
        assert not [w for w, _ in rule_mutants(rule) if "part" in w], pattern


def test_the_action_condition_is_never_deleted():
    assert not any("'action'" in w for w, _ in rule_mutants(counting_rule()))


def test_every_edit_is_noticed_when_the_tests_are_thorough():
    rule = counting_rule()
    rule["tests"] += [
        {"name": "exactly the threshold fires", "expect": "fire",
         "events": [{"action": "login", "outcome": "failure", "service": "ssh", "user": "u", "repeat": 3}]},
        {"name": "successes do not count", "expect": "no_fire",
         "events": [{"action": "login", "outcome": "success", "service": "rdp", "user": "u", "repeat": 5}]},
        {"name": "other services do not count", "expect": "no_fire",
         "events": [{"action": "login", "outcome": "failure", "service": "vpn", "user": "u", "repeat": 5}]},
        {"name": "four failures also fire", "expect": "fire",
         "events": [{"action": "login", "outcome": "failure", "service": "rdp", "user": "u", "repeat": 4}]},
        {"name": "two failures over ssh stay quiet", "expect": "no_fire",
         "events": [{"action": "login", "outcome": "failure", "service": "ssh", "user": "u", "repeat": 2}]},
        {"name": "the third failure exactly a minute after the first still counts", "expect": "fire",
         "events": [{"action": "login", "outcome": "failure", "service": "rdp", "user": "u", "repeat": 2},
                    {"at": 60, "action": "login", "outcome": "failure", "service": "rdp", "user": "u"}]},
        {"name": "the third failure a second later is outside the window", "expect": "no_fire",
         "events": [{"action": "login", "outcome": "failure", "service": "rdp", "user": "u", "repeat": 2},
                    {"at": 61, "action": "login", "outcome": "failure", "service": "rdp", "user": "u"}]},
        {"name": "failures of two users do not add up", "expect": "no_fire",
         "events": [{"action": "login", "outcome": "failure", "service": "rdp", "user": "u", "repeat": 2},
                    {"action": "login", "outcome": "failure", "service": "rdp", "user": "v", "repeat": 2}]}]
    rows = mutation_checks([rule])
    assert len(rows) == 9
    assert [r["edit"] for r in rows if not r["caught"]] == [], [r for r in rows if not r["caught"]]


def test_thin_tests_leave_edits_unnoticed_and_the_check_names_them():
    """Two tests (three failures over rdp fire, two do not) say nothing about the outcome, the service or ssh."""
    rows = mutation_checks([counting_rule()])
    missed = {r["edit"] for r in rows if not r["caught"]}
    assert missed == {"delete the condition 'outcome' from filter", "delete the condition 'service|in' from filter",
                      "drop the value 'ssh' from 'service|in' in filter", "change window_seconds from 60 to 59",
                      "change window_seconds from 60 to 61", "stop grouping by 'user' (group_by ['user'] becomes [])"}
    assert all(r["rule"] == "DET-900" for r in rows) and len(rows) == 9


def test_one_rule_can_be_selected():
    other = counting_rule(id="DET-901")
    assert {r["rule"] for r in mutation_checks([counting_rule(), other], only="DET-901")} == {"DET-901"}


def test_every_small_edit_of_every_shipped_rule_is_noticed(rules):
    rows = mutation_checks(rules)
    assert len(rows) == 247
    assert [f"{r['rule']}: {r['edit']}" for r in rows if not r["caught"]] == []


def test_the_mutate_option_of_the_command(capsys):
    assert main(["test-rules", "--mutate"]) == 0
    out = capsys.readouterr().out
    assert "247 of 247 small edits to the rules are caught by a test" in out and "NOT CAUGHT" not in out


def test_the_mutate_option_fails_and_names_the_edit_when_a_test_is_missing(tmp_path, capsys):
    import shutil
    folder = tmp_path / "rules"
    shutil.copytree("rules", folder)
    text = (folder / "DET-001.yml").read_text(encoding="utf-8")
    cut = text.index("  - name: 25 successful logins from one address are ordinary")
    (folder / "DET-001.yml").write_text(text[:cut], encoding="utf-8")       # the test that guards the 'outcome' condition
    assert main(["test-rules", "--rules", str(folder), "--rule", "DET-001", "--mutate"]) == 1
    out = capsys.readouterr().out
    assert "NOT CAUGHT  DET-001: delete the condition 'outcome' from filter" in out
    assert main(["test-rules", "--rules", str(folder), "--rule", "DET-001"]) == 0      # without --mutate nothing is wrong


def test_the_mutate_option_does_not_run_over_failing_tests(tmp_path, capsys):
    import shutil
    folder = tmp_path / "rules"
    shutil.copytree("rules", folder)
    broken = (folder / "DET-004.yml").read_text(encoding="utf-8").replace("expect: fire", "expect: no_fire", 1)
    (folder / "DET-004.yml").write_text(broken, encoding="utf-8")
    assert main(["test-rules", "--rules", str(folder), "--rule", "DET-004", "--mutate"]) == 1
    assert "small edits" not in capsys.readouterr().out

