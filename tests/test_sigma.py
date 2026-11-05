"""Sigma export: what is written, what is refused, the drift check, and a check that the Sigma files mean what the rules mean."""

import copy
import hashlib
import json
import re
import shutil
import uuid
import zipfile
from pathlib import Path

import pytest

import sigma_reader as sr
from detlab import replay as rp
from detlab.engine import run_rules
from detlab.matching import _condition_ok, matches
from detlab.rules import yaml
from detlab.sigma import (NAMESPACE, NOT_EXPORTED_TYPES, NotExportable, check_sigma, export_all, export_rule,
                          render_files, render_index, slug, split_regex, to_yaml, write_sigma, _timespan)
from detlab.unit_tests import expand_events

ROOT = Path(__file__).resolve().parents[1]
SIGMA = ROOT / "sigma"
ATTACK = {"tactic": "Execution", "technique": "T1059", "technique_name": "Command and Scripting Interpreter"}
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}


def toy(filt, rtype="match", **kw):
    rule = {"id": "DET-901", "title": "Toy", "status": "experimental", "severity": "high", "attack": ATTACK,
            "description": "A toy.", "type": rtype, "filter": filt, "entity_fields": ["host"], "exclusions": [],
            "triage": ["x"], "response": ["y"]}
    rule.update(kw)
    return rule


def export(filt, **kw):
    return export_rule(toy(filt, **kw))


# ------------------------------------------------------------------ regular expressions without lookahead

def alt(*positive, neg=()):
    return list(positive), list(neg)


@pytest.mark.parametrize("pattern,flags,alternatives", [
    ("abc", "", [alt("abc")]),
    ("(?i)abc", "i", [alt("abc")]),
    ("(?is)a.b", "is", [alt("a.b")]),
    ("^(?=.*foo)(?=.*bar)", "", [alt("foo", "bar")]),
    ("(?i)^(?=.*foo)(?!.*baz)", "i", [alt("foo", neg=["baz"])]),
    ("^(?=.*foo)(?!.*a)(?!.*b)", "", [alt("foo", neg=["a", "b"])]),
    ("^(?=.*foo)(?=.*(x|y))", "", [alt("foo", "(x|y)")]),
    ("^(?=.*a)|^(?=.*b)", "", [alt("a"), alt("b")]),
    ("(^(?=.*a)(?=.*b)|^(?=.*c))", "", [alt("a", "b"), alt("c")]),
    ("^(?=.*a)(?=.*b)|plain|x[|]y", "", [alt("a", "b"), alt("plain"), alt("x[|]y")]),
    (r"^(?=.*a\|b)(?=.*[|]c)", "", [alt(r"a\|b", "[|]c")]),
    ("^(?=.*[)])(?=.*b)", "", [alt("[)]", "b")]),
])
def test_a_lookahead_regex_is_split_into_patterns_that_need_no_lookahead(pattern, flags, alternatives):
    assert split_regex(pattern) == (flags, alternatives)


def test_a_regex_without_lookahead_is_kept_exactly_as_written():
    pattern = r"(?i)\s-(e|ec|enc)\s+[A-Za-z0-9+/=]{20,}|a\|b"
    flags, alternatives = split_regex(pattern)
    assert flags == "i" and alternatives == [([pattern[len("(?i)"):]], [])]


@pytest.mark.parametrize("pattern,needle", [
    ("^(?!.*x)", "only says what must be absent"),
    ("^(?=.*a)tail", "mixes lookaheads"),
    ("^(?=.*a)|(?<=b)c", "lookaround"),
    ("^(?=.*(a)", "unbalanced"),
])
def test_a_regex_that_cannot_be_split_is_refused_with_a_reason(pattern, needle):
    with pytest.raises(NotExportable, match=needle):
        split_regex(pattern)


def test_the_split_patterns_mean_the_same_as_the_lookahead_pattern():
    """Check the rewrite itself on strings, with Python's own regex engine on both sides."""
    import itertools
    import re as regex

    patterns = ["^(?=.*a)(?=.*b)", "^(?=.*a)(?!.*b)", "^(?=.*ab)|^(?=.*c)(?!.*d)", "^(?=.*(a|b))(?=.*c)(?!.*(d|e))"]
    texts = ["".join(p) for n in range(0, 4) for p in itertools.product("abcde ", repeat=n)]
    for pattern in patterns:
        flags, alternatives = split_regex(pattern)
        for text in texts:
            original = regex.search(pattern, text) is not None
            rewritten = any(all(regex.search(p, text) for p in pos) and not any(regex.search(n, text) for n in neg)
                            for pos, neg in alternatives)
            assert original == rewritten, (pattern, text)


# ------------------------------------------------------------------ small helpers and the YAML writer

def test_names_and_time_spans():
    assert slug("DET-004") == "detlab_det_004"
    assert [_timespan(s) for s in (30, 90, 120, 900, 3600, 7200, 86400, 172800, 604800)] == \
        ["30s", "90s", "2m", "15m", "1h", "2h", "1d", "2d", "7d"]


TRICKY = ["plain", "true", "No", "null", "12", "1.5", "a: b", "- x", "# c", "it's", "", " lead", "trail ", "tab\tx",
          "line\nbreak", "x\u2028y", "C:\\Windows\\System32", "'quoted'", '"dq"', "[a]", "{b}", "a,b", "*star", "&amp",
          "!tag", "%pct", "@at", "`tick", "~", "?"]


@pytest.mark.parametrize("text", TRICKY)
def test_the_yaml_writer_round_trips_awkward_text(text):
    doc = {"key": text, "list": [text, {"nested": text}], "n": 5, "flag": True, "empty": [], "none": {}}
    assert yaml.safe_load(to_yaml(doc)) == doc


def test_the_yaml_writer_refuses_nested_lists():
    with pytest.raises(ValueError, match="nested lists"):
        to_yaml([["a"]])


def test_every_exported_file_reads_back_as_the_documents_that_were_exported(rules):
    files, result = render_files(rules)
    assert len(files) == 19
    for name, text in files.items():
        assert list(yaml.safe_load_all(text)) == result[name[:-4]]["docs"], name


# ------------------------------------------------------------------ the shipped export

@pytest.fixture(scope="module")
def exported(rules):
    """rule id -> (the rule, the Sigma documents read back from the committed file)."""
    out = {}
    for rule in rules:
        path = SIGMA / f"{rule['id']}.yml"
        if path.exists():
            out[rule["id"]] = (rule, list(yaml.safe_load_all(path.read_text(encoding="utf-8"))))
    return out


def test_nineteen_of_thirty_two_rules_can_be_written_as_sigma(rules, exported):
    result = export_all(rules)
    assert len(result) == 32 and sorted(exported) == sorted(r for r, i in result.items() if i["status"] == "exported")
    assert len(exported) == 19


def test_every_document_has_what_a_sigma_rule_needs(exported):
    ids, names = set(), set()
    for rid, (rule, docs) in exported.items():
        for d in docs:
            assert d["title"] and d["description"] and d["author"] == "Detection Lab", rid
            assert d["status"] in ("stable", "experimental") and d["level"] in SIGMA_LEVELS, rid
            assert str(uuid.UUID(d["id"])) == d["id"], rid
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", d["date"]), rid
            assert re.fullmatch(r"detlab_det_\d{3}(_[a-z_]+)?", d["name"]), d["name"]
            assert d["falsepositives"] and all(isinstance(x, str) and x for x in d["falsepositives"]), rid
            assert ("detection" in d) != ("correlation" in d), rid
            assert ("logsource" in d) == ("detection" in d), rid
            assert d["id"] not in ids and d["name"] not in names, "ids and names are unique"
            ids.add(d["id"])
            names.add(d["name"])


def test_status_and_level_come_from_the_rule(exported):
    for rid, (rule, docs) in exported.items():
        for d in docs:
            assert d["status"] == rule["status"] and d["level"] == rule["severity"], rid


def test_the_tags_follow_the_attack_mapping_of_the_rule(exported):
    for rid, (rule, docs) in exported.items():
        att = rule["attack"]
        want = ["attack." + att["tactic"].lower().replace(" ", "-"), "attack." + att["technique"].lower(),
                *["attack." + t.lower() for t in att.get("also", [])]]
        for d in docs:
            assert d["tags"] == want, rid
            assert all(re.fullmatch(r"attack\.([a-z-]+|t\d{4}(\.\d{3})?)", t) for t in d["tags"]), d["tags"]


def test_the_ids_are_the_same_every_time_so_a_re_export_changes_nothing(rules, exported):
    assert export_all(rules) == export_all(rules)
    assert exported["DET-004"][1][0]["id"] == str(uuid.uuid5(NAMESPACE, "DET-004:process_create"))
    assert exported["DET-026"][1][1]["id"] == str(uuid.uuid5(NAMESPACE, "DET-026:corr"))
    assert [d["name"] for d in exported["DET-017"][1]] == ["detlab_det_017_log_clear", "detlab_det_017_audit_policy_change",
                                                         "detlab_det_017_process_create"]


def test_every_condition_names_things_that_exist_and_nothing_is_left_unused(exported):
    for rid, (rule, docs) in exported.items():
        for d in docs:
            det = d.get("detection")
            if det:
                defined = set(det) - {"condition"}
                used = set(re.findall(r"[A-Za-z_]\w*", det["condition"])) - {"and", "or", "not"}
                assert used == defined, (rid, used ^ defined)


def test_a_correlation_points_at_a_rule_in_the_same_file(exported):
    seen = 0
    for rid, (rule, docs) in exported.items():
        names = {d["name"] for d in docs}
        for d in docs:
            for ref in d.get("correlation", {}).get("rules", []):
                assert ref in names, rid
                seen += 1
    assert seen == 1                                        # DET-026 is the only counting rule that can be exported


def test_exclusions_are_listed_as_false_positives_and_never_change_the_logic(rules):
    result = export_all(rules)
    checked = 0
    for rule in rules:
        info = result[rule["id"]]
        if info["status"] != "exported":
            continue
        reasons = [" ".join(e["reason"].split()) for e in rule.get("exclusions") or []]
        for d in info["docs"]:
            for reason in reasons:
                assert any(fp.startswith("Known benign source at the lab site, not part of this export: ")
                           and fp.endswith(reason) for fp in d["falsepositives"]), rule["id"]
            checked += len(reasons)
        bare = export_rule({**rule, "exclusions": []})
        strip = lambda docs: [{k: v for k, v in d.items() if k != "falsepositives"} for d in docs]      # noqa: E731
        assert strip(info["docs"]) == strip(bare), f"{rule['id']}: an exclusion leaked into the exported logic"
    assert checked > 10


def test_a_rule_with_no_known_false_positives_says_unknown():
    assert export_rule(toy({"action": "process_create", "user": "a"}))[0]["falsepositives"] == ["Unknown"]


@pytest.mark.parametrize("rid,needle", [
    ("DET-001", "different products"), ("DET-002", "different products"), ("DET-003", "distance and time"),
    ("DET-005", "sequence"), ("DET-009", "single bits"), ("DET-022", "spread of the gaps"),
    ("DET-023", "sum of bytes"), ("DET-024", "'domain'"), ("DET-027", "baseline"), ("DET-030", "'outcome'")])
def test_each_rule_that_is_not_exported_says_why_in_plain_words(rules, rid, needle):
    info = export_all(rules)[rid]
    assert info["status"] == "not exported" and needle in info["reason"]


def test_no_reason_is_an_error_message_from_the_code(rules):
    for rid, info in export_all(rules).items():
        if info["status"] != "exported":
            assert len(info["reason"].split()) >= 8 and "Error" not in info["reason"] and "Traceback" not in info["reason"], rid


# ------------------------------------------------------------------ how each kind of condition is written

def test_a_list_of_program_names_becomes_endswith_with_a_backslash():
    doc = export({"action": "process_create", "process_name|in": ["a.exe", "b.exe"]})[0]
    assert doc["detection"] == {"selection_1": {"Image|endswith": ["\\a.exe", "\\b.exe"]}, "condition": "selection_1"}
    assert doc["logsource"] == {"category": "process_creation", "product": "windows"}


def test_one_program_name_is_a_single_value():
    doc = export({"action": "process_create", "process_name": "a.exe"})[0]
    assert doc["detection"]["selection_1"] == {"Image|endswith": "\\a.exe"}


def test_text_modifiers_and_plain_values():
    doc = export({"action": "process_create", "command_line|contains_all": ["a", "b"], "user": "eve",
                  "parent_process|endswith": "x.exe", "host|startswith": "WS-"})[0]
    assert doc["detection"]["selection_1"] == {"CommandLine|contains|all": ["a", "b"], "User": "eve",
                                               "ParentImage|endswith": "x.exe", "Computer|startswith": "WS-"}


def test_a_regex_flag_becomes_a_modifier():
    assert export({"action": "process_create", "command_line|regex": "(?i)abc"})[0]["detection"]["selection_1"] == \
        {"CommandLine|re|i": "abc"}
    assert export({"action": "powershell_scriptblock", "script_text|regex": "(?is)abc"})[0]["detection"]["selection_1"] == \
        {"ScriptBlockText|re|i|s": "abc"}
    assert export({"action": "process_create", "command_line|regex": "abc"})[0]["detection"]["selection_1"] == \
        {"CommandLine|re": "abc"}


def test_a_lookahead_regex_becomes_patterns_that_must_all_match_and_a_filter():
    det = export({"action": "process_create", "command_line|regex": "(?i)^(?=.*foo)(?=.*bar)(?!.*baz)"})[0]["detection"]
    assert det["selection_1"] == {"CommandLine|re|i|all": ["foo", "bar"]}
    assert det["filter_1_1"] == {"CommandLine|re|i": "baz"}
    assert det["condition"] == "(selection_1 and not filter_1_1)"


def test_two_negative_parts_become_one_not_with_or():
    det = export({"action": "process_create", "command_line|regex": "^(?=.*foo)(?!.*a)(?!.*b)"})[0]["detection"]
    assert det["condition"] == "(selection_1 and not (filter_1_1 or filter_1_2))"


def test_a_list_of_branches_means_or():
    det = export([{"action": "process_create", "user": "a"}, {"action": "process_create", "user": "b"}])[0]["detection"]
    assert det["condition"] == "selection_1 or selection_2" and det["selection_2"] == {"User": "b"}


def test_a_not_condition_becomes_a_filter():
    det = export({"action": "process_create", "user": "a", "not": {"parent_process": "explorer.exe"}})[0]["detection"]
    assert det["filter_1_1"] == {"ParentImage|endswith": "\\explorer.exe"}
    assert det["condition"] == "(selection_1 and not filter_1_1)"


def test_a_key_naming_several_fields_means_any_of_them():
    det = export({"action": "process_create", "process_name,original_name|in": ["a.exe", "b.exe"]})[0]["detection"]
    assert det["selection_1"] == {"Image|endswith": ["\\a.exe", "\\b.exe"]}
    assert det["selection_2"] == {"OriginalFileName": ["a.exe", "b.exe"]}
    assert det["condition"] == "selection_1 or selection_2"


def test_a_logon_outcome_chooses_the_event_id():
    assert export({"action": "host_logon", "outcome": "failure", "logon_type": 3})[0]["detection"]["selection_1"] == \
        {"EventID": 4625, "LogonType": 3}
    assert export({"action": "host_logon", "outcome": "success"})[0]["detection"]["selection_1"] == {"EventID": 4624}


def test_a_number_test_and_an_exists_test():
    sel = export({"action": "process_access", "granted_access|startswith": "0x1", "call_trace|exists": True})[0]["detection"]["selection_1"]
    assert sel == {"GrantedAccess|startswith": "0x1", "CallTrace|exists": True}


def test_events_of_several_kinds_become_several_documents():
    docs = export([{"action": "log_clear"}, {"action": "audit_policy_change"}])
    assert [d["title"] for d in docs] == ["Toy [log_clear]", "Toy [audit_policy_change]"]
    assert len({d["id"] for d in docs}) == 2 and len({d["name"] for d in docs}) == 2
    assert docs[0]["detection"]["selection_1"] == {"EventID": [1102, 104]}
    assert docs[1]["detection"]["selection_1"] == {"EventID": 4719}


def test_a_threshold_rule_becomes_a_detection_and_an_event_count_correlation():
    docs = export({"action": "process_create", "process_name": "a.exe"}, rtype="threshold",
                  group_by=["user", "host"], window_seconds=300, threshold=5)
    assert len(docs) == 2
    assert docs[1]["correlation"] == {"type": "event_count", "rules": [docs[0]["name"]], "group-by": ["User", "Computer"],
                                      "timespan": "5m", "condition": {"gte": 5}}


def test_a_distinct_threshold_rule_counts_values():
    docs = export({"action": "process_create", "process_name": "a.exe"}, rtype="distinct_threshold",
                  group_by=["user"], distinct_field="host", window_seconds=900, threshold=8)
    assert docs[1]["correlation"]["type"] == "value_count"
    assert docs[1]["correlation"]["condition"] == {"gte": 8, "field": "Computer"}
    assert docs[1]["correlation"]["timespan"] == "15m"


# ------------------------------------------------------------------ what the exporter refuses

@pytest.mark.parametrize("rule,needle", [
    (toy({"action": "process_access", "granted_access|bitany": ["0x10"]}), "single bits"),
    (toy({"action": "process_create", "integrity": "High"}), "no equivalent"),
    (toy({"action": "process_create", "gone": 1}), "no equivalent"),
    (toy({"action": "network_connect", "dst_port": 443}), "no Sigma log source"),
    (toy({"action": "process_create", "process_name": "a.exe", "process_path|endswith": "\\b.exe"}), "same Sigma field"),
    (toy({"action": "process_create", "process_name|startswith": "a"}), "start or the middle of the program name"),
    (toy({"action": "process_create", "process_name|contains": "a"}), "start or the middle of the program name"),
    (toy({"action": "process_create", "process_name|regex": "^a"}), "start or the middle of the program name"),
    (toy({"action": "process_create", "parent_process|contains_all": ["a", "b"]}), "start or the middle of the program name"),
    (toy({"user": "a"}), "does not say which kind of event"),
    (toy({"action": "process_create", "user": "a", "not": {"command_line|regex": "^(?=.*a)(?!.*b)"}}),
     "itself contains a lookahead"),
    (toy({"action": "process_create", "command_line|regex": "^(?!.*b)"}), "only says what must be absent"),
    (toy({"action": "login", "outcome": "failure"}, rtype="threshold", group_by=["user"], window_seconds=60, threshold=3),
     "different products"),
    (toy({"action": "process_create", "user": "a"}, rtype="threshold", group_by=["country"], window_seconds=60, threshold=3),
     "computed by the engine"),
    (toy({"action": "process_create", "user": "a"}, rtype="distinct_threshold", group_by=["user"], distinct_field="domain",
         window_seconds=60, threshold=3), "has no Sigma field"),
    (toy({"action": "process_create", "user": "a"}, rtype="flying"), "is not supported by the exporter"),
    (toy([{"action": "process_create", "user": "a"}, {"action": "registry_set", "user": "a"}], rtype="threshold",
         group_by=["user"], window_seconds=60, threshold=3), "several event kinds"),
])
def test_a_rule_that_sigma_cannot_say_is_refused_with_the_reason(rule, needle):
    with pytest.raises(NotExportable, match=needle):
        export_rule(rule)


@pytest.mark.parametrize("rtype", sorted(NOT_EXPORTED_TYPES))
def test_rule_types_that_need_a_baseline_a_sequence_or_statistics_are_refused(rtype):
    with pytest.raises(NotExportable) as info:
        export_rule(toy({"action": "login"}, rtype=rtype))
    assert str(info.value) == NOT_EXPORTED_TYPES[rtype]


def test_a_program_name_may_still_be_tested_with_equals_in_and_endswith():
    for op in ("", "|in", "|endswith"):
        assert export({"action": "process_create", f"process_name{op}": "a.exe"})


# ------------------------------------------------------------------ the index and writing the folder

def test_the_index_reports_what_each_converter_did():
    rules = [toy({"action": "process_create", "user": "a"}), toy({"action": "login"}, rtype="beaconing", id="DET-902")]
    result = export_all(rules)
    manifest = {"tools": {"splunk": {"pysigma": "9.9", "backend": "8.8"}},
                "rules": {"DET-901": {"splunk": {"status": "ok", "queries": 2, "notes": ["it was only partly converted"]},
                                      "kusto": {"status": "failed", "error": "Boom\nsecond line"}}}}
    text = render_index(rules, result, manifest)
    assert "1 of 2 rules are exported as Sigma" in text
    assert "Splunk with pySigma 9.9 and pysigma-backend-splunk 8.8" in text
    assert "2 queries (partial: it was only partly converted)" in text and "failed: Boom |" in text
    assert "| DET-902 | Toy | not exported | - | - |" in text
    assert "None of the queries has been run against a live Splunk or Sentinel instance" in text
    assert "pySigma" not in render_index(rules, result, {"tools": {}, "rules": {}})


def test_writing_the_folder_replaces_old_files_and_writes_an_index(rules, tmp_path):
    (tmp_path / "DET-999.yml").write_text("stale", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("keep me", encoding="utf-8")
    summary = write_sigma(rules, tmp_path)
    assert len(summary["exported"]) == 19 and len(summary["not_exported"]) == 13
    assert not (tmp_path / "DET-999.yml").exists() and (tmp_path / "notes.txt").read_text(encoding="utf-8") == "keep me"
    assert sorted(p.name for p in tmp_path.glob("DET-*.yml")) == sorted(f"{r}.yml" for r in summary["exported"])
    assert (tmp_path / "INDEX.md").read_text(encoding="utf-8").startswith("# Sigma export")


# ------------------------------------------------------------------ the drift check

def fresh(tmp_path):
    dest = tmp_path / "sigma"
    shutil.copytree(SIGMA, dest)
    return dest


def edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{old!r} is not in {path.name}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def change_manifest(dest, fn):
    path = dest / "queries" / "MANIFEST.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    fn(manifest)
    path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")


def test_the_committed_sigma_folder_matches_the_rules(rules):
    assert check_sigma(rules, SIGMA) == []


def test_a_copy_of_the_folder_is_in_sync_too(rules, tmp_path):
    assert check_sigma(rules, fresh(tmp_path)) == []


def test_a_rule_that_changed_after_its_sigma_file_was_made_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    changed = [{**r, "description": r["description"] + " Extra words."} if r["id"] == "DET-004" else r for r in rules]
    problems = check_sigma(changed, dest)
    assert "DET-004.yml no longer matches its rule (run: python -m detlab export-sigma)" in problems
    assert any("queries for DET-004 were made from an older Sigma file" in p for p in problems)


def test_a_change_to_a_rule_that_is_not_exported_and_not_in_the_index_changes_nothing(rules, tmp_path):
    changed = [{**r, "threshold": r["threshold"] + 5} if r["id"] == "DET-001" else r for r in rules]
    assert check_sigma(changed, fresh(tmp_path)) == []


def test_a_new_title_on_a_rule_that_is_not_exported_only_changes_the_index(rules, tmp_path):
    changed = [{**r, "title": "A new title"} if r["id"] == "DET-001" else r for r in rules]
    assert check_sigma(changed, fresh(tmp_path)) == ["INDEX.md is out of date (run: python -m detlab export-sigma)"]


def test_a_missing_sigma_file_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    (dest / "DET-004.yml").unlink()
    assert check_sigma(rules, dest) == ["DET-004.yml is missing (run: python -m detlab export-sigma)"]


def test_a_stray_sigma_file_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    (dest / "DET-999.yml").write_text("title: stray\n", encoding="utf-8")
    assert check_sigma(rules, dest) == ["DET-999.yml should not exist: that rule is not exported (run: python -m detlab export-sigma)"]


def test_a_sigma_file_edited_by_hand_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    edit(dest / "DET-006.yml", "level: critical", "level: low")
    problems = check_sigma(rules, dest)
    assert "DET-006.yml no longer matches its rule (run: python -m detlab export-sigma)" in problems


def test_an_index_edited_by_hand_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    with open(dest / "INDEX.md", "a", encoding="utf-8") as fh:
        fh.write("\nA sentence somebody added.\n")
    assert check_sigma(rules, dest) == ["INDEX.md is out of date (run: python -m detlab export-sigma)"]


def test_a_missing_index_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    (dest / "INDEX.md").unlink()
    assert check_sigma(rules, dest) == ["INDEX.md is out of date (run: python -m detlab export-sigma)"]


def test_a_query_edited_by_hand_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    with open(dest / "queries" / "splunk" / "DET-004.spl", "a", encoding="utf-8") as fh:
        fh.write("| where 1=1\n")
    assert check_sigma(rules, dest) == ["queries/splunk/DET-004.spl was edited by hand after it was made"]


def test_a_missing_query_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    (dest / "queries" / "kql" / "DET-004.kql").unlink()
    assert check_sigma(rules, dest) == ["queries/kql/DET-004.kql is missing"]


def test_a_query_that_failed_to_convert_has_no_file_and_is_not_reported_missing(rules):
    manifest = json.loads((SIGMA / "queries" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["rules"]["DET-029"]["kusto"]["status"] == "failed"
    assert not (SIGMA / "queries" / "kql" / "DET-029.kql").exists()
    assert check_sigma(rules, SIGMA) == []


def test_queries_made_from_an_older_sigma_file_are_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    change_manifest(dest, lambda m: m["rules"]["DET-004"].__setitem__("sigma_sha256", "0" * 64))
    assert check_sigma(rules, dest) == ["the Splunk and Sentinel queries for DET-004 were made from an older Sigma file: "
                                        "run tools/make_sigma_queries.py again"]


def test_an_exported_rule_with_no_manifest_entry_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    change_manifest(dest, lambda m: m["rules"].pop("DET-004"))
    problems = check_sigma(rules, dest)
    assert any(p.startswith("queries/MANIFEST.json has no entry for DET-004") for p in problems)


def test_a_manifest_entry_for_a_rule_that_is_not_exported_is_reported(rules, tmp_path):
    dest = fresh(tmp_path)
    change_manifest(dest, lambda m: m["rules"].__setitem__("DET-001", copy.deepcopy(m["rules"]["DET-004"])))
    assert check_sigma(rules, dest) == ["queries/MANIFEST.json lists DET-001, which is not an exported rule"]


def test_a_folder_that_does_not_exist_gives_problems_and_not_a_crash(rules, tmp_path):
    problems = check_sigma(rules, tmp_path / "nothing-here")
    assert "DET-004.yml is missing (run: python -m detlab export-sigma)" in problems
    assert "INDEX.md is out of date (run: python -m detlab export-sigma)" in problems
    assert sum(p.startswith("queries/MANIFEST.json has no entry") for p in problems) == 19


# ------------------------------------------------------------------ the hashes and the conversion results

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_the_manifest_hashes_match_the_files_on_disk():
    manifest = json.loads((SIGMA / "queries" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert len(manifest["rules"]) == 19
    for rid, entry in manifest["rules"].items():
        assert entry["sigma_sha256"] == sha256(SIGMA / f"{rid}.yml"), rid
        for key, folder, ext in (("splunk", "splunk", "spl"), ("kusto", "kql", "kql")):
            path = SIGMA / "queries" / folder / f"{rid}.{ext}"
            if entry[key]["status"] == "ok":
                assert sha256(path) == entry[key]["sha256"] and path.read_text(encoding="utf-8").strip(), (rid, key)
            else:
                assert not path.exists(), (rid, key)


def test_the_conversion_results_are_reported_as_they_are():
    manifest = json.loads((SIGMA / "queries" / "MANIFEST.json").read_text(encoding="utf-8"))
    ok = {k: sum(1 for e in manifest["rules"].values() if e[k]["status"] == "ok") for k in ("splunk", "kusto")}
    assert ok == {"splunk": 19, "kusto": 17}
    assert {rid for rid, e in manifest["rules"].items() if e["kusto"]["status"] != "ok"} == {"DET-021", "DET-029"}
    assert manifest["tools"] == {"splunk": {"pysigma": "2.0.2", "backend": "3.0.0"},
                                 "kusto": {"pysigma": "1.5.1", "backend": "1.0.1"}}
    index = (SIGMA / "INDEX.md").read_text(encoding="utf-8")
    assert "19 of 32 rules are exported as Sigma" in index and index.count("failed:") == 2 and "(partial:" in index
    assert "None of the queries has been run against a live Splunk or Sentinel instance" in index
    assert "pySigma 2.0.2" in index and "pySigma 1.5.1" in index


# ------------------------------------------------------------------ a separate reader of Sigma (tests the reader first)

def test_the_reader_applies_the_text_modifiers_the_way_sigma_does():
    rec = {"A": "Hello World", "N": 7}
    assert sr.field_matches(rec, "A", "hello world") and not sr.field_matches(rec, "A", "hello")
    assert sr.field_matches(rec, "A|contains", "O W") and sr.field_matches(rec, "A|startswith", "HELLO")
    assert sr.field_matches(rec, "A|endswith", "world") and not sr.field_matches(rec, "A|endswith", "hello")
    assert sr.field_matches(rec, "A|contains", ["zzz", "world"]) and not sr.field_matches(rec, "A|contains|all", ["zzz", "world"])
    assert sr.field_matches(rec, "A|contains|all", ["hello", "world"])
    assert not sr.field_matches(rec, "A|re", "hello") and sr.field_matches(rec, "A|re|i", "hello") and sr.field_matches(rec, "A|re", "H.llo")
    assert sr.field_matches(rec, "N", 7) and sr.field_matches(rec, "N|gte", 7) and not sr.field_matches(rec, "N|gt", 7)
    assert sr.field_matches(rec, "N|lt", "8") and not sr.field_matches(rec, "N|lte", 6)
    assert sr.field_matches(rec, "A|exists", True) and not sr.field_matches(rec, "B|exists", True) and sr.field_matches(rec, "B|exists", False)
    assert not sr.field_matches(rec, "B", "x") and not sr.field_matches(rec, "B|contains", "x")


def test_the_reader_evaluates_and_or_not_and_brackets():
    det = {"a": {"A": 1}, "b": {"B": 1}, "c": [{"C": 1}, {"D": 1}], "condition": ""}

    def ok(cond, **rec):
        return sr.condition_true({**det, "condition": cond}, rec)

    assert ok("a and b", A=1, B=1) and not ok("a and b", A=1)
    assert ok("a or b", B=1) and not ok("a or b")
    assert ok("a and not b", A=1) and not ok("a and not b", A=1, B=1)
    assert ok("(a or b) and c", B=1, D=1) and not ok("(a or b) and c", B=1)
    assert ok("a or b and c", A=1) and not ok("a or b and c", B=1), "and binds tighter than or"
    assert ok("not (a and b)", A=1) and ok("c", C=1) and ok("c", D=1)


@pytest.mark.parametrize("cond,needle", [("a and zzz", "does not define"), ("(a", "not closed"), ("a b", "left over")])
def test_the_reader_refuses_a_condition_it_cannot_read(cond, needle):
    with pytest.raises(ValueError, match=needle):
        sr.condition_true({"a": {"A": 1}, "condition": cond}, {"A": 1})


def test_a_lab_event_can_be_written_under_several_event_ids():
    ids = lambda ev: [r.get("EventID") for r in sr.records_for(ev)]      # noqa: E731
    assert ids({"action": "group_add"}) == [4728, 4732, 4756]
    assert ids({"action": "log_clear"}) == [1102, 104]
    assert ids({"action": "host_logon", "outcome": "success"}) == [4624] and ids({"action": "host_logon", "outcome": "failure"}) == [4625]
    assert ids({"action": "host_logon", "outcome": "locked"}) == [None], "an unknown outcome has no event id"
    assert ids({"action": "process_create"}) == [None] and sr.records_for({"action": "teleport"}) == []


def test_a_program_name_becomes_a_full_path_unless_the_event_has_one():
    rec = sr.records_for({"action": "process_create", "process_name": "a.exe", "parent_process": "b.exe",
                          "parent_path": "D:\\Apps\\b.exe"})[0]
    assert rec["Image"] == "C:\\Windows\\System32\\a.exe" and rec["ParentImage"] == "D:\\Apps\\b.exe"


def test_a_rule_that_catches_only_some_of_the_event_ids_gives_no_clear_answer():
    doc = {"name": "x", "logsource": {"product": "windows", "service": "security"},
           "detection": {"s": {"EventID": 4728}, "condition": "s"}}
    assert sr.sigma_event_matches([doc], {"action": "group_add"}) is None
    doc["detection"]["s"] = {"EventID": [4728, 4732, 4756]}
    assert sr.sigma_event_matches([doc], {"action": "group_add"}) is True
    doc["detection"]["s"] = {"EventID": 1}
    assert sr.sigma_event_matches([doc], {"action": "group_add"}) is False
    assert sr.sigma_event_matches([doc], {"action": "teleport"}) is False


def test_a_rule_for_one_log_source_does_not_read_events_of_another():
    doc = {"name": "x", "logsource": {"category": "process_creation", "product": "windows"},
           "detection": {"s": {"User": "eve"}, "condition": "s"}}
    assert sr.sigma_event_matches([doc], {"action": "process_create", "user": "eve"}) is True
    assert sr.sigma_event_matches([doc], {"action": "registry_set", "user": "eve"}) is False


def test_the_reader_counts_events_and_distinct_values_inside_a_window():
    logsource = {"product": "windows", "service": "security"}
    base = {"name": "b", "logsource": logsource, "detection": {"s": {"EventID": 4624}, "condition": "s"}}

    def events(n, gap, **extra):
        return [{"action": "host_logon", "outcome": "success", "user": "u", "host": f"H{i}", "_t": 1000.0 + i * gap, **extra}
                for i in range(n)]

    def count(gte, span, kind="event_count", **cond):
        return {"name": "c", "correlation": {"type": kind, "rules": ["b"], "group-by": ["TargetUserName"], "timespan": span,
                                             "condition": {"gte": gte, **cond}}}

    assert sr.sigma_fires([base, count(3, "20s")], events(3, 10)) is True, "three events 20 s apart fit a 20 s window"
    assert sr.sigma_fires([base, count(3, "19s")], events(3, 10)) is False
    assert sr.sigma_fires([base, count(4, "1h")], events(3, 10)) is False
    assert sr.sigma_fires([base, count(3, "1h", "value_count", field="Computer")], events(3, 10)) is True
    same_host = [{**e, "host": "H0"} for e in events(5, 10)]
    assert sr.sigma_fires([base, count(3, "1h", "value_count", field="Computer")], same_host) is False
    assert sr.sigma_fires([base, count(3, "1h")], same_host) is True
    other_users = [{**e, "user": f"u{i}"} for i, e in enumerate(events(5, 10))]
    assert sr.sigma_fires([base, count(2, "1h")], other_users) is False, "each account is counted on its own"
    assert sr.sigma_fires([base], events(1, 10)) is True


# ------------------------------------------------------------------ does the Sigma export mean what the rule means?

@pytest.fixture(scope="module")
def evidence(rules, dataset):
    """Every event the check can use: the rules' own test events, the made-up logs, and the real recordings."""
    manifest = rp.load_manifest(ROOT / "replay")
    real = []
    with zipfile.ZipFile(ROOT / "replay" / manifest["source"]["container"]) as container:
        for entry in manifest["datasets"]:
            real += rp.read_dataset(container, entry)
    unit = [e for rule in rules for case in rule["tests"] for e in expand_events(case["events"])]
    synthetic = dataset[0]
    return {"unit": unit, "synthetic": synthetic, "real": real, "pool": sr.field_pool([unit, synthetic, real])}


def test_for_every_unit_test_the_sigma_file_and_the_engine_agree_on_whether_it_fires(exported):
    """With the exclusions switched off on the engine side, because exclusions are not exported (see falsepositives)."""
    cases, fires, differ = 0, 0, []
    for rid, (rule, docs) in exported.items():
        for case in rule["tests"]:
            events = expand_events(case["events"])
            engine = len(run_rules(events, [rule], use_exclusions=False)) > 0
            cases += 1
            fires += engine
            if sr.sigma_fires(docs, events) != engine:
                differ.append(f"{rid}: {case['name']}")
    assert differ == []
    assert cases == 190 and fires == 126


def test_the_sigma_files_select_exactly_the_events_the_engine_selects(exported, evidence):
    """Every event of every source, against every exported rule: the same yes or no."""
    events = evidence["unit"] + evidence["synthetic"] + evidence["real"]
    assert len(events) == 74549
    differ, selected = [], 0
    for rid, (rule, docs) in exported.items():
        for ev in events:
            engine = matches(ev, rule["filter"])
            selected += engine
            if sr.sigma_event_matches(docs, ev) != engine:
                differ.append((rid, ev["event_id"]))
    assert differ == []
    assert selected == 1353, "the check is not empty: the rules select this many events in all"


def test_the_sigma_files_also_agree_on_events_built_from_each_rule_itself(exported, evidence):
    """For every listed value of every condition, one event that has it, and near misses with one condition broken."""
    total = selected = 0
    for rid, (rule, docs) in exported.items():
        witnesses = sr.witness_events(rule, evidence["pool"], _condition_ok)
        assert witnesses, rid
        for ev in witnesses:
            engine = matches(ev, rule["filter"])
            assert sr.sigma_event_matches(docs, ev) == engine, (rid, ev)
            total += 1
            selected += engine
    assert total == 260 and selected == 161


def proof_for(rule, evidence):
    """What is used to tell a damaged Sigma file from a good one: single events, and the rule's own test cases.

    Single events catch a wrong value, modifier or condition. Only a whole test case (several events with times)
    can catch a wrong count, window or grouping, because those are only seen over time.
    """
    events = (evidence["unit"] + sr.witness_events(rule, evidence["pool"], _condition_ok)
              + [e for e in evidence["synthetic"] + evidence["real"] if matches(e, rule["filter"])]
              + (evidence["synthetic"] + evidence["real"])[::25])
    cases = []
    for case in rule["tests"]:
        case_events = expand_events(case["events"])
        cases.append((case_events, len(run_rules(case_events, [rule], use_exclusions=False)) > 0))
    return {"events": [(e, matches(e, rule["filter"])) for e in events], "cases": cases}


def noticed(docs, proof):
    """True when the Sigma documents give a different answer from the engine for something in the proof."""
    if any(sr.sigma_event_matches(docs, e) != engine for e, engine in proof["events"]):
        return True
    return any(sr.sigma_fires(docs, events) != engine for events, engine in proof["cases"])


def damaged(docs, doc_index, path, value):
    out = copy.deepcopy(docs)
    node = out[doc_index]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return out


def without_all(docs, doc_index, key):
    """The same documents with the |all modifier taken off one key (patterns that must ALL match become ANY)."""
    out = copy.deepcopy(docs)
    sel = out[doc_index]["detection"]["selection_1"]
    out[doc_index]["detection"]["selection_1"] = {(k.replace("|all", "") if k == key else k): v for k, v in sel.items()}
    return out


@pytest.mark.parametrize("rid,doc_index,path,value", [
    ("DET-004", 0, ["detection", "selection_1", "Image|endswith"], ["\\powershellx.exe", "\\pwsh.exe"]),
    ("DET-004", 0, ["detection", "selection_1", "CommandLine|re|i"], "\\s-e\\s+[A-Za-z0-9+/=]{20,}"),
    ("DET-006", 0, ["detection", "selection_1", "EventID"], [4728, 4732]),
    ("DET-006", 0, ["detection", "selection_1", "TargetUserName"], ["Domain Admins"]),
    ("DET-019", 1, ["detection", "condition"], "selection_1 or selection_2"),
    ("DET-020", 0, ["detection", "selection_1", "ParentImage|endswith"], ["\\wmiprvse.exe"]),
    ("DET-026", 1, ["correlation", "condition", "gte"], 7),
    ("DET-026", 1, ["correlation", "condition", "gte"], 9),
    ("DET-026", 1, ["correlation", "timespan"], "16m"),
    ("DET-026", 1, ["correlation", "timespan"], "14m"),
    ("DET-026", 1, ["correlation", "group-by"], ["TargetUserName"]),
    ("DET-026", 1, ["correlation", "condition", "field"], "IpAddress"),
    ("DET-029", 0, ["detection", "selection_1", "eventName"], ["StopLogging", "DeleteTrail"]),
])
def test_the_comparison_notices_when_a_sigma_file_is_damaged(exported, evidence, rid, doc_index, path, value):
    rule, docs = exported[rid]
    bad = damaged(docs, doc_index, path, value)
    assert bad != docs
    proof = proof_for(rule, evidence)
    assert not noticed(docs, proof), "the good file passes"
    assert noticed(bad, proof), f"{rid}: damage to {path} went unnoticed"


def test_the_comparison_notices_patterns_that_must_all_match_turned_into_any(exported, evidence):
    rule, docs = exported["DET-013"]
    key = next(k for k in docs[0]["detection"]["selection_1"] if k.endswith("|all"))
    proof = proof_for(rule, evidence)
    assert not noticed(docs, proof) and noticed(without_all(docs, 0, key), proof)


def test_the_comparison_notices_a_lost_flag_and_a_wrong_log_source(exported, evidence):
    rule, docs = exported["DET-010"]
    no_flag = copy.deepcopy(docs)
    for sel in no_flag[0]["detection"].values():
        if isinstance(sel, dict) and "CommandLine|re|i" in sel:
            sel["CommandLine|re"] = sel.pop("CommandLine|re|i")
    assert noticed(no_flag, proof_for(rule, evidence)), "a lost (?i) flag changes which command lines match"
    rule, docs = exported["DET-007"]
    other_source = copy.deepcopy(docs)
    other_source[0]["logsource"] = {"category": "registry_set", "product": "windows"}
    assert noticed(other_source, proof_for(rule, evidence))


def test_most_one_step_edits_to_the_exported_files_are_noticed(exported, evidence):
    """Delete one condition, or drop one listed value, in every exported file: how many does the comparison see?

    Measured: 170 of 215 (79 percent), the number quoted in the documentation. The 45 it does not see are edits that
    no event in the comparison pulls apart: six are EventID conditions that the lab's event kinds make redundant, and
    the rest are alternatives inside regular expressions and the file-name branches of a rule, which would need an
    event the comparison does not contain. They were not chased. This is a check of the check: it tells how much
    weight the "0 disagreements" result can carry, and it is not a claim that the export is perfect.
    """
    edits = caught = 0
    missed = []
    proofs = {rid: proof_for(rule, evidence) for rid, (rule, _) in exported.items()}
    for rid, (rule, docs) in exported.items():
        for di, doc in enumerate(docs):
            for name, sel in (doc.get("detection") or {}).items():
                if name == "condition":
                    continue
                for key in list(sel):
                    tries = [("key", None)]
                    if isinstance(sel[key], list) and len(sel[key]) > 1:
                        tries += [("value", i) for i in range(len(sel[key]))]
                    for kind, index in tries:
                        bad = copy.deepcopy(docs)
                        target = bad[di]["detection"][name]
                        if kind == "key":
                            del target[key]
                            if not target:
                                target["EventID"] = -1
                        else:
                            del target[key][index]
                        edits += 1
                        if noticed(bad, proofs[rid]):
                            caught += 1
                        else:
                            missed.append((rid, name, key, kind, index))
    assert edits == 215
    assert caught == 170, f"{caught} of {edits} edits noticed (measured: 170); not noticed: {missed}"
