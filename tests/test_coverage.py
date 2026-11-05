"""ATT&CK coverage: the data file, the four levels, the matrix, the text report and the group gaps."""

import json

import pytest

from detlab import coverage as cv
from detlab.cli import main


def rule(rid, technique, also=(), title="A rule"):
    return {"id": rid, "title": title, "attack": {"tactic": "Execution", "technique": technique, "also": list(also)}}


# ------------------------------------------------------------------ the data file

def test_the_data_file_is_the_reduced_attack_enterprise_release():
    a = cv.load_attack()
    assert a["source"]["name"] == "MITRE ATT&CK Enterprise" and a["source"]["version"] == "20.0"
    assert len(a["source"]["stix_sha256"]) == 64 and a["source"]["built_by"] == "tools/build_attack_data.py"
    assert "registered trademarks of The MITRE Corporation" in a["notice"] and "Terms of Use" in a["notice"]
    assert len(a["tactics"]) == 15 and len(a["techniques"]) == 706 and len(a["groups"]) == 174
    assert sum(1 for t in a["techniques"].values() if not t["p"]) == 227


def test_every_technique_names_a_real_parent_and_real_tactics():
    a = cv.load_attack()
    tactics = {t["short"] for t in a["tactics"]}
    for tid, t in a["techniques"].items():
        assert t["n"] and t["t"] and set(t["t"]) <= tactics, tid
        if t["p"]:
            assert a["techniques"][t["p"]]["p"] is None, f"{tid}: a parent is never itself a sub-technique"
            assert tid.startswith(t["p"] + "."), tid


def test_every_revoked_technique_leads_to_a_current_one_and_every_group_technique_exists():
    a = cv.load_attack()
    for old, new in a["revoked_by"].items():
        assert old not in a["techniques"] and cv.resolve(a, old) in a["techniques"], old
    assert all(t in a["techniques"] for g in a["groups"] for t in g["techniques"])


def test_the_data_is_loaded_once():
    assert cv.load_attack() is cv.load_attack()


def test_a_revoked_technique_is_followed_to_the_one_that_replaced_it():
    a = {"revoked_by": {"T1": "T2", "T2": "T3"}}
    assert cv.resolve(a, "T1") == "T3" and cv.resolve(a, "T3") == "T3"


def test_a_loop_of_replacements_does_not_hang():
    assert cv.resolve({"revoked_by": {"T1": "T2", "T2": "T1"}}, "T1") in ("T1", "T2")


# ------------------------------------------------------------------ the mapping of the rules

def test_the_shipped_rules_only_name_current_techniques(rules):
    assert cv.rule_mapping_problems(rules) == []


def test_a_misspelled_or_unknown_technique_is_reported():
    assert cv.rule_mapping_problems([rule("DET-901", "T9999")]) == ["DET-901: T9999 is not a current ATT&CK technique"]
    assert cv.rule_mapping_problems([rule("DET-902", "T1059", also=["T1059.999"])]) == \
        ["DET-902: T1059.999 is not a current ATT&CK technique"]


def test_a_revoked_technique_is_reported_with_its_replacement():
    old, new = next(iter(cv.load_attack()["revoked_by"].items()))
    assert cv.rule_mapping_problems([rule("DET-903", old)]) == \
        [f"DET-903: {old} is not a current ATT&CK technique (replaced by {cv.resolve(cv.load_attack(), old)})"]


# ------------------------------------------------------------------ the four levels

def levels(rules, lab=(), real=()):
    cov = cv.compute(rules, set(lab), set(real))
    out = {}
    for col in cov["columns"]:
        for c in col["cells"]:
            out[c["id"]] = c["level"]
            for s in c["subs"]:
                out[s["id"]] = s["level"]
    return cov, out


def test_with_no_rules_nothing_is_covered():
    cov, lv = levels([])
    assert set(lv.values()) == {0}
    assert cov["summary"] == {"mapped_ids": 0, "by_level": {1: 0, 2: 0, 3: 0}, "parents_with_any": 0, "parents": 227, "rules": 0}


def test_a_rule_that_only_lists_a_technique_maps_it_at_level_one():
    _, lv = levels([rule("DET-901", "T1059.001")])
    assert lv["T1059.001"] == 1 and lv["T1059"] == 0


def test_the_main_technique_of_a_rule_that_caught_a_lab_attack_is_level_two():
    _, lv = levels([rule("DET-901", "T1059.001")], lab={"DET-901"})
    assert lv["T1059.001"] == 2


def test_the_main_technique_of_a_rule_that_fired_on_a_real_recording_is_level_three():
    _, lv = levels([rule("DET-901", "T1059.001")], lab={"DET-901"}, real={"DET-901"})
    assert lv["T1059.001"] == 3
    _, lv = levels([rule("DET-901", "T1059.001")], real={"DET-901"})
    assert lv["T1059.001"] == 3, "a rule seen on a real recording counts even if the lab run did not use it"


def test_a_technique_listed_under_also_is_never_more_than_mapped():
    _, lv = levels([rule("DET-901", "T1059.001", also=["T1204.002"])], lab={"DET-901"}, real={"DET-901"})
    assert lv["T1059.001"] == 3 and lv["T1204.002"] == 1


def test_the_highest_level_among_the_rules_wins():
    rules = [rule("DET-901", "T1059.001"), rule("DET-902", "T1059.001"), rule("DET-903", "T1059.001", also=["T1204.002"])]
    _, lv = levels(rules, lab={"DET-902"}, real=set())
    assert lv["T1059.001"] == 2
    _, lv = levels(rules, lab={"DET-902"}, real={"DET-901"})
    assert lv["T1059.001"] == 3


def test_a_technique_that_is_not_in_the_data_is_left_out_of_the_counts():
    cov, _ = levels([rule("DET-901", "T9999", also=["T1059.001"])])
    assert cov["summary"]["mapped_ids"] == 1 and cov["problems"] == ["DET-901: T9999 is not a current ATT&CK technique"]


def test_a_parent_with_a_mapped_sub_technique_counts_as_covered_but_stays_at_level_zero_itself():
    cov, lv = levels([rule("DET-901", "T1059.001")])
    cell = next(c for col in cov["columns"] for c in col["cells"] if c["id"] == "T1059")
    assert cell["level"] == 0 and cell["best"] == 1 and cell["subs_mapped"] == 1
    assert cell["subs_total"] == len(cell["subs"]) > 1 and cell["rules"] == []
    assert next(s for s in cell["subs"] if s["id"] == "T1059.001")["rules"] == ["DET-901"]
    assert cov["summary"]["parents_with_any"] == 1


def test_the_same_technique_listed_twice_by_one_rule_is_counted_once():
    cov, _ = levels([rule("DET-901", "T1059.001", also=["T1059.001"])])
    assert cov["summary"]["mapped_ids"] == 1 and cov["summary"]["by_level"] == {1: 1, 2: 0, 3: 0}


# ------------------------------------------------------------------ the matrix

def test_the_matrix_has_one_column_per_tactic_and_every_parent_at_least_once(lab):
    cov = lab.coverage
    a = cv.load_attack()
    assert [c["short"] for c in cov["columns"]] == [t["short"] for t in a["tactics"]]
    cells = [c["id"] for col in cov["columns"] for c in col["cells"]]
    assert len(cells) == 259 and len(set(cells)) == 227
    for col in cov["columns"]:
        names = [c["name"].lower() for c in col["cells"]]
        assert names == sorted(names), f"{col['name']}: cells are in name order"
        assert col["mapped"] == sum(1 for c in col["cells"] if c["best"] > 0)
        for c in col["cells"]:
            assert all(s["id"].startswith(c["id"] + ".") for s in c["subs"])
            assert 0 <= c["subs_mapped"] <= c["subs_total"] == len(c["subs"])
            assert c["best"] == max([c["level"], *[s["level"] for s in c["subs"]]])


def test_the_shipped_rules_cover_this_much_of_attack_and_the_levels_are_measured(lab):
    cov = lab.coverage
    assert cov["summary"] == {"mapped_ids": 48, "by_level": {1: 21, 2: 13, 3: 14}, "parents_with_any": 28,
                              "parents": 227, "rules": 32}
    assert cov["attack"]["version"] == "20.0" and cov["attack"]["techniques"] == 706 and cov["attack"]["groups"] == 174
    assert cov["problems"] == []
    assert cov["levels"] == {0: "no rule", 1: "mapped", 2: "exercised in the lab", 3: "seen in a real recording"}


def test_the_levels_come_from_what_happened_and_not_from_the_rule_text(lab):
    """A level of 2 or 3 needs a rule that caught something. Re-computing with nothing caught must give level 1 only."""
    cov = cv.compute(lab.rules, set(), set())
    assert cov["summary"]["by_level"] == {1: cov["summary"]["mapped_ids"], 2: 0, 3: 0}


# ------------------------------------------------------------------ groups

def test_a_group_is_found_by_name_or_alias_in_any_letter_case(lab):
    cov = lab.coverage
    by_name = cv.group_gaps(cov, "apt29")
    by_alias = cv.group_gaps(cov, "iron ritual")
    assert by_name["name"] == "APT29" and by_alias["id"] == by_name["id"]


def test_an_unknown_group_gives_none(lab):
    assert cv.group_gaps(lab.coverage, "No Such Group") is None


def test_the_gaps_are_the_techniques_with_no_rule_and_are_limited(lab):
    gap = cv.group_gaps(lab.coverage, "APT29", limit=5)
    assert len(gap["gaps"]) == 5 and gap["gap_count"] == gap["total"] - gap["mapped"] > 5
    assert gap["share"] == pytest.approx(gap["mapped"] / gap["total"])
    names = cv.load_attack()["techniques"]
    assert all(names[tid]["n"] == name and gap["techniques"][tid] == 0 for tid, name in gap["gaps"])
    assert (gap["total"], gap["mapped"]) == (66, 14)


def test_a_group_with_no_technique_in_the_data_has_a_share_of_zero():
    cov = cv.compute([], set(), set())
    assert all(g["share"] == 0.0 for g in cov["groups"])
    cov["groups"].append({"id": "G0", "name": "Empty", "aliases": [], "total": 0, "mapped": 0, "share": 0.0, "techniques": {}})
    assert cv.group_gaps(cov, "empty")["gaps"] == []


# ------------------------------------------------------------------ the text report and the command

def test_the_text_report_says_what_it_measures_and_what_it_does_not(lab):
    text = cv.render_text(lab.coverage)
    assert text.startswith("ATT&CK v20.0 (modified 2026-10-13): 28 of 227 techniques have a rule (12%).")
    assert "48 technique IDs are mapped by 32 rules: 14 seen in a real recording, 13 exercised in the lab, 21 only mapped." in text
    assert "Coverage is a map of where to look, not a score for how safe a network is." in text
    for col in lab.coverage["columns"]:
        assert col["name"] in text
    assert "Problems:" not in text and "uses" not in text


def test_the_text_report_lists_problems_and_the_gaps_of_a_group(lab):
    cov = {**lab.coverage, "problems": ["DET-901: T9999 is not a current ATT&CK technique"]}
    text = cv.render_text(cov, cv.group_gaps(cov, "APT29", limit=3))
    assert "Problems:\n  DET-901: T9999 is not a current ATT&CK technique" in text
    assert "APT29 uses 66 techniques and sub-techniques; 14 have a rule (21%), 52 do not. First gaps:" in text
    assert text.rstrip().count("\n  T1") == 3


def test_the_text_report_survives_an_empty_matrix():
    cov = cv.compute([], set(), set())
    assert "0 of 227 techniques have a rule (0%)" in cv.render_text(cov)
    assert cv.render_text({**cov, "summary": {**cov["summary"], "parents": 0, "parents_with_any": 0}}).startswith("ATT&CK v20.0")


def test_the_coverage_command_prints_the_report(capsys):
    assert main(["coverage"]) == 0
    out = capsys.readouterr().out
    assert "28 of 227 techniques have a rule (12%)" in out and "Tactic" in out


def test_the_coverage_command_can_print_the_gaps_of_a_group(capsys):
    assert main(["coverage", "--group", "APT29", "--limit", "2"]) == 0
    out = capsys.readouterr().out
    assert "APT29 uses 66 techniques" in out and out.count("\n  T1") == 2


def test_the_coverage_command_can_print_json(capsys):
    assert main(["coverage", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["parents_with_any"] == 28 and data["group"] is None and len(data["tactics"]) == 15
    assert data["tactics"][0] == {"name": "Reconnaissance", "with_a_rule": 0, "techniques": 12}


def test_the_coverage_command_fails_for_an_unknown_group_and_a_missing_folder(capsys, tmp_path):
    assert main(["coverage", "--group", "No Such Group"]) == 1
    assert "No group named 'No Such Group' in ATT&CK v20.0." in capsys.readouterr().out
    assert main(["coverage", "--rules", str(tmp_path / "nothing")]) == 1
    assert "I cannot find the rules folder" in capsys.readouterr().out
