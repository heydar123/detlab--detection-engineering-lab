"""The command line: every command, and what a beginner sees when something is wrong (a wrong folder, a missing file)."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from detlab.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = ["validate", "test-rules", "replay", "generate", "detect", "run", "case", "cases", "evasion", "export-sigma",
            "coverage", "export-site", "app"]


def lines(capsys):
    return capsys.readouterr().out


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    """A made-up dataset on disk with the alerts of the shipped rules: generate, then detect."""
    folder = tmp_path_factory.mktemp("data")
    assert main(["generate", "--out", str(folder)]) == 0
    assert main(["detect", "--data", str(folder), "--out", str(folder)]) == 0
    return folder


@pytest.fixture()
def rules_copy(tmp_path):
    folder = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", folder)
    return folder


# ------------------------------------------------------------------ the parser

def test_every_command_is_listed_and_a_command_is_required(capsys):
    parser = build_parser()
    choices = next(a for a in parser._actions if a.dest == "command").choices
    assert sorted(choices) == sorted(COMMANDS)
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2
    with pytest.raises(SystemExit) as info:
        main(["no-such-command"])
    assert info.value.code == 2


def test_the_module_can_be_started_the_way_the_instructions_say():
    done = subprocess.run([sys.executable, "-m", "detlab", "validate"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0 and done.stdout.strip() == "OK: 32 rules valid", done.stderr


# ------------------------------------------------------------------ validate

def test_validate_accepts_the_shipped_rules(capsys):
    assert main(["validate"]) == 0
    assert lines(capsys) == "OK: 32 rules valid\n"


def test_validate_lists_every_problem_it_finds(rules_copy, capsys):
    path = rules_copy / "DET-004.yml"
    path.write_text(path.read_text(encoding="utf-8").replace("severity: high", "severity: urgent", 1), encoding="utf-8")
    assert main(["validate", "--rules", str(rules_copy)]) == 1
    out = lines(capsys)
    assert out.startswith("Rule validation FAILED:\n  - ") and "DET-004" in out and "severity" in out


def test_a_wrong_folder_is_explained_and_not_a_traceback(tmp_path, capsys):
    assert main(["validate", "--rules", str(tmp_path / "nothing-here")]) == 1
    out = lines(capsys)
    assert out.startswith("I cannot find the rules folder") and "Open the detection-lab folder first" in out
    assert "Traceback" not in out


def test_an_empty_folder_is_not_reported_as_valid(tmp_path, capsys):
    assert main(["validate", "--rules", str(tmp_path)]) == 1
    assert "There are no rule files (*.yml)" in lines(capsys)


def test_a_rule_file_with_broken_yaml_is_named_with_its_line(rules_copy, capsys):
    (rules_copy / "DET-004.yml").write_text("id: DET-004\ntitle: [unclosed\n", encoding="utf-8")
    assert main(["validate", "--rules", str(rules_copy)]) == 1
    out = lines(capsys)
    assert out.startswith("DET-004.yml is not valid YAML (line ") and "Traceback" not in out


@pytest.mark.parametrize("text", ["", "- a\n- b\n", "just words\n"])
def test_a_rule_file_that_is_not_a_list_of_name_value_lines_is_named(rules_copy, capsys, text):
    (rules_copy / "DET-004.yml").write_text(text, encoding="utf-8")
    assert main(["validate", "--rules", str(rules_copy)]) == 1
    assert "DET-004.yml: a rule file must be a list of 'name: value' lines" in lines(capsys)


@pytest.mark.parametrize("command", [["test-rules"], ["detect"], ["evasion"], ["export-sigma"], ["export-sigma", "--check"],
                                     ["replay"], ["run"], ["case", "--user", "x"]])
def test_every_command_that_reads_rules_explains_a_wrong_rules_folder(command, tmp_path, capsys):
    assert main([*command, "--rules", str(tmp_path / "nothing-here")]) == 1
    assert lines(capsys).startswith("I cannot find the rules folder")


def test_the_case_command_checks_the_rules_folder_before_it_looks_for_logs_so_the_result_does_not_depend_on_earlier_runs(
        tmp_path, capsys):
    """A fresh copy of the project has no build/ folder yet, and that is the state continuous integration starts in."""
    empty = tmp_path / "no-logs-here"
    assert main(["case", "--user", "x", "--data", str(empty), "--rules", str(tmp_path / "nothing-here")]) == 1
    assert lines(capsys).startswith("I cannot find the rules folder")
    assert main(["case", "--user", "x", "--data", str(empty)]) == 1
    assert lines(capsys) == (f"I cannot find {empty / 'events.jsonl'}. Make the logs first with: python -m detlab run --out {empty}\n")


# ------------------------------------------------------------------ test-rules

def test_test_rules_can_list_every_test(capsys):
    assert main(["test-rules", "--rule", "DET-004", "-v"]) == 0
    out = lines(capsys)
    assert out.count("    PASS  [") == 8 and "FAIL" not in out
    assert "8 of 8 rule tests passed across 1 rules." in out and "1 of 1 exclusions are proven by a test" in out


def test_test_rules_says_so_when_there_is_nothing_to_run(capsys):
    assert main(["test-rules", "--rule", "DET-999"]) == 1
    assert lines(capsys) == "No tests found for DET-999.\n"


def test_test_rules_stops_when_the_rules_are_invalid(rules_copy, capsys):
    path = rules_copy / "DET-004.yml"
    path.write_text(path.read_text(encoding="utf-8").replace("severity: high", "severity: urgent", 1), encoding="utf-8")
    assert main(["test-rules", "--rules", str(rules_copy)]) == 1
    assert lines(capsys).startswith("Rule validation FAILED:")


# ------------------------------------------------------------------ generate, detect, case, cases

def test_generate_writes_the_logs_and_the_answer_key(data):
    assert sorted(p.name for p in data.iterdir()) == ["alerts.jsonl", "events.jsonl", "ground_truth.json"]
    assert len((data / "events.jsonl").read_text(encoding="utf-8").splitlines()) == 11865
    truth = json.loads((data / "ground_truth.json").read_text(encoding="utf-8"))
    assert set(truth) == {"meta", "scenarios"} and len(truth["scenarios"]) == 13


def test_generate_refuses_too_few_days_in_plain_words(tmp_path, capsys):
    assert main(["generate", "--out", str(tmp_path), "--days", "7"]) == 1
    out = lines(capsys)
    assert out == "I cannot make the logs: days must be at least 14 so every attack scenario fits.\n"
    assert list(tmp_path.iterdir()) == []


def test_generate_prints_how_much_it_wrote(tmp_path, capsys):
    assert main(["generate", "--out", str(tmp_path), "--seed", "3"]) == 0
    out = lines(capsys)
    assert re.fullmatch(rf"Wrote \d+ events and ground truth to {re.escape(str(tmp_path))}/\n", out), out


def test_detect_writes_the_alerts_and_scores_them(data, capsys):
    assert main(["detect", "--data", str(data), "--out", str(data)]) == 0
    out = lines(capsys)
    assert out.startswith("54 alerts written to ") and "Rule     Alerts   TP   FP  Precision   Recall  Title" in out
    assert "\nALL" in out and len((data / "alerts.jsonl").read_text(encoding="utf-8").splitlines()) == 54


def test_detect_without_the_documented_exclusions_raises_more_alerts(data, tmp_path, capsys):
    assert main(["detect", "--data", str(data), "--out", str(tmp_path), "--no-exclusions"]) == 0
    assert lines(capsys).startswith("143 alerts written to ")


def test_detect_without_an_answer_key_only_counts_the_alerts(data, tmp_path, capsys):
    folder = tmp_path / "logs"
    folder.mkdir()
    shutil.copy(data / "events.jsonl", folder / "events.jsonl")
    assert main(["detect", "--data", str(folder), "--out", str(folder)]) == 0
    out = lines(capsys)
    assert out == f"54 alerts written to {folder / 'alerts.jsonl'}\n"


def test_detect_and_case_and_cases_explain_a_missing_dataset(tmp_path, capsys):
    missing = str(tmp_path / "nothing")
    assert main(["detect", "--data", missing]) == 1
    assert lines(capsys) == (f"I cannot find {Path(missing) / 'events.jsonl'}. "
                             f"Make the logs first with: python -m detlab generate --out {missing}\n")
    assert main(["case", "--user", "adm.rossi", "--data", missing]) == 1
    assert "I cannot find" in lines(capsys)
    assert main(["cases", "--data", missing]) == 1
    assert lines(capsys) == (f"I cannot find {Path(missing) / 'alerts.jsonl'}. "
                             f"Make the alerts first with: python -m detlab run --out {missing}\n")


def test_case_prints_the_case_file_of_one_account(data, capsys):
    assert main(["case", "--user", "adm.rossi", "--data", str(data)]) == 0
    out = lines(capsys)
    assert out.startswith("# Incident case file: `adm.rossi`") and "Every name, IP, and host in this file is fictional." in out
    assert "Highest severity: **critical**" in out


def test_case_can_write_the_file_instead(data, tmp_path, capsys):
    target = tmp_path / "case.md"
    assert main(["case", "--user", "adm.rossi", "--data", str(data), "--out", str(target)]) == 0
    assert lines(capsys) == f"Case file written to {target}\n"
    assert target.read_text(encoding="utf-8").startswith("# Incident case file: `adm.rossi`")


def test_cases_groups_the_alerts_into_incident_cases(data, capsys):
    assert main(["cases", "--data", str(data)]) == 0
    out = lines(capsys)
    assert out.startswith("54 alerts grouped into 14 incident cases") and "CASE-001" in out


# ------------------------------------------------------------------ evasion

def test_evasion_refuses_too_few_days_in_plain_words(tmp_path, capsys):
    assert main(["evasion", "--out", str(tmp_path), "--days", "3"]) == 1
    assert lines(capsys) == "I cannot make the logs: days must be at least 14 so every attack scenario fits.\n"


# ------------------------------------------------------------------ export-sigma

def test_export_sigma_writes_the_files_and_names_what_it_cannot_express(tmp_path, capsys):
    out_dir = tmp_path / "sigma"
    assert main(["export-sigma", "--out", str(out_dir)]) == 0
    out = lines(capsys)
    assert f"Wrote 19 Sigma files and INDEX.md to {out_dir}/" in out
    assert "13 rules are not exported (Sigma cannot express them):" in out
    assert "  DET-005  " in out and "does not rewrite them" in out
    assert len(list(out_dir.glob("DET-*.yml"))) == 19 and (out_dir / "INDEX.md").is_file()


def test_export_sigma_check_passes_on_the_committed_folder(capsys):
    assert main(["export-sigma", "--check"]) == 0
    assert lines(capsys) == ("OK: sigma/ matches the 32 rules (Sigma files, INDEX.md and the hashes of the SIEM queries)\n")


def test_export_sigma_check_fails_and_names_the_file_when_a_rule_changed(rules_copy, capsys):
    path = rules_copy / "DET-004.yml"
    path.write_text(path.read_text(encoding="utf-8").replace("severity: high", "severity: critical", 1), encoding="utf-8")
    assert main(["export-sigma", "--rules", str(rules_copy), "--check"]) == 1
    out = lines(capsys)
    assert out.startswith("sigma/ does not match the rules:\n  DET-004.yml no longer matches its rule")


def test_export_sigma_check_changes_nothing_on_disk(tmp_path, capsys):
    before = {p.name: p.read_bytes() for p in (ROOT / "sigma").glob("*") if p.is_file()}
    assert main(["export-sigma", "--check"]) == 0
    assert before == {p.name: p.read_bytes() for p in (ROOT / "sigma").glob("*") if p.is_file()}


def test_export_sigma_stops_when_the_rules_are_invalid(rules_copy, tmp_path, capsys):
    path = rules_copy / "DET-004.yml"
    path.write_text(path.read_text(encoding="utf-8").replace("severity: high", "severity: urgent", 1), encoding="utf-8")
    assert main(["export-sigma", "--rules", str(rules_copy), "--out", str(tmp_path / "s")]) == 1
    assert lines(capsys).startswith("Rule validation FAILED:") and not (tmp_path / "s").exists()
