"""Replaying real public attack recordings: the protocol that keeps the result honest, and the arithmetic of the result."""

import hashlib
import io
import json
import re
import shutil
import zipfile
from pathlib import Path

import pytest

from detlab import replay as rp
from detlab.cli import main
from detlab.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "replay"
ATTACK = {"tactic": "Credential Access", "technique": "T1003", "technique_name": "OS Credential Dumping"}


def toy(rule_id, filt, **kw):
    base = {"id": rule_id, "title": rule_id, "status": "experimental", "severity": "low", "attack": ATTACK,
            "description": "toy", "type": "match", "filter": filt, "entity_fields": ["host"],
            "triage": ["x"], "response": ["y"]}
    base.update(kw)
    return base


NTDS = toy("DET-901", {"action": "process_create", "process_name": "ntdsutil.exe"})
SCRIPTS = toy("DET-902", {"action": "powershell_scriptblock", "script_text|contains": "mimikatz"})


def raw_process(t, image, **extra):
    return {"@timestamp": t, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Hostname": "WIN10",
            "User": "CORP\\bob", "Image": f"C:\\Windows\\System32\\{image}", "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": image, **extra}


def raw_script(t, text):
    return {"@timestamp": t, "Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104, "Hostname": "WIN10",
            "ScriptBlockText": text}


def make_container(raw_events):
    """A container zip holding one recording, the way replay/otrf-datasets.zip holds the real ones."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("recording.json", "\n".join(json.dumps(e) for e in raw_events))
    data = inner.getvalue()
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("rec.zip", data)
    entry = {"id": "rec", "file": "rec.zip", "sha256": hashlib.sha256(data).hexdigest(), "split": "dev",
             "title": "a made-up recording", "attack": ["T1003"], "expect": ["DET-901", "DET-902"]}
    return zipfile.ZipFile(io.BytesIO(outer.getvalue())), entry


LABELS = {"rec": {"attack": [{"action": "process_create", "process_name": "ntdsutil.exe"}]}}


# ------------------------------------------------------------------ one recording

def test_a_rule_the_recording_cannot_test_is_not_counted_as_a_miss():
    """No PowerShell script block events were recorded, so a rule that reads them has nothing to look at."""
    container, entry = make_container([raw_process("2020-10-22T03:52:05.773Z", "ntdsutil.exe"),
                                       raw_process("2020-10-22T03:52:09.000Z", "notepad.exe")])
    result = rp.replay_dataset([NTDS, SCRIPTS], container, entry, LABELS)
    assert result["hit"] == ["DET-901"]
    assert result["no_data"] == ["DET-902"] and result["missed"] == []
    assert "powershell_scriptblock" not in result["actions_present"]


def test_a_rule_that_could_have_fired_and_did_not_is_a_miss():
    container, entry = make_container([raw_process("2020-10-22T03:52:05.773Z", "ntdsutil.exe"),
                                       raw_script("2020-10-22T03:52:07.000Z", "Get-Date")])
    result = rp.replay_dataset([NTDS, SCRIPTS], container, entry, LABELS)
    assert result["hit"] == ["DET-901"] and result["missed"] == ["DET-902"] and result["no_data"] == []


def test_alerts_are_labeled_attack_other_or_unlabeled():
    container, entry = make_container([raw_process("2020-10-22T03:52:05.773Z", "ntdsutil.exe"),
                                       raw_process("2020-10-22T03:52:09.000Z", "notepad.exe")])
    noisy = toy("DET-903", {"action": "process_create", "process_name": "notepad.exe"})
    result = rp.replay_dataset([NTDS, noisy], container, {**entry, "expect": ["DET-901"]}, LABELS)
    assert {a["rule_id"]: a["label"] for a in result["alerts"]} == {"DET-901": "attack", "DET-903": "other"}
    assert result["labels"] == {"attack": 1, "other": 1, "unlabeled": 0}
    assert result["other_rules"] == ["DET-903"]
    unlabeled = rp.replay_dataset([NTDS], container, {**entry, "expect": ["DET-901"]}, {})
    assert unlabeled["labels"] == {"attack": 0, "other": 0, "unlabeled": 1}


def test_a_recording_that_does_not_match_its_checksum_is_refused():
    container, entry = make_container([raw_process("2020-10-22T03:52:05.773Z", "ntdsutil.exe")])
    with pytest.raises(ValueError, match="does not match the manifest"):
        rp.replay_dataset([NTDS], container, {**entry, "sha256": "0" * 64}, LABELS)


def test_the_summary_adds_up():
    container, entry = make_container([raw_process("2020-10-22T03:52:05.773Z", "ntdsutil.exe"),
                                       raw_process("2020-10-22T03:52:09.000Z", "notepad.exe")])
    result = rp.replay_dataset([NTDS, SCRIPTS], container, entry, LABELS)
    s = rp.summarize([result])
    assert (s["datasets"], s["expectations"], s["expectations_hit"], s["expectations_no_data"],
            s["expectations_missed"]) == (1, 2, 1, 1, 0)
    assert s["datasets_fully_hit"] == 0 and s["datasets_with_any_hit"] == 1
    assert s["alerts"] == 1 and s["attack_share"] == 1.0 and s["events"] == 2
    assert rp.summarize([])["attack_share"] is None


# ------------------------------------------------------------------ the split

def test_the_split_is_a_fixed_formula_of_the_file_name():
    manifest = rp.load_manifest(REPLAY)
    for d in manifest["datasets"]:
        odd = hashlib.sha256(d["file"].encode()).digest()[0] % 2 == 1
        assert d["split"] == ("holdout" if odd else "dev"), d["id"]
        assert rp.split_for(d["file"]) == d["split"]
    counts = {s: sum(1 for d in manifest["datasets"] if d["split"] == s) for s in ("dev", "holdout")}
    assert counts == {"dev": 14, "holdout": 12}


def test_the_manifest_is_valid_and_pinned_to_one_commit():
    manifest = rp.load_manifest(REPLAY)
    assert rp.validate_manifest(manifest) == []
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["source"]["commit"])
    assert manifest["source"]["files_are_unmodified"] is True and "MIT" in manifest["source"]["license"]
    assert len(manifest["datasets"]) == 26


@pytest.mark.parametrize("change,needle", [
    (lambda m: m["datasets"].append(dict(m["datasets"][0])), "duplicate id"),
    (lambda m: m["datasets"][0].pop("sha256"), "missing 'sha256'"),
    (lambda m: m["datasets"][0].__setitem__("split", "somewhere"), "split must be dev or holdout"),
    (lambda m: m["datasets"][0].__setitem__("split", "dev" if m["datasets"][0]["split"] == "holdout" else "holdout"), "does not match the formula"),
    (lambda m: m["datasets"][0].__setitem__("expect", []), "non-empty list"),
])
def test_the_manifest_check_names_each_problem(change, needle):
    manifest = json.loads(json.dumps(rp.load_manifest(REPLAY)))
    change(manifest)
    assert any(needle in p for p in rp.validate_manifest(manifest)), rp.validate_manifest(manifest)
    assert rp.validate_manifest({}) == ["the manifest needs a 'datasets' list"]


# ------------------------------------------------------------------ the real recordings

@pytest.fixture(scope="module")
def results(rules):
    return {split: rp.replay(rules, REPLAY, split) for split in ("all", "dev", "holdout")}


def test_the_headline_numbers(results):
    s = results["all"]["summary"]
    assert (s["datasets"], s["expectations"], s["expectations_hit"], s["expectations_missed"],
            s["expectations_no_data"]) == (26, 29, 26, 2, 1)
    assert (s["alerts"], s["labels"]) == (56, {"attack": 47, "other": 9, "unlabeled": 0})
    assert s["events"] == 59897 and round(s["attack_share"], 3) == 0.839
    dev, hold = results["dev"]["summary"], results["holdout"]["summary"]
    assert (dev["datasets"], dev["expectations_hit"], dev["expectations_missed"], dev["expectations_no_data"]) == (14, 15, 1, 1)
    assert (hold["datasets"], hold["expectations_hit"], hold["expectations_missed"], hold["expectations_no_data"]) == (12, 11, 1, 0)
    assert (hold["alerts"], hold["labels"]) == (27, {"attack": 23, "other": 4, "unlabeled": 0})


def test_the_three_misses_and_not_testables_are_the_known_ones(results):
    problems = {(r["id"], tuple(r["missed"]), tuple(r["no_data"])) for r in results["all"]["results"] if r["missed"] or r["no_data"]}
    assert problems == {("covenant_psremoting_command", ("DET-020",), ()),
                        ("empire_mimikatz_logonpasswords", (), ("DET-021",)),
                        ("covenant_sharpsc_create_dcerpc_smb_svcctl", ("DET-012",), ())}


def test_every_alert_in_every_recording_has_a_label(results):
    unlabeled = [(r["id"], a["rule_id"]) for r in results["all"]["results"] for a in r["alerts"] if a["label"] == "unlabeled"]
    assert unlabeled == []


def test_every_recording_is_in_the_container_with_the_right_checksum():
    manifest = rp.load_manifest(REPLAY)
    with zipfile.ZipFile(REPLAY / manifest["source"]["container"]) as z:
        names = set(z.namelist())
        assert names == {d["file"] for d in manifest["datasets"]}, "the container holds exactly the recordings the manifest lists"
        for d in manifest["datasets"]:
            assert hashlib.sha256(z.read(d["file"])).hexdigest() == d["sha256"], d["id"]


def test_replaying_with_a_selection_and_without_exclusions(rules):
    one = rp.replay(rules, REPLAY, "all", only="empire_mimikatz_logonpasswords")
    assert one["summary"]["datasets"] == 1
    with pytest.raises(ValueError, match="no dataset matches"):
        rp.replay(rules, REPLAY, "all", only="not_a_recording")
    strict = rp.replay(rules, REPLAY, "all", use_exclusions=False)
    assert strict["summary"]["alerts"] >= 56


# ------------------------------------------------------------------ the honesty protocol

@pytest.fixture(scope="module")
def first_run():
    return rp.load_first_run(REPLAY)


def test_the_expectations_were_not_edited_after_the_first_holdout_run(first_run):
    """expect lists were written from the technique alone, before any holdout run. Editing manifest.yml changes this hash."""
    assert first_run["manifest_sha256"] == rp.file_sha256(REPLAY / "manifest.yml")


def test_the_stored_first_run_is_untouched(first_run, rules):
    s = first_run["summary"]
    assert (s["datasets"], s["expectations"], s["expectations_hit"], s["expectations_missed"], s["alerts"]) == (12, 12, 10, 2, 27)
    assert first_run["rule_count"] == 32 and len(first_run["logic_fingerprints"]) == 32
    assert {d["id"] for d in first_run["datasets"]} == {d["id"] for d in rp.load_manifest(REPLAY)["datasets"] if d["split"] == "holdout"}
    assert first_run["addenda"], "the note about how the logic fingerprints were added stays with the record"


def test_every_rule_changed_since_the_first_run_has_a_written_reason(first_run, rules):
    changes = rp.compare_to_first_run(rules, first_run)
    assert changes["unchanged"] is False and changes["added"] == [] and changes["removed"] == []
    assert changes["changed"] == ["DET-009", "DET-015"]
    notes = rp.load_change_notes(REPLAY)
    assert set(notes) == set(changes["changed"]), "a rule cannot change after the freeze without saying why"
    assert all(len(text.split()) >= 30 for text in notes.values())


def test_the_first_run_labels_come_from_the_current_alerts_or_from_written_entries(first_run, results):
    labels = rp.load_labels(REPLAY)
    labeled = rp.label_first_run(first_run, results["holdout"]["results"], labels)
    assert labeled["labels"] == {"attack": 22, "other": 5, "unlabeled": 0}
    assert round(labeled["attack_share"], 3) == 0.815
    assert sum(d["alerts"] for d in labeled["datasets"]) == 27


def test_a_first_run_alert_that_no_rule_raises_any_more_needs_a_written_label():
    first = {"datasets": [{"id": "d1", "alerts": [
        {"rule_id": "DET-901", "first_ts": "2020-01-01T00:00:00Z", "entity": {"host": "A"}},
        {"rule_id": "DET-902", "first_ts": "2020-01-01T00:00:05Z", "entity": {"host": "A"}},
        {"rule_id": "DET-903", "first_ts": "2020-01-01T00:00:09Z", "entity": {"host": "A"}}]}]}
    current = [{"id": "d1", "alerts": [{"rule_id": "DET-901", "first_ts": "2020-01-01T00:00:00Z", "entity": {"host": "A"}, "label": "attack"}]}]
    labels = {"d1": {"first_run_only": [{"rule_id": "DET-902", "first_ts": "2020-01-01T00:00:05Z", "label": "other"}]}}
    out = rp.label_first_run(first, current, labels)
    assert out["labels"] == {"attack": 1, "other": 1, "unlabeled": 1}, "DET-903 has no label anywhere, so it stays unlabeled"


# ------------------------------------------------------------------ fingerprints and the freeze

def test_a_fingerprint_changes_with_behaviour_and_not_with_wording(rules):
    before = rp.rule_fingerprints(rules)
    rule = next(r for r in rules if r["id"] == "DET-001")
    for key, value in (("title", "a new title"), ("description", "a new description"), ("triage", ["new"]),
                       ("response", ["new"]), ("false_positives", ["new"]), ("status", "experimental"),
                       ("references", ["https://example.org"]), ("queries", {"x": "y"}), ("tests", []),
                       ("attack", {**rule["attack"], "technique_name": "Renamed"})):
        after = rp.rule_fingerprints([{**rule, key: value}])
        assert after["DET-001"] == before["DET-001"], f"{key} is wording, not behaviour"
    for key, value in (("threshold", rule["threshold"] + 1), ("window_seconds", rule["window_seconds"] + 1),
                       ("severity", "critical" if rule["severity"] != "critical" else "low")):
        assert rp.rule_fingerprints([{**rule, key: value}])["DET-001"] != before["DET-001"], key
    narrower = {**rule, "exclusions": [*(rule.get("exclusions") or []), {"match": {"user": "x"}, "reason": "r"}]}
    assert rp.rule_fingerprints([narrower])["DET-001"] != before["DET-001"], "an added exclusion changes behaviour"
    reworded = {**rule, "exclusions": [{"match": e["match"], "reason": "different words"} for e in rule.get("exclusions") or []]}
    assert rp.rule_fingerprints([reworded])["DET-001"] == before["DET-001"], "an exclusion's reason is wording"


def test_the_freeze_stores_the_first_run_once_and_refuses_to_replace_it(tmp_path):
    folder = tmp_path / "replay"
    folder.mkdir()
    for name in ("manifest.yml", "labels.yml", "otrf-datasets.zip"):
        shutil.copy(REPLAY / name, folder / name)
    record = rp.freeze_holdout(ROOT / "rules", folder)
    assert (folder / rp.FIRST_RUN_FILE).exists()
    assert record["summary"]["datasets"] == 12 and record["rule_count"] == 32
    assert record["manifest_sha256"] == rp.file_sha256(folder / "manifest.yml")
    with pytest.raises(FileExistsError, match="not replaced"):
        rp.freeze_holdout(ROOT / "rules", folder)
    assert rp.freeze_holdout(ROOT / "rules", folder, force=True)["rule_count"] == 32
    assert rp.compare_to_first_run(load_rules(ROOT / "rules"), rp.load_first_run(folder))["unchanged"] is True


def test_the_freeze_refuses_rules_that_are_not_valid(tmp_path):
    folder = tmp_path / "replay"
    folder.mkdir()
    for name in ("manifest.yml", "labels.yml", "otrf-datasets.zip"):
        shutil.copy(REPLAY / name, folder / name)
    bad = tmp_path / "rules"
    bad.mkdir()
    (bad / "DET-001.yml").write_text("id: DET-001\ntitle: broken\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid"):
        rp.freeze_holdout(bad, folder)
    assert not (folder / rp.FIRST_RUN_FILE).exists()


def test_the_replay_command_prints_the_split_and_the_comparison(capsys):
    assert main(["replay", "--split", "holdout"]) == 0
    out = capsys.readouterr().out
    assert "holdout" in out.lower() and "DET-009" in out and "DET-015" in out
    assert "11 of 12" in out or "11/12" in out


def test_no_other_replay_command_can_overwrite_the_first_run(first_run, tmp_path):
    """Running the normal commands must leave the stored first run exactly as it was."""
    before = (REPLAY / rp.FIRST_RUN_FILE).read_bytes()
    main(["replay", "--split", "holdout"])
    main(["replay", "--split", "all"])
    assert (REPLAY / rp.FIRST_RUN_FILE).read_bytes() == before
