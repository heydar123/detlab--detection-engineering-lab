from pathlib import Path

import pytest

from detlab.matching import excluded, matches, validate_filter
from detlab.rules import load_rules

# Use the SHIPPED rule, not a copy, so these tests fail if the real rule regresses.
ENC_RULE = load_rules(Path(__file__).resolve().parent.parent / "rules" / "DET-004.yml")[0]["filter"]
B64 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAZQBzAHQAJwA="

# Every shorthand of -EncodedCommand in TrustedSec's published list (not independently tested on a host).
ENCODED_FORMS = ["e", "ec", "en", "enc", "enco", "encod", "encode", "encoded", "encodedc", "encodedco",
                 "encodedcom", "encodedcomm", "encodedcomma", "encodedcomman", "encodedcommand"]


def ps(cmd):
    return {"process_name": "powershell.exe", "command_line": cmd}


def test_equals_is_case_insensitive():
    assert matches({"outcome": "Failure"}, {"outcome": "failure"})


def test_missing_field_never_matches():
    assert not matches({"a": 1}, {"b": 1})
    assert not matches({"a": 1}, {"b|in": [1]})


def test_in_contains_startswith_endswith():
    ev = {"cmd": "C:\\Windows\\System32\\cmd.exe"}
    assert matches(ev, {"cmd|in": ["c:\\windows\\system32\\cmd.exe"]})
    assert matches(ev, {"cmd|contains": ["system32"]})
    assert matches(ev, {"cmd|startswith": "c:\\windows"})
    assert matches(ev, {"cmd|endswith": ".exe"})
    assert not matches(ev, {"cmd|contains": ["powershell"]})


def test_all_conditions_must_match():
    assert not matches({"a": "x", "b": "y"}, {"a": "x", "b": "z"})


@pytest.mark.parametrize("flag", ["-enc", "-EncodedCommand", "-e", "-ENCODEDCOMMAND", "-Encode"])
def test_encoded_powershell_positives(flag):
    assert matches(ps(f"powershell.exe -nop -w hidden {flag} {B64}"), ENC_RULE)


@pytest.mark.parametrize("form", ENCODED_FORMS)
def test_every_listed_encodedcommand_shorthand_is_detected(form):
    assert matches(ps(f"powershell.exe -nop -w hidden -{form} {B64}"), ENC_RULE)


def test_known_gap_flag_built_at_runtime_is_not_matched():
    """Documented gap (EV-06): the literal flag is not in the command line, so a pattern cannot see it."""
    cmd = f"powershell.exe -nop -w hidden -c \"$f='-e'+'c'; powershell $f {B64}\""
    assert not matches(ps(cmd), ENC_RULE)


@pytest.mark.parametrize("cmd", [
    "powershell.exe -ec short",
    "powershell.exe -NoProfile -Command Get-Process",
    "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1",
    "powershell.exe -e short",
    "powershell.exe -Command \"echo -enc\"",
])
def test_encoded_powershell_negatives(cmd):
    assert not matches(ps(cmd), ENC_RULE)


def test_non_powershell_process_ignored():
    ev = {"process_name": "notepad.exe", "command_line": f"notepad.exe -enc {B64}"}
    assert not matches(ev, ENC_RULE)


def test_excluded_requires_all_fields_in_one_exclusion():
    exclusions = [{"match": {"user": "svc_backup", "host": "BACKUP-01"}, "reason": "backup"}]
    assert excluded({"user": "svc_backup", "host": "BACKUP-01"}, exclusions)
    # same user on a different host must NOT be excluded
    assert not excluded({"user": "svc_backup", "host": "WS-001"}, exclusions)


def test_validate_filter_catches_problems():
    assert validate_filter({"a|bogus": 1}, "x")
    assert validate_filter({"a|regex": "("}, "x")
    assert validate_filter({}, "x")
    assert not validate_filter({"a|in": [1, 2]}, "x")
