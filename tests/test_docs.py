"""The documents: every number in them is measured, every link and command exists, and nothing generated is stale.

The tables, the rule catalogue, the event schema and the sample reports are written by tools/make_docs.py from the lab's own
output. The sentences around them are written by hand, so this file pins each number that those sentences state to the value
that is measured now. A document that drifts from the lab fails here, with the file named.
"""

import importlib.util
import re
import shlex
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from detlab.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("make_docs", ROOT / "tools" / "make_docs.py")
make_docs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_docs)

GENERATED = ["docs/rule-catalogue.md", "docs/event-schema.md", "docs/sample-detection-report.md",
             "docs/sample-evasion-report.md", "docs/sample-case-report.md", "docs/sample-incident-report.md",
             "README.md", "docs/CASE-STUDY.md", "docs/replay-results.md"]
WRITTEN_BY_HAND = ["README.md", "docs/CASE-STUDY.md", "docs/RUN-IT.md", "docs/replay-results.md"]
DOC_FILES = sorted(["README.md", "NOTICE", "LICENSE"] + [str(p.relative_to(ROOT)) for p in (ROOT / "docs").glob("*.md")])

# Measured by tests/test_sigma.py, which pins every one of these numbers. They are repeated here only so that the documents
# can be checked against them, and test_the_sigma_numbers_are_the_ones_the_sigma_tests_pin keeps the two in step.
SIGMA = {"events": 74549, "files": 19, "selected": 1353, "cases": 190, "damaged": 215, "noticed": 170}

NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine",
                10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
                17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty"}


def squash(text: str) -> str:
    """The text with every run of spaces and line breaks made into one space, so a sentence can be found across a wrap."""
    return " ".join(text.split())


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8").replace("\r\n", "\n")


def word(n: int, capital: bool = False) -> str:
    text = NUMBER_WORDS[n]
    return text.capitalize() if capital else text


def pct(x) -> str:
    return f"{x * 100:.0f}%"


@pytest.fixture(scope="module")
def facts(lab):
    return make_docs.facts(lab)


@pytest.fixture(scope="module")
def generated(lab):
    return make_docs.render_all(lab)


# ------------------------------------------------------------------ generated text is current

def test_the_generator_makes_exactly_the_documents_listed_here(generated):
    assert sorted(generated) == sorted(GENERATED)


@pytest.mark.parametrize("path", GENERATED)
def test_a_generated_document_is_up_to_date(path, generated):
    assert read(path) == generated[path], f"{path} is out of date. Run: python tools/make_docs.py"


def test_the_sample_reports_are_what_the_commands_write(facts, tmp_path):
    assert main(["run", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "detection_report.md").read_text(encoding="utf-8") == read("docs/sample-detection-report.md")
    assert (tmp_path / "evasion_report.md").read_text(encoding="utf-8") == read("docs/sample-evasion-report.md")
    case = tmp_path / "case.md"
    assert main(["case", "--user", facts["top_case_account"], "--data", str(tmp_path), "--out", str(case)]) == 0
    assert case.read_text(encoding="utf-8") == read("docs/sample-incident-report.md")


def test_the_sample_case_report_is_the_top_ranked_case(facts):
    text = read("docs/sample-case-report.md")
    assert text.startswith(f"# {facts['top_case']}: {facts['top_case_account']}\n")
    assert f"rank 1 of {facts['cases']} cases" in text


def test_the_generator_check_command_passes_on_the_committed_files(lab, monkeypatch, capsys):
    monkeypatch.setattr(make_docs, "Lab", lambda *args, **kwargs: lab)
    assert make_docs.main(["--check"]) == 0
    assert capsys.readouterr().out == "OK: 9 generated documents are up to date\n"


def test_the_generator_check_names_a_stale_file_and_changes_nothing(lab, monkeypatch, capsys, tmp_path):
    for path in GENERATED:
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(read(path), encoding="utf-8")
    stale = tmp_path / "docs" / "sample-evasion-report.md"
    stale.write_text(stale.read_text(encoding="utf-8").replace("9 of 15", "12 of 15"), encoding="utf-8")
    monkeypatch.setattr(make_docs, "Lab", lambda *args, **kwargs: lab)
    monkeypatch.setattr(make_docs, "ROOT", tmp_path)
    before = {p: (tmp_path / p).read_bytes() for p in GENERATED}
    assert make_docs.main(["--check"]) == 1
    out = capsys.readouterr().out
    assert "docs/sample-evasion-report.md" in out and "Run: python tools/make_docs.py" in out
    assert out.count("\n  docs/") == 1, "only the stale file is named"
    assert before == {p: (tmp_path / p).read_bytes() for p in GENERATED}, "--check must not write"
    assert make_docs.main([]) == 0, "without --check it repairs the file"
    assert make_docs.main(["--check"]) == 0


def test_a_block_is_rewritten_from_the_measurements_and_the_words_around_it_are_kept(lab, tmp_path):
    for path in ("README.md", "docs/CASE-STUDY.md", "docs/replay-results.md"):
        text = read(path)
        garbled = re.sub(r"(<!-- generated: [a-z0-9-]+ -->\n).*?(<!-- /generated -->)", r"\1THIS WAS EDITED BY HAND\n\2", text,
                         flags=re.S)
        assert garbled != text
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(garbled, encoding="utf-8")
    rebuilt = make_docs.render_all(lab, root=tmp_path)
    for path in ("README.md", "docs/CASE-STUDY.md", "docs/replay-results.md"):
        assert rebuilt[path] == read(path), path


def test_a_document_that_lost_its_block_markers_is_refused(lab, tmp_path):
    for path in ("README.md", "docs/CASE-STUDY.md", "docs/replay-results.md"):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(read(path), encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8").replace("<!-- generated: results -->\n", ""), encoding="utf-8")
    with pytest.raises(SystemExit, match="generated blocks"):
        make_docs.render_all(lab, root=tmp_path)


def test_the_sentences_that_depend_on_a_fact_stop_the_generator_when_the_fact_changes(lab, facts):
    """The README says the one remaining false positive is DET-027 and that the false-alarm case ranks last."""
    with pytest.raises(SystemExit, match="DET-027"):
        make_docs.block_results(lab, {**facts, "fp_rules": ["DET-004"]})
    with pytest.raises(SystemExit, match="ranks last"):
        make_docs.block_results(lab, {**facts, "ranking_false_ranks": [3]})


# ------------------------------------------------------------------ numbers written by hand

def claims(f: dict) -> dict[str, list[str]]:
    """Each sentence (after line wraps are removed) that a hand-written document must contain, with its numbers filled in."""
    sigma_pairs = SIGMA["events"] * SIGMA["files"]
    sigma_pct = pct(SIGMA["noticed"] / SIGMA["damaged"])
    return {
        "README.md": [
            f"{f['rules']} detection rules written as code, and the evidence for how far to trust them.",
            f"Everything here runs on made-up logs and on {f['replay_datasets']} short public attack recordings.",
            f"{f['rules']} rules mapped to MITRE ATT&CK v{f['attack_version']}",
            f"{f['sigma_exported']} of the rules export to Sigma",
            f"The red team found {f['redteam_open']} attacks the rules still miss.",
            f"{pct(f['tuned_precision'])} precision and {pct(f['recall'])} recall there show that the method works.",
            f"{f['kql_failed']} Sentinel conversions failed and {len(f['kql_partial_rules'])} are partial",
            f"{f['parents_with_rule']} of {f['parents']} ATT&CK parent techniques have a rule.",
            f"{word(len(f['first_changed']), True)} rules were changed after the holdout's first run.",
            f"On {SIGMA['events']:,} events times {SIGMA['files']} files ({sigma_pairs:,} comparisons)",
            f"{SIGMA['selected']:,} of those comparisons are events the rules select",
            f"all {SIGMA['cases']} rule test cases that have a Sigma file",
            f"{SIGMA['damaged']} Sigma files were damaged by one small edit each: it noticed {SIGMA['noticed']} of them "
            f"({sigma_pct}). The {SIGMA['damaged'] - SIGMA['noticed']} it misses",
            f"`python -m detlab replay` | Run the rules on the public attack recordings",
            f"`rules/` the {f['rules']} detection rules, one YAML file each".replace("`rules/` ", "rules/            "),
        ],
        "docs/CASE-STUDY.md": [
            f"Made-up logs with {f['attacks']} labeled attacks",
            f"{f['replay_datasets']} public recordings of real attack tools, split before the results were seen",
            f"{f['rule_tests']} in all.",
            f"Each of the {f['exclusions']} exclusions is removed in turn, and a test must go red "
            f"({f['exclusions_proven']} of {f['exclusions']} do).",
            f"some test must notice each of the {f['edits']} edits ({f['edits_caught']} of {f['edits']} do).",
            f"from 272 to {f['rule_tests']}.",
            f"the {f['rules']} rules raise {f['untuned_alerts']} alerts, {f['untuned_fp']} of them false alarms "
            f"({pct(f['untuned_precision'])} precision).",
            f"{f['exclusions']} documented exclusions: {f['tuned_alerts']} alerts, {f['tuned_fp']} false positive "
            f"({pct(f['tuned_precision'])}), and all {f['attacks']} attacks found.",
            f"{word(f['redteam_total'], True)} attack variants were written to get past the rules, and the report lists "
            f"{word(f['redteam_caught'])} gaps found and closed.",
            f"{word(f['redteam_open'], True)} variants still get through",
            f"Of the {f['replay_expectations']} expectations",
            f"{f['replay_hit']} fire. On the holdout half, run once after the rules were frozen, "
            f"{f['first_hit']} of {f['first_expectations']} fired.",
            f"(the stored first run is kept next to the current result ({f['hold_hit']} of {f['hold_expectations']})".replace(
                "(the stored", "the stored"),
            f"{word(f['sigma_exported'], True)} of the {f['rules']} rules export to Sigma.",
            f"The other {f['rules'] - f['sigma_exported']} need things Sigma cannot say",
            f"on {SIGMA['events']:,} events times {SIGMA['files']} files: no disagreements.",
            f"{SIGMA['damaged']} Sigma files were damaged by one edit each: it noticed {SIGMA['noticed']} "
            f"({pct(SIGMA['noticed'] / SIGMA['damaged'])}).",
            f"two Sentinel conversions failed and two are partial",
            f"which is {f['ttd_max'] // 60} minutes after the first prompt.",
            f"the same {f['actions']} kinds of event",
            f"{f['parents_with_rule']} of {f['parents']} ATT&CK parent techniques have a rule.",
        ],
        "docs/replay-results.md": [
            f"A look at all {f['replay_datasets']} came before the split.",
            f"{word(len(f['first_changed']), True)} rules were changed after the first holdout run",
            "the ATT&CK labels of five rules were updated afterwards",
        ],
        "docs/RUN-IT.md": [
            f"prints `OK: {f['rules']} rules valid`",
            f"A lab for detection engineering: {f['rules']} detection rules, made-up logs",
        ],
    }


@pytest.mark.parametrize("path", ["README.md", "docs/CASE-STUDY.md", "docs/replay-results.md", "docs/RUN-IT.md"])
def test_every_number_a_hand_written_document_states_is_the_measured_one(path, facts):
    text = squash(read(path))
    missing = [claim for claim in claims(facts)[path] if squash(claim) not in text]
    assert not missing, f"{path} does not say (or says differently): {missing}"


def test_the_numbers_that_were_pinned_for_the_sentences_are_themselves_what_the_lab_measures(facts):
    """If one of these changes, the sentences above must be rewritten, not just renumbered."""
    assert (facts["rules"], facts["rule_tests"], facts["exclusions"], facts["edits"]) == (32, 320, 28, 247)
    assert (facts["tuned_alerts"], facts["tuned_fp"], facts["untuned_alerts"], facts["untuned_fp"]) == (54, 1, 143, 90)
    assert (facts["attacks"], facts["cases"], facts["redteam_caught"], facts["redteam_total"]) == (13, 14, 9, 15)
    assert (facts["replay_datasets"], facts["replay_expectations"], facts["replay_hit"], facts["first_hit"],
            facts["hold_hit"]) == (26, 29, 26, 10, 11)
    assert (facts["sigma_exported"], facts["splunk_ok"], facts["kql_ok"], facts["kql_failed"]) == (19, 19, 17, 2)
    assert facts["kql_failed_rules"] == ["DET-021", "DET-029"] and facts["kql_partial_rules"] == ["DET-013", "DET-026"]
    assert (facts["ttd_max_id"], facts["ttd_max"], facts["ttd_median"], facts["ttd_zero"]) == ("SC-08", 780, 38, 5)
    assert (facts["parents_with_rule"], facts["parents"], facts["mapped_ids"]) == (28, 227, 48)


def test_the_sigma_numbers_are_the_ones_the_sigma_tests_pin(facts):
    source = read("tests/test_sigma.py")
    for needle in (f"len(events) == {SIGMA['events']}", f"selected == {SIGMA['selected']}", f"cases == {SIGMA['cases']}",
                   f"edits == {SIGMA['damaged']}", f"caught == {SIGMA['noticed']}"):
        assert needle in source, needle
    assert SIGMA["files"] == facts["sigma_exported"]
    assert "0 disagreements" in source or "differ == []" in source


def test_the_documented_red_team_gaps_found_and_closed_are_as_many_as_the_caught_variants(facts):
    report = read("docs/sample-evasion-report.md")
    closed = report.split("## Gaps found and closed")[1].split("## Open gaps and what would close them")[0]
    assert len(re.findall(r"^- \*\*EV-", closed, re.M)) == facts["redteam_caught"]
    assert len(re.findall(r"^### EV-", report, re.M)) == facts["redteam_open"]


def test_over_six_hundred_pytest_tests_as_the_readme_says():
    done = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    collected = re.search(r"(\d+) tests? collected", done.stdout)
    assert collected and int(collected.group(1)) > 600, done.stdout[-300:]
    assert "Over 600 pytest tests" in read("README.md")


# ------------------------------------------------------------------ nothing stale, nothing private

STALE = ["134 tests", "eight detection rules", "Eight detection rules", "3,068 events", "6 hidden attacks", "50 alerts",
         "36 of them", "overview-no-tuning", "overview-tuned", "playground.png", "PRESENTING-THIS-PROJECT", "START-HERE",
         "223 tests", "8 rules", "0 of 6", "six hidden attacks"]


@pytest.mark.parametrize("path", ["README.md", "docs/RUN-IT.md", "docs/replay-results.md", "docs/rule-catalogue.md",
                                  "docs/event-schema.md"])
def test_no_number_or_name_from_an_older_version_is_left(path):
    text = read(path)
    assert [s for s in STALE if s in text] == []


def test_the_case_study_mentions_no_old_number_except_the_one_it_explains():
    text = read("docs/CASE-STUDY.md")
    assert [s for s in STALE if s in text and s != "from 272"] == []


def test_the_documents_folder_holds_exactly_the_expected_files():
    names = sorted(p.name for p in (ROOT / "docs").iterdir())
    assert names == ["CASE-STUDY.md", "RUN-IT.md", "event-schema.md", "replay-results.md", "rule-catalogue.md",
                     "sample-case-report.md", "sample-detection-report.md", "sample-evasion-report.md",
                     "sample-incident-report.md", "screenshots"]


# Windows paths such as C:\Users\Public appear in the rules on purpose, so a bare "C:\Users" is not searched for.
# What must never be committed is a folder path from the machine the project was built or run on. The list holds the
# folder names of the machine it was built on; the home folder of whoever runs this test is added when it runs.
BUILD_FOLDERS = ["/home/claude", "claude-0", "scratchpad", "/root/"]
TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".json", ".html", ".txt", ".toml", ".cfg", ""}


def _folders_that_must_not_appear():
    home = Path.home()
    own = {str(home), home.as_posix()}
    # a very short home folder (such as /root or /) would match ordinary text, so only a longer one is searched for
    return BUILD_FOLDERS + sorted(name for name in own if len(name) > 8)


def test_the_repository_holds_no_folder_path_from_the_machine_it_was_built_on():
    needles = _folders_that_must_not_appear()
    found = []
    for path in ROOT.rglob("*"):
        parts = set(path.relative_to(ROOT).parts)
        if not path.is_file() or parts & {"build", "site", "__pycache__", ".pytest_cache", ".git", "_vendor"} or path.suffix == ".zip":
            continue
        if path.suffix not in TEXT_SUFFIXES or path.name == "test_docs.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found += [f"{path.relative_to(ROOT)}: {needle}" for needle in needles if needle in text]
    assert found == []


def test_the_folder_check_adds_the_home_folder_of_the_machine_running_it(monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/somebody-else")))
    assert "/home/somebody-else" in _folders_that_must_not_appear()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/root")))
    assert _folders_that_must_not_appear() == BUILD_FOLDERS


# ------------------------------------------------------------------ links, images, commands, paths

LINK = re.compile(r"(!?)\[[^\]]*\]\(([^)\s]+)\)")
URL = re.compile(r"https?://[^\s)`>\]\"']+")
EXPECTED_HOSTS = {"github.com", "attack.mitre.org", "sigmahq.io"}


@pytest.mark.parametrize("path", DOC_FILES)
def test_every_relative_link_and_image_points_at_a_file_that_exists(path):
    base = (ROOT / path).parent
    broken = []
    for _, target in LINK.findall(read(path)):
        if re.match(r"(https?:|mailto:|#)", target):
            continue
        if not (base / target.split("#")[0]).resolve().exists():
            broken.append(target)
    assert broken == []


@pytest.mark.parametrize("path", WRITTEN_BY_HAND)
def test_every_address_in_a_hand_written_document_is_https_and_to_a_site_the_project_uses(path):
    hosts = {}
    for url in URL.findall(read(path)):
        assert url.startswith("https://"), f"{path}: {url}"
        hosts.setdefault(url.split("/")[2], url)
    assert set(hosts) <= EXPECTED_HOSTS, hosts


def test_every_screenshot_is_a_real_image_and_every_image_is_used():
    shots = sorted((ROOT / "docs" / "screenshots").glob("*"))
    assert [p.name for p in shots] == ["case-timeline.png", "coverage.png", "overview.png", "real-recordings.png",
                                       "red-team.png", "rule-page.png"]
    used = {Path(t).name for bang, t in LINK.findall(read("README.md")) if bang}
    assert used == {p.name for p in shots}
    for p in shots:
        data = p.read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", data[16:24])
        assert (width, height) == (1280, 1000), p.name


COMMAND = re.compile(r"python3? -m detlab ([^`\n]*)")


@pytest.mark.parametrize("path", WRITTEN_BY_HAND)
def test_every_command_shown_in_a_document_is_accepted_by_the_command_line(path):
    parser = build_parser()
    shown = []
    for raw in COMMAND.findall(read(path)):
        argv = shlex.split(raw.split("#")[0].strip())
        if not argv:
            continue
        shown.append(argv)
        try:
            parser.parse_args(argv)
        except SystemExit:
            pytest.fail(f"{path} shows a command the program does not accept: python -m detlab {raw.strip()}")
    assert shown, f"{path} should show at least one command"


def test_every_command_of_the_program_is_in_the_readme_table():
    readme = read("README.md")
    choices = next(a for a in build_parser()._actions if a.dest == "command").choices
    assert [c for c in choices if f"python -m detlab {c}" not in readme] == []


def test_every_script_named_in_a_document_exists():
    for path in WRITTEN_BY_HAND:
        for script in re.findall(r"python3? (tools/[\w.-]+\.py)", read(path)):
            assert (ROOT / script).is_file(), (path, script)


def test_every_path_in_the_repository_map_exists():
    block = read("README.md").split("## Repository map")[1].split("```")[1]
    paths = [line.split()[0] for line in block.splitlines() if line.strip()]
    assert len(paths) >= 9 and [p for p in paths if not (ROOT / p).exists()] == []


# ------------------------------------------------------------------ honesty and licenses

def test_the_readme_leads_with_the_honest_label_and_discloses_its_limits():
    text = squash(read("README.md"))
    assert text.index("**A lab, not production experience.**") < text.index("## What is in it")
    for needle in ("The made-up logs and the rules come from the same author.", "The red team is the same author too.",
                   "so there is no false-positive rate for real data.",
                   "The SIEM queries have never run on a live Splunk or Sentinel.",
                   "Built with AI assistance."):
        assert needle in text, needle


FIRST_PERSON = re.compile(r"\b(I|I'm|I've|I'd|I'll|my|mine|we|We|our|Our|ours)\b")


def test_no_text_is_written_in_the_first_person_so_none_claims_work_for_someone_who_did_not_do_it():
    """The documents, the web page and the notes in the data files speak in a neutral voice ("the author", passive).
    The one exception is the program's own error messages ("I cannot find the rules folder"), which are the program talking."""
    files = (["README.md", "NOTICE", "replay/labels.yml", "detlab/web/index.html", "detlab/schema.py"]
             + [f"docs/{p.name}" for p in sorted((ROOT / "docs").glob("*.md"))]
             + [f"rules/{p.name}" for p in sorted((ROOT / "rules").glob("*.yml"))])
    found = []
    for path in files:
        for number, line in enumerate(read(path).splitlines(), 1):
            for match in FIRST_PERSON.finditer(line):
                if line[match.start():].startswith("I cannot "):
                    continue
                found.append(f"{path}:{number}: {line.strip()[:90]}")
    assert found == []


def test_the_web_page_and_the_readme_both_say_that_an_ai_assistant_helped_build_this():
    assert "Built with AI assistance." in read("README.md")
    assert "built with the help of an AI assistant (Claude, by Anthropic)" in read("detlab/web/index.html")


@pytest.mark.parametrize("path", ["docs/CASE-STUDY.md", "docs/RUN-IT.md", "docs/replay-results.md"])
def test_each_page_says_what_it_is_and_what_it_is_not(path):
    text = squash(read(path)).lower()
    assert "not production experience" in text or "nobody here wrote" in text or "made-up" in text


def test_the_license_is_mit_and_the_notice_carries_the_terms_of_what_was_included(facts):
    assert read("LICENSE").startswith("MIT License\n\nCopyright (c) 2026 detlab contributors\n")
    notice = read("NOTICE")
    manifest = read("replay/manifest.yml")
    assert facts["replay_commit"] in notice and f"commit: {facts['replay_commit']}" in manifest
    assert "Copyright (c) 2021 Open Threat Research Forge" in notice and "MIT License" in notice
    assert "The README text of that repository still says GPL" in squash(notice).replace("\n", " ") or "still says GPL" in notice
    attack = (ROOT / "detlab" / "data" / "attack.json").read_text(encoding="utf-8")
    assert "Copyright 2015-2026, The MITRE Corporation." in notice and "Copyright 2015-2026, The MITRE Corporation." in attack
    assert (ROOT / "detlab" / "_vendor" / "yaml" / "LICENSE").is_file() and "PyYAML 6.0.3" in notice
    assert "__version__ = '6.0.3'" in read("detlab/_vendor/yaml/__init__.py")


def test_git_is_told_to_keep_line_endings_as_lf_so_a_windows_clone_passes_the_hash_checks():
    """Without this file, Git on Windows turns LF into CRLF at clone time, and the checks that compare bytes or hashes
    (the SIEM queries in sigma/queries, replay/manifest.yml) report edits that nobody made."""
    attributes = read(".gitattributes")
    assert "* text=auto eol=lf" in attributes
    assert "*.zip binary" in attributes and "*.png binary" in attributes


def test_continuous_integration_runs_the_mutation_check_and_the_document_check():
    ci = read(".github/workflows/ci.yml")
    assert "python -m detlab test-rules --mutate" in ci
    assert "python tools/make_docs.py --check" in ci
    assert "python -m detlab export-sigma --check" in ci
