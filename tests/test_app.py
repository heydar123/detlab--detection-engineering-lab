"""Tests for the local web app: the data it serves, the checks that protect it, and the playground."""

import hashlib
import http.client
import json
import re
import socket
import threading
from pathlib import Path

import pytest

from detlab.app import EVIDENCE_LIMIT, MAX_BODY_BYTES, WEB_DIR, Lab, make_server
from detlab.cli import main

RULES = Path(__file__).resolve().parents[1] / "rules"


class Client:
    """A tiny HTTP client that lets a test choose the Host and Origin headers."""

    def __init__(self, server):
        self.server = server
        self.port = server.server_address[1]
        self.token = server.token

    def call(self, method, path, body=None, token="good", host="good", origin=None, raw_body=None, content_length=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}" if host == "good" else host)
        if token == "good":
            conn.putheader("X-Lab-Token", self.token)
        elif token is not None:
            conn.putheader("X-Lab-Token", token)
        if origin:
            conn.putheader("Origin", origin)
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else b"")
        if method == "POST":
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(data) if content_length is None else content_length))
        conn.endheaders(data if method == "POST" else None)
        resp = conn.getresponse()
        payload = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, headers, payload

    def json(self, method, path, body=None, **kw):
        status, headers, payload = self.call(method, path, body, **kw)
        return status, json.loads(payload.decode()) if payload else None


def _start(seed=7, days=14, lab=None, with_replay=True):
    server = make_server(RULES, seed=seed, days=days, port=0, lab=lab, with_replay=with_replay)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture(scope="module")
def client(lab):
    """Serves the shared lab. The tests that use it only read; none of them changes the lab."""
    server = _start(lab=lab)
    yield Client(server)
    server.shutdown()
    server.server_close()


@pytest.fixture
def fresh_client():
    """A separate server with its own lab, for tests that change the lab's state (no replay: they do not need it)."""
    server = _start(with_replay=False)
    yield Client(server)
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------- the page itself
def test_page_is_served_with_a_token_and_safe_headers(client):
    status, headers, body = client.call("GET", "/", token=None)
    html = body.decode()
    assert status == 200
    assert "__LAB_TOKEN__" not in html
    assert client.token in html
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "connect-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"


def test_page_loads_nothing_from_the_internet():
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"""(src|href)\s*=\s*["']https?://""", html)
    assert "@import" not in html and "url(http" not in html
    assert "<script src" not in html


def test_page_never_builds_html_from_data():
    """Everything shown must go through text nodes. Building HTML strings from log text would let a log run code."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert "innerHTML" not in html and "outerHTML" not in html and "insertAdjacentHTML" not in html
    assert "document.write" not in html and "eval(" not in html


def test_server_listens_on_the_local_address_only(client):
    assert client.server.server_address[0] == "127.0.0.1"


# ---------------------------------------------------------------- who may call the API
def test_api_needs_the_token(client):
    assert client.call("GET", "/api/lab", token=None)[0] == 403
    assert client.call("GET", "/api/lab", token="wrong")[0] == 403
    assert client.call("GET", "/api/lab", token="")[0] == 403
    assert client.call("GET", "/api/lab")[0] == 200


def test_post_needs_the_token(client):
    assert client.call("POST", "/api/run", {"seed": 7, "days": 14}, token=None)[0] == 403
    assert client.call("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": "x"}, token="wrong")[0] == 403


def test_wrong_host_is_refused_even_for_the_page(client):
    """Blocks DNS-rebinding: a web page cannot reach the lab by pointing its own name at 127.0.0.1."""
    assert client.call("GET", "/", token=None, host="evil.example")[0] == 403
    assert client.call("GET", "/", token=None, host=f"evil.example:{client.port}")[0] == 403
    assert client.call("GET", "/api/lab", host="evil.example")[0] == 403
    assert client.call("GET", "/", token=None, host=f"localhost:{client.port}")[0] == 200


def test_wrong_origin_is_refused(client):
    assert client.call("POST", "/api/run", {"seed": 7, "days": 14}, origin="http://evil.example")[0] == 403
    assert client.call("GET", "/api/lab", origin="https://127.0.0.1:%d" % client.port)[0] == 403
    assert client.call("GET", "/api/lab", origin=f"http://127.0.0.1:{client.port}")[0] == 200


def test_unknown_paths_and_methods(client):
    assert client.call("GET", "/etc/passwd", token=None)[0] == 404
    assert client.call("GET", "/../../etc/passwd", token=None)[0] == 404
    assert client.call("GET", "/api/nothing")[0] == 404
    assert client.call("POST", "/api/lab", {"a": 1})[0] == 404


# ---------------------------------------------------------------- the data
def test_lab_payload_has_the_measured_numbers(client):
    status, data = client.json("GET", "/api/lab")
    assert status == 200
    assert data["meta"]["seed"] == 7 and data["meta"]["days"] == 14 and data["meta"]["events"] == 11865
    assert data["overall"]["untuned"]["alerts"] == 143 and data["overall"]["untuned"]["fp"] == 90
    assert data["overall"]["tuned"]["alerts"] == 54 and data["overall"]["tuned"]["fp"] == 1
    assert len(data["rules"]) == 32 and len(data["attacks"]) == 13 and len(data["cases"]) == 14
    assert all(a["caught"] for a in data["attacks"])
    assert (data["redteam"]["caught"], data["redteam"]["total"]) == (9, 15)
    assert data["case_summary"] == {"alerts": 54, "cases": 14, "attacks_found": 13, "split": 0, "merged": 0,
                                    "false_positive_cases": 1}
    assert data["tests_summary"] == {"total": 320, "passed": 320, "exclusions": 28, "exclusions_proven": 28,
                                      "edits": 247, "edits_caught": 247}


def test_payload_has_every_section_the_page_draws(client):
    _, data = client.json("GET", "/api/lab")
    assert set(data) == {"meta", "timeline", "rules", "overall", "alerts", "attacks", "cases", "case_summary", "redteam",
                         "ranking", "risk_method", "coverage", "replay", "sigma_summary", "tests_summary"}
    assert data["ranking"]["pairs_ordered"] == 1.0 and data["ranking"]["false_case_ranks"] == [14]
    assert data["risk_method"]["severity_points"] == {"low": 1, "medium": 3, "high": 6, "critical": 10}
    assert data["risk_method"]["window_hours"] == 2
    assert [c["rank"] for c in sorted(data["cases"], key=lambda c: c["rank"])] == list(range(1, 15))
    for rule in data["rules"]:
        assert {"sigma", "queries", "query_status", "tests", "exclusion_proofs", "attack_ids", "yaml", "stats"} <= set(rule)


def test_payload_tells_the_truth_about_the_real_recordings(client):
    _, data = client.json("GET", "/api/lab")
    rp = data["replay"]
    s = rp["summary"]
    assert (s["datasets"], s["expectations"], s["expectations_hit"], s["expectations_missed"],
            s["expectations_no_data"]) == (26, 29, 26, 2, 1)
    assert (s["alerts"], s["labels"]) == (56, {"attack": 47, "other": 9, "unlabeled": 0})
    assert (rp["by_split"]["dev"]["datasets"], rp["by_split"]["holdout"]["datasets"]) == (14, 12)
    first = rp["first_run"]
    assert (first["summary"]["expectations"], first["summary"]["expectations_hit"]) == (12, 10), "the stored first run must not change"
    assert first["labeled"]["labels"] == {"attack": 22, "other": 5, "unlabeled": 0}
    assert first["changes"]["changed"] == ["DET-009", "DET-015"] and set(first["change_notes"]) == {"DET-009", "DET-015"}
    assert first["addenda"], "the note about how the logic fingerprints were added must travel with the numbers"
    by_id = {d["id"]: d for d in rp["datasets"]}
    assert by_id["covenant_sharpsc_create_dcerpc_smb_svcctl"]["missed"] == ["DET-012"]
    assert by_id["covenant_sharpsc_create_dcerpc_smb_svcctl"]["notes"], "a miss must be explained next to the miss"
    assert by_id["empire_mimikatz_logonpasswords"]["no_data"] == ["DET-021"]
    assert "MIT" in rp["source"]["license"] and len(rp["source"]["commit"]) == 40


def test_payload_reports_failed_siem_conversions_instead_of_hiding_them(client):
    _, data = client.json("GET", "/api/lab")
    assert data["sigma_summary"]["queries"] == {"splunk": {"ok": 19, "failed": 0}, "kql": {"ok": 17, "failed": 2}}
    det021 = next(r for r in data["rules"] if r["id"] == "DET-021")
    assert det021["query_status"]["kql"]["status"] == "failed" and det021["query_status"]["kql"]["error"]
    assert det021["queries"].get("kql") is None, "a failed conversion has no query text"
    assert det021["queries"]["splunk"].strip()


def test_payload_is_consistent_with_itself(client):
    _, data = client.json("GET", "/api/lab")
    ids = [a["id"] for a in data["alerts"]["tuned"]] + [a["id"] for a in data["alerts"]["untuned"]]
    assert len(ids) == len(set(ids)), "alert ids must be unique so the page can look each one up"
    tuned_ids = {a["id"] for a in data["alerts"]["tuned"]}
    for case in data["cases"]:
        assert set(case["alert_ids"]) <= tuned_ids
    assert {a["id"] for a in data["alerts"]["tuned"]} == {i for c in data["cases"] for i in c["alert_ids"]}
    t0, t1 = data["timeline"]["start"], data["timeline"]["end"]
    assert all(t0 <= a["fired_t"] <= t1 for a in data["alerts"]["tuned"] + data["alerts"]["untuned"])
    for a in data["attacks"]:
        assert t0 <= a["start"] <= a["end"] <= t1


def test_alert_detail_limits_evidence_and_knows_unknown_ids(client):
    status, big = client.json("GET", "/api/alert?id=A-0001")
    assert status == 200
    assert big["total_events"] == 120 and len(big["events"]) == EVIDENCE_LIMIT
    assert all(not k.startswith("_") for k in big["events"][0]), "internal fields must not leave the server"
    assert big["triage"] and big["response"]
    assert client.json("GET", "/api/alert?id=U-0001")[0] == 200       # untuned alerts can be opened too
    assert client.call("GET", "/api/alert?id=A-9999")[0] == 404
    assert client.call("GET", "/api/alert")[0] == 404
    assert client.call("GET", "/api/alert?id=../../x")[0] == 404


def test_case_timeline_collapses_failed_logins(client):
    status, case = client.json("GET", "/api/case?id=CASE-005")
    assert status == 200
    assert case["multi_stage"] and case["severity"] == "critical"
    assert len(case["timeline"]) < 12, "40 failed logins should be one line, not 40"
    failures = next(r for r in case["timeline"] if r["kind"] == "failures")
    assert "40 failed rdp logins" in failures["text"] and failures["count"] == 40
    assert any(r["kind"] == "group" and "Domain Admins" in r["text"] for r in case["timeline"])
    assert {t["rule_id"] for t in case["triage"]} == {"DET-001", "DET-004", "DET-005", "DET-006", "DET-007", "DET-028"}
    assert client.call("GET", "/api/case?id=CASE-999")[0] == 404


def test_case_detail_carries_its_risk_score_and_rank(client):
    _, case = client.json("GET", "/api/case?id=CASE-007")
    assert case["rank"] == 1 and case["risk"]["score"] == 115 and case["risk"]["level"] == "critical"
    assert sum(f["points"] for f in case["risk"]["factors"]) == 115
    assert len(case["alerts"]) == 13 and len(case["timeline"]) == 13


def test_case_report_downloads_as_a_hand_over_note(client):
    status, headers, body = client.call("GET", "/api/case-report?id=CASE-007")
    text = body.decode()
    assert status == 200 and 'filename="CASE-007.md"' in headers["content-disposition"]
    assert headers["content-type"].startswith("text/markdown")
    assert text.startswith("# CASE-007: adm.rossi") and "Risk 115 (critical), rank 1 of 14 cases" in text
    for heading in ("## Why this risk score", "## ATT&CK", "## Alerts", "## Timeline", "## What to check", "## What to do"):
        assert heading in text
    assert "Generated by Detection Lab from synthetic data" in text
    assert client.call("GET", "/api/case-report?id=CASE-999")[0] == 404
    assert client.call("GET", "/api/case-report?id=../../etc/passwd")[0] == 404
    assert client.call("GET", "/api/case-report")[0] == 404


def test_reports_download_and_reject_other_names(client):
    status, headers, body = client.call("GET", "/api/report?name=detection_report.md")
    assert status == 200 and "attachment" in headers["content-disposition"]
    assert b"False positives before tuning" in body
    status, _, body = client.call("GET", "/api/report?name=evasion_report.md")
    assert status == 200 and b"EV-01" in body
    for bad in ("../../etc/passwd", "README.md", "", "detection_report.md%00"):
        assert client.call("GET", "/api/report?name=" + bad)[0] == 404


# ---------------------------------------------------------------- run controls
@pytest.mark.parametrize("body", [
    {"seed": "7", "days": 14}, {"seed": 7.5, "days": 14}, {"seed": True, "days": 14}, {"seed": -1, "days": 14},
    {"seed": 1_000_001, "days": 14}, {"seed": 7, "days": 13}, {"seed": 7, "days": 31}, {"seed": 7, "days": "14"},
    {"seed": 7}, {"days": 14}, {}, {"seed": None, "days": None},
])
def test_run_rejects_bad_input(client, body):
    status, data = client.json("POST", "/api/run", body)
    assert status == 400 and "error" in data


def test_run_with_a_new_seed_changes_the_lab_and_stays_deterministic(fresh_client):
    status, data = fresh_client.json("POST", "/api/run", {"seed": 11, "days": 20})
    assert status == 200 and data["meta"]["seed"] == 11 and data["meta"]["days"] == 20
    again = fresh_client.json("POST", "/api/run", {"seed": 11, "days": 20})[1]
    assert json.dumps(data, sort_keys=True) == json.dumps(again, sort_keys=True)
    assert all(a["caught"] for a in data["attacks"]), "every planted attack should still be found at another seed"
    back = fresh_client.json("POST", "/api/run", {"seed": 7, "days": 14})[1]
    assert back["overall"]["untuned"]["alerts"] == 143


def test_request_body_limits(client):
    assert client.call("POST", "/api/run", raw_body=b"x" * (MAX_BODY_BYTES + 1))[0] == 400
    assert client.call("POST", "/api/run", raw_body=b"")[0] == 400
    assert client.call("POST", "/api/run", raw_body=b"not json")[0] == 400
    assert client.call("POST", "/api/run", raw_body=b"[1, 2]")[0] == 400
    assert client.call("POST", "/api/run", raw_body=b'{"seed": 7, "days": 14}', content_length=-5)[0] == 400


# ---------------------------------------------------------------- the playground
def _rule_text(rule_id="DET-001"):
    return (RULES / f"{rule_id}.yml").read_text(encoding="utf-8")


def test_unchanged_rule_shows_no_change(client):
    status, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": _rule_text()})
    assert status == 200 and res["ok"]
    assert res["before"] == res["after"]
    assert all(a["before"] == a["after"] for a in res["attacks"] + res["redteam"])


def test_the_playground_hint_in_the_page_is_true(client):
    """The page says: on DET-022 change max_cv 0.15 to 0.35 and EV-07 is caught, with no new false alarm.
    If this test fails, the hint in index.html is wrong and must be updated."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert "max_cv: 0.15" in html and "max_cv: 0.35" in html and "EV-07" in html
    text = _rule_text("DET-022")
    assert "max_cv: 0.15" in text
    _, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-022", "yaml": text.replace("max_cv: 0.15", "max_cv: 0.35")})
    assert res["ok"]
    assert (res["before"]["redteam_caught"], res["after"]["redteam_caught"]) == (9, 10)
    assert [r["id"] for r in res["redteam"] if r["before"] != r["after"]] == ["EV-07"]
    assert res["after"]["overall"]["fp"] == res["before"]["overall"]["fp"] and res["after"]["overall"]["recall"] == 1.0
    # a limit that is a little too tight changes nothing, so the number in the hint matters
    _, tight = client.json("POST", "/api/test-rule", {"rule_id": "DET-022", "yaml": text.replace("max_cv: 0.15", "max_cv: 0.3")})
    assert tight["after"]["redteam_caught"] == 9


def test_a_very_loose_limit_still_shows_no_false_alarms_here(client):
    """The warning shown with the hint: this lab's background traffic is too irregular to punish a loose limit."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert "Even a limit of 1.0 adds no false alarm at seed 7" in html
    _, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-022", "yaml": _rule_text("DET-022").replace("max_cv: 0.15", "max_cv: 1.0")})
    assert res["ok"] and res["after"]["overall"]["fp"] == res["before"]["overall"]["fp"]


def test_the_old_brute_force_hint_is_gone_because_it_stopped_being_true(client):
    """EV-01 is now caught by DET-028, so lowering DET-001's threshold changes no red-team result."""
    _, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": _rule_text().replace("threshold: 20", "threshold: 15")})
    assert res["ok"] and res["before"]["redteam_caught"] == res["after"]["redteam_caught"] == 9
    assert "threshold: 15" not in (WEB_DIR / "index.html").read_text(encoding="utf-8")


def test_removing_an_exclusion_brings_the_false_alarms_back(client):
    text = _rule_text("DET-006")
    assert "exclusions:" in text
    start = text.index("exclusions:")
    end = text.index("false_positives:")
    stripped = text[:start] + text[end:]
    _, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-006", "yaml": stripped})
    assert res["ok"]
    assert res["after"]["rule"]["fp"] > res["before"]["rule"]["fp"]
    assert res["false_alarms"] and "summary" in res["false_alarms"][0]


@pytest.mark.parametrize("label,text", [
    ("broken yaml", "id: [unclosed\n  - x"),
    ("not a mapping", "- a\n- b"),
    ("empty", ""),
    ("scalar", "just words"),
    ("wrong id", None),
    ("negative number", None),
    ("unknown type", None),
    ("missing required key", None),
    ("steps become a mapping", None),
])
def test_bad_rules_are_explained_not_crashed(client, label, text):
    base = _rule_text()
    if label == "wrong id":
        text = base.replace("id: DET-001", "id: DET-009")
    elif label == "negative number":
        text = base.replace("threshold: 20", "threshold: -4")
    elif label == "unknown type":
        text = base.replace("type: threshold", "type: magic")
    elif label == "missing required key":
        text = base.replace("severity: medium\n", "")
    elif label == "steps become a mapping":
        text = base.replace("  - Is the account privileged or a service account?", "  - Note: this has a colon and no quotes")
    status, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": text})
    assert status == 200 and res["ok"] is False and res["errors"], label
    assert all(isinstance(e, str) and e for e in res["errors"])


def test_playground_input_limits(client):
    assert client.json("POST", "/api/test-rule", {"rule_id": "DET-999", "yaml": _rule_text()})[0] == 400
    assert client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": "x" * 30_000})[0] == 400
    assert client.json("POST", "/api/test-rule", {"rule_id": 1, "yaml": "x"})[0] == 400
    assert client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": None})[0] == 400
    assert client.json("POST", "/api/test-rule", {"rule_id": "DET-001"})[0] == 400


def test_playground_never_changes_anything_on_disk_or_in_the_lab(fresh_client):
    def fingerprint():
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(RULES.glob("*.yml"))}

    before_files = fingerprint()
    before_lab = fresh_client.json("GET", "/api/lab")[1]
    text = _rule_text().replace("threshold: 20", "threshold: 5")
    assert fresh_client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": text})[1]["ok"]
    assert fingerprint() == before_files, "testing a rule must never write a rule file"
    after_lab = fresh_client.json("GET", "/api/lab")[1]
    assert json.dumps(before_lab, sort_keys=True) == json.dumps(after_lab, sort_keys=True), \
        "testing a rule must not change what the rest of the page shows"
    # The edit must not leak into later tests either: an unchanged DET-002 must still compare equal to the baseline,
    # even though the earlier edit (threshold 5) would have changed the red-team result if it had stuck.
    res = fresh_client.json("POST", "/api/test-rule", {"rule_id": "DET-002", "yaml": _rule_text("DET-002")})[1]
    assert res["before"] == res["after"], "an earlier edit leaked into the lab"
    rerun = fresh_client.json("POST", "/api/run", {"seed": 7, "days": 14})[1]
    assert json.dumps(before_lab, sort_keys=True) == json.dumps(rerun, sort_keys=True), \
        "running the lab again used an edited rule instead of the saved one"


def test_html_inside_a_rule_comes_back_as_plain_data(client):
    text = _rule_text().replace("title: Brute force", "title: <img src=x onerror=alert(1)>Brute force")
    status, res = client.json("POST", "/api/test-rule", {"rule_id": "DET-001", "yaml": text})
    assert status == 200 and res["ok"]    # it is just text; the page shows it with text nodes (checked above)


# ---------------------------------------------------------------- the Lab class and the command line
def test_lab_matches_the_command_line_numbers(lab):
    assert (lab.tuned["overall"]["alerts"], lab.untuned["overall"]["alerts"]) == (54, 143)
    assert len(lab.cases) == 14 and lab.evasion["caught"] == 9


def test_lab_refuses_invalid_rules(tmp_path):
    (tmp_path / "DET-001.yml").write_text("id: DET-001\ntitle: broken\n", encoding="utf-8")
    with pytest.raises(ValueError):
        Lab(tmp_path, 7, 14)


def test_app_command_checks_its_arguments_before_starting(capsys):
    assert main(["app", "--days", "3", "--no-browser"]) == 1
    assert "Days must be" in capsys.readouterr().out
    assert main(["app", "--seed", "-1", "--no-browser"]) == 1
    assert "seed must be" in capsys.readouterr().out
    assert main(["app", "--rules", "no_such_folder", "--no-browser"]) == 1
    assert "rules folder" in capsys.readouterr().out


def test_server_picks_another_port_when_the_first_is_busy():
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy = blocker.getsockname()[1]
    try:
        server = make_server(RULES, 7, 14, port=busy)
        try:
            assert server.server_address[1] != busy
            assert busy < server.server_address[1] <= busy + 19
        finally:
            server.server_close()
    finally:
        blocker.close()
