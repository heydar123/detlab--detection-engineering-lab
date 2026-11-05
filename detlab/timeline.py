"""Turn the log events around a case into a short story an analyst can read.

``build_timeline`` gives the case page, the downloaded case report and the static site the same rows. There is one row
per event, except that a run of similar events becomes one row with a count and the time it took:

* failed sign-ins from one address (40 of them become one line),
* connections from one program to one address (a beacon makes hundreds),
* DNS lookups under one domain, refused MFA prompts, network logons to many computers, files dropped by one program.

Every event kind in the schema has a plain-words sentence. Nothing here can fail on a missing field: a value that is
not there is shown as "?".
"""

from __future__ import annotations

from collections import defaultdict
from statistics import median

from .engine import _fmt_secs, _fmt_size

TIMELINE_LIMIT = 200          # rows, after similar events are merged
RUN_GAP_SECONDS = 1800        # a pause longer than this starts a new row for the same kind of event
DETAIL_LIMIT = 200            # characters of a command line, script or path shown under a row

LOGON_TYPES = {2: "at the keyboard", 3: "over the network", 4: "batch job", 5: "service", 7: "screen unlock",
               10: "remote desktop", 11: "cached sign-in"}
MFA_WORDS = {"approved": "approved", "denied": "denied", "timeout": "ignored (timed out)"}


def _v(ev: dict, key: str, default: str = "?") -> str:
    value = ev.get(key)
    return default if value is None or value == "" else str(value)


def _clip(text) -> str | None:
    if text is None or text == "":
        return None
    flat = " ".join(str(text).split())
    return flat if len(flat) <= DETAIL_LIMIT else flat[:DETAIL_LIMIT] + "..."


def _clock(ev: dict) -> str:
    return str(ev.get("ts", ""))[11:19] or "?"


def _logon_how(ev: dict) -> str:
    try:
        return LOGON_TYPES.get(int(ev.get("logon_type")), f"logon type {ev.get('logon_type')}")
    except (TypeError, ValueError):
        return "logon type ?"


# ------------------------------------------------------------------------------ one event

def describe_event(ev: dict) -> tuple[str, str | None]:
    """One event in plain words, plus a detail line (command, path, script) when there is one."""
    action = ev.get("action")
    user, host = _v(ev, "user"), _v(ev, "host")
    if action == "login":
        return (f"{user} logged in ({_v(ev, 'outcome')}) with {_v(ev, 'service')} from {_v(ev, 'src_ip')} "
                f"({_v(ev, 'country')})"), None
    if action == "host_logon":
        return (f"{user} logged on to {host} ({_v(ev, 'outcome')}, {_logon_how(ev)}) from {_v(ev, 'src_ip')}"), None
    if action == "mfa_prompt":
        return (f"The MFA {_v(ev, 'method')} prompt for {user} was {MFA_WORDS.get(str(ev.get('outcome')), _v(ev, 'outcome'))} "
                f"(sign-in from {_v(ev, 'src_ip')}, {_v(ev, 'country')})"), None
    if action == "process_create":
        return (f"{_v(ev, 'process_name')} started on {host} by {user}, launched by {_v(ev, 'parent_process')}",
                _clip(ev.get("command_line")))
    if action == "process_access":
        return (f"{_v(ev, 'process_name')} opened {_v(ev, 'target_process')} on {host} with access "
                f"{_v(ev, 'granted_access')}"), None
    if action == "registry_set":
        detail = f"{_v(ev, 'registry_key')} = {_v(ev, 'registry_value')}"
        return f"{_v(ev, 'process_name')} set a registry value on {host}", _clip(detail)
    if action == "file_create":
        return f"{_v(ev, 'process_name')} created a file on {host}", _clip(ev.get("file_path"))
    if action == "service_install":
        return (f"The service {_v(ev, 'service_name')} was installed on {host} by {user}, running as "
                f"{_v(ev, 'service_account')}"), _clip(ev.get("service_path"))
    if action == "scheduled_task_create":
        return f"{user} created the scheduled task {_v(ev, 'task_name')} on {host}", _clip(ev.get("task_command"))
    if action == "user_create":
        return f"{user} created the account {_v(ev, 'target_user')} on {host}", None
    if action == "group_add":
        return f"{user} added {_v(ev, 'target_user')} to the group {_v(ev, 'group')} on {host}", None
    if action == "directory_access":
        return (f"{user} read {_v(ev, 'object_type')} directory data on {host} with access mask "
                f"{_v(ev, 'access_mask')}"), _clip(ev.get("properties"))
    if action == "log_clear":
        return f"{user} cleared the {_v(ev, 'log_name')} event log on {host}", None
    if action == "audit_policy_change":
        return (f"{user} changed the audit policy for {_v(ev, 'subcategory')} on {host}"), _clip(ev.get("audit_changes"))
    if action == "powershell_scriptblock":
        return f"PowerShell on {host} ran a script block for {user}", _clip(ev.get("script_text"))
    if action == "network_connect":
        sent = f", sent {_fmt_size(float(ev['bytes_out']))}" if isinstance(ev.get("bytes_out"), (int, float)) else ""
        return (f"{_v(ev, 'process_name')} on {host} connected to {_v(ev, 'dst_ip')}:{_v(ev, 'dst_port')} "
                f"({_v(ev, 'protocol')}){sent}"), None
    if action == "dns_query":
        by = f" ({ev['process_name']})" if ev.get("process_name") else ""
        return f"{host} looked up {_v(ev, 'query')} ({_v(ev, 'query_type')}){by}", None
    if action == "cloud_audit":
        mfa = "MFA used" if ev.get("mfa_used") else "no MFA"
        return (f"{user} called {_v(ev, 'event_name')} on {_v(ev, 'event_source')} from {_v(ev, 'src_ip')} "
                f"({_v(ev, 'country')}): {_v(ev, 'outcome')}, {mfa}"), _clip(ev.get("resource"))
    return f"{_v(ev, 'action')} on {host}", None


# --------------------------------------------------------------------------- runs of similar events

def run_key(ev: dict):
    """Events with the same key (and the same alerts) can be shown as one row. None means: never merge."""
    action = ev.get("action")
    if action == "network_connect":
        return (action, ev.get("host"), ev.get("process_name"), ev.get("dst_ip"), ev.get("dst_port"), ev.get("protocol"))
    if action == "dns_query":
        return (action, ev.get("host"), ev.get("domain"), ev.get("process_name"))
    if action == "mfa_prompt":
        return (action, ev.get("user"), ev.get("outcome"), ev.get("method"))
    if action == "host_logon":
        return (action, ev.get("user"), ev.get("outcome"), ev.get("logon_type"))
    if action == "file_create":
        return (action, ev.get("host"), ev.get("process_name"))
    if action == "cloud_audit":
        return (action, ev.get("user"), ev.get("event_name"), ev.get("outcome"))
    return None


def _every(run: list[dict]) -> str:
    gaps = [b["_t"] - a["_t"] for a, b in zip(run, run[1:]) if "_t" in a and "_t" in b]
    return f", about every {_fmt_secs(median(gaps))}" if gaps else ""


def describe_run(run: list[dict]) -> tuple[str, str | None, str | None]:
    """The sentence for 2 or more similar events (see run_key): (text, detail, note).

    ``detail`` is text copied from the logs (a path); ``note`` is a summary written by this module."""
    first, n, last = run[0], len(run), _clock(run[-1])
    action = first.get("action")
    if n == 1:
        text, detail = describe_event(first)
        return text, detail, None
    if action == "network_connect":
        out = sum(e["bytes_out"] for e in run if isinstance(e.get("bytes_out"), (int, float)))
        back = sum(e["bytes_in"] for e in run if isinstance(e.get("bytes_in"), (int, float)))
        note = f"{_fmt_size(out)} sent and {_fmt_size(back)} received in total" if (out or back) else None
        return (f"{n} connections by {_v(first, 'process_name')} on {_v(first, 'host')} to {_v(first, 'dst_ip')}:"
                f"{_v(first, 'dst_port')} ({_v(first, 'protocol')}){_every(run)}, the last one at {last}Z"), None, note
    if action == "dns_query":
        names = list(dict.fromkeys(str(e.get("query")) for e in run if e.get("query")))
        sample = ", ".join(names[:2])
        by = f" ({first['process_name']})" if first.get("process_name") else ""
        note = f"{len(names)} different names, for example {sample}" if names else None
        return (f"{n} DNS lookups under {_v(first, 'domain')} from {_v(first, 'host')}{by}{_every(run)}, "
                f"the last one at {last}Z"), None, note
    if action == "mfa_prompt":
        word = MFA_WORDS.get(str(first.get("outcome")), _v(first, "outcome"))
        return (f"{n} MFA {_v(first, 'method')} prompts for {_v(first, 'user')} were {word}, "
                f"the last one at {last}Z"), None, None
    if action == "host_logon":
        hosts = list(dict.fromkeys(str(e.get("host")) for e in run if e.get("host")))
        shown = ", ".join(hosts[:3]) + (f" and {len(hosts) - 3} more" if len(hosts) > 3 else "")
        many = len(hosts) > 1
        times = "" if many and len(hosts) == n else f" {n} times"
        where = f"{len(hosts)} computers" if many else _v(first, "host")
        text = (f"{_v(first, 'user')} logged on{times} to {where} ({_v(first, 'outcome')}, {_logon_how(first)}) "
                f"from {_v(first, 'src_ip')}, the last one at {last}Z")
        return text, None, (shown if many else None)
    if action == "file_create":
        return (f"{_v(first, 'process_name')} created {n} files on {_v(first, 'host')}, the last one at {last}Z"), \
            _clip(first.get("file_path")), None
    if action == "cloud_audit":
        return (f"{_v(first, 'user')} called {_v(first, 'event_name')} {n} times on {_v(first, 'event_source')} "
                f"({_v(first, 'outcome')}), the last one at {last}Z"), None, None
    return f"{n} x {describe_event(first)[0]}", None, None


def build_timeline(window: list[dict], cited: dict[str, list[str]], limit: int = TIMELINE_LIMIT) -> list[dict]:
    """Rows for one case. ``window`` is the events around the case in time order; ``cited`` maps an event id to the
    alert ids that point at it. A row is {ts, kind, text, alerts, detail?, note?, count?}: ``detail`` is text taken from
    the logs (a command, a path), ``note`` is a summary, and ``count`` is how many events a merged row stands for."""
    rows: list[dict] = []
    open_runs: dict[tuple, dict] = {}                # (run key, alert ids) -> the row that is still growing
    i = 0
    while i < len(window):
        ev = window[i]
        alerts = sorted(set(cited.get(ev.get("event_id"), [])))
        if ev.get("action") == "login" and ev.get("outcome") == "failure":
            j = i
            while (j + 1 < len(window) and window[j + 1].get("action") == "login"
                   and window[j + 1].get("outcome") == "failure" and window[j + 1].get("src_ip") == ev.get("src_ip")):
                j += 1
            run = window[i:j + 1]
            users = sorted({str(e.get("user")) for e in run})
            who = users[0] if len(users) == 1 else f"{len(users)} different accounts"
            row = {"ts": run[0]["ts"], "kind": "failures",
                   "text": (f"{len(run)} failed {_v(ev, 'service')} logins from {_v(ev, 'src_ip')} ({_v(ev, 'country')}) "
                            f"against {who}, the last one at {_clock(run[-1])}Z"),
                   "alerts": sorted({a for e in run for a in cited.get(e.get("event_id"), [])}),
                   "_n": len(run)}
            i = j + 1
        else:
            key = run_key(ev)
            slot = (key, tuple(alerts)) if key is not None else None
            current = open_runs.get(slot) if slot else None
            if current is not None and ev.get("_t", 0) - current["_last_t"] <= RUN_GAP_SECONDS:
                current["_events"].append(ev)
                current["_last_t"] = ev.get("_t", current["_last_t"])
                current["_n"] += 1
                i += 1
                continue
            text, detail = describe_event(ev)
            kind = {"login": "login", "process_create": "process", "group_add": "group"}.get(ev.get("action"), str(ev.get("action")))
            row = {"ts": ev["ts"], "kind": kind, "text": text, "alerts": alerts, "_n": 1}
            if detail:
                row["detail"] = detail
            if slot:
                row["_events"], row["_last_t"] = [ev], ev.get("_t", 0)
                open_runs[slot] = row
            i += 1
        if len(rows) < limit:
            rows.append(row)

    shown = sum(r["_n"] for r in rows)
    for row in rows:                                   # now that every run is complete, write its sentence
        events = row.pop("_events", None)
        row.pop("_last_t", None)
        count = row.pop("_n")
        if events and len(events) > 1:
            row["text"], detail, note = describe_run(events)
            row.pop("detail", None)
            if detail:
                row["detail"] = detail
            if note:
                row["note"] = note
        if count > 1:
            row["count"] = count
    if shown < len(window):
        rows.append({"ts": rows[-1]["ts"], "kind": "more", "alerts": [],
                     "text": f"{len(window) - shown} more events are not shown."})
    return rows
