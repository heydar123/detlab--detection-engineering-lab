"""Replay real public attack logs through the same rules.

The synthetic lab proves the method. This module tests it on something nobody here wrote: Windows event
logs recorded while real attack tools (Mimikatz, PsExec, Empire, Covenant ...) ran in a research lab. They come
from the OTRF "Security Datasets" project (MIT license), unmodified, pinned to one commit.

Three steps, kept apart on purpose:

1. read   - open a dataset (a zip holding one JSON-lines file of raw Windows events).
2. translate - turn each raw event into the shared event schema (see schema.py), so the same rule files run.
3. replay - run the rules, then compare with what the manifest says should fire and with the reviewed labels.

Nothing here executes anything from the data. Fields are only read as text.
"""

from __future__ import annotations

import calendar
import hashlib
import io
import ipaddress
import json
import re
import zipfile
from pathlib import Path

from .engine import run_rules
from .matching import matches
from .models import fmt_ts

MAX_EVENTS = 250_000          # a safety limit per dataset
MAX_UNZIPPED = 200_000_000    # bytes; refuse a zip that expands past this

_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?Z?$")
_TIME_FIELDS = ("@timestamp", "TimeCreated", "UtcTime", "EventTime")


# ------------------------------------------------------------------ reading

def parse_time(value) -> float | None:
    """Parse '2020-10-22T03:52:05.773Z' or '2020-10-22 07:52:05.773' as UTC seconds (with milliseconds)."""
    m = _TIME_RE.match(str(value).strip()) if value is not None else None
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    frac = float("0." + m.group(7)) if m.group(7) else 0.0
    try:
        return calendar.timegm((y, mo, d, h, mi, s)) + frac
    except (ValueError, OverflowError):
        return None


def read_raw_events(zf: zipfile.ZipFile) -> list[dict]:
    """The raw events of one dataset zip: the JSON-lines file inside it, parsed as plain data."""
    members = [i for i in zf.infolist()
               if i.filename.lower().endswith(".json") and not i.filename.startswith("__MACOSX")]
    if not members:
        raise ValueError("no .json file inside the dataset zip")
    info = members[0]
    if info.file_size > MAX_UNZIPPED:
        raise ValueError(f"{info.filename} is larger than {MAX_UNZIPPED:,} bytes unzipped")
    events: list[dict] = []
    with zf.open(info) as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except ValueError:
                continue
            if isinstance(ev, dict):
                events.append(ev)
            if len(events) > MAX_EVENTS:
                raise ValueError(f"more than {MAX_EVENTS:,} events in one dataset")
    return events


def open_pack(pack_path: str | Path, name: str) -> list[dict]:
    """Read one dataset out of the single-file pack (a zip of the original dataset zips)."""
    with zipfile.ZipFile(pack_path) as pack:
        inner = zipfile.ZipFile(io.BytesIO(pack.read(name)))
        return read_raw_events(inner)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -------------------------------------------------------------- translating

def _text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-", "(null)") else text


def _name(path) -> str | None:
    text = _text(path)
    if not text:
        return None
    return text.strip('"').replace("/", "\\").rsplit("\\", 1)[-1] or None


def _account(value) -> str | None:
    text = _text(value)
    return text.rsplit("\\", 1)[-1] if text else None


def _first(ev: dict, *keys: str) -> str | None:
    for key in keys:
        value = _text(ev.get(key))
        if value is not None:
            return value
    return None


def _scope(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return "internal" if (addr.is_private or addr.is_loopback or addr.is_link_local) else "external"


def _dn_name(member) -> str | None:
    text = _text(member)
    if not text:
        return None
    m = re.match(r"(?i)^cn=([^,]+)", text)
    return m.group(1) if m else text


def _task_command(xml: str | None) -> str | None:
    if not xml:
        return None
    cmd = re.search(r"<Command>(.*?)</Command>", xml, re.S)
    args = re.search(r"<Arguments>(.*?)</Arguments>", xml, re.S)
    if not cmd:
        return None
    return (cmd.group(1).strip() + (" " + args.group(1).strip() if args else "")).strip()


def _channel(ev: dict) -> str:
    c = str(ev.get("Channel") or "").lower()
    if "sysmon" in c:
        return "sysmon"
    if c == "security":
        return "security"
    if c == "system":
        return "system"
    if "powershell/operational" in c:
        return "powershell"
    return c


def _event_id(ev: dict) -> int:
    try:
        return int(ev.get("EventID"))
    except (TypeError, ValueError):
        return -1


def _event_time(ev: dict) -> float | None:
    for key in _TIME_FIELDS:
        t = parse_time(ev.get(key))
        if t is not None:
            return t
    return None


def _sysmon_process(ev):
    return {"action": "process_create", "user": _account(ev.get("User")),
            "process_path": _text(ev.get("Image")), "process_name": _name(ev.get("Image")),
            "parent_path": _text(ev.get("ParentImage")), "parent_process": _name(ev.get("ParentImage")),
            "command_line": _text(ev.get("CommandLine")), "parent_command_line": _text(ev.get("ParentCommandLine")),
            "original_name": _text(ev.get("OriginalFileName")), "integrity": _text(ev.get("IntegrityLevel"))}


def _security_process(ev):
    return {"action": "process_create", "user": _account(ev.get("SubjectUserName")),
            "process_path": _text(ev.get("NewProcessName")), "process_name": _name(ev.get("NewProcessName")),
            "parent_path": _text(ev.get("ParentProcessName")), "parent_process": _name(ev.get("ParentProcessName")),
            "command_line": _text(ev.get("CommandLine"))}


def _sysmon_network(ev):
    dst = _text(ev.get("DestinationIp"))
    return {"action": "network_connect", "user": _account(ev.get("User")),
            "process_path": _text(ev.get("Image")), "process_name": _name(ev.get("Image")),
            "src_ip": _text(ev.get("SourceIp")), "src_port": _text(ev.get("SourcePort")),
            "dst_ip": dst, "dst_port": _text(ev.get("DestinationPort")), "dst_scope": _scope(dst),
            "protocol": _text(ev.get("Protocol"))}


def _sysmon_access(ev):
    return {"action": "process_access", "process_path": _text(ev.get("SourceImage")),
            "process_name": _name(ev.get("SourceImage")), "target_path": _text(ev.get("TargetImage")),
            "target_process": _name(ev.get("TargetImage")), "granted_access": _text(ev.get("GrantedAccess")),
            "call_trace": _text(ev.get("CallTrace"))}


def _sysmon_file(ev):
    return {"action": "file_create", "user": _account(ev.get("User")), "process_path": _text(ev.get("Image")),
            "process_name": _name(ev.get("Image")), "file_path": _text(ev.get("TargetFilename"))}


def _sysmon_registry(ev):
    return {"action": "registry_set", "user": _account(ev.get("User")), "process_path": _text(ev.get("Image")),
            "process_name": _name(ev.get("Image")), "registry_key": _text(ev.get("TargetObject")),
            "registry_value": _text(ev.get("Details"))}


def _sysmon_dns(ev):
    query = _text(ev.get("QueryName"))
    return {"action": "dns_query", "user": _account(ev.get("User")), "process_name": _name(ev.get("Image")),
            "query": query, "domain": ".".join(query.split(".")[-2:]) if query else None}


def _logon(ev):
    ok = _event_id(ev) == 4624
    return {"action": "host_logon", "outcome": "success" if ok else "failure",
            "user": _account(ev.get("TargetUserName")), "logon_type": _text(ev.get("LogonType")),
            "src_ip": _text(ev.get("IpAddress"))}


def _service(ev):
    return {"action": "service_install", "user": _account(ev.get("SubjectUserName")),
            "service_name": _first(ev, "ServiceName"),
            "service_path": _first(ev, "ServiceFileName", "ImagePath"),
            "service_account": _first(ev, "ServiceAccount", "AccountName")}


def _task(ev):
    xml = _text(ev.get("TaskContent"))
    return {"action": "scheduled_task_create", "user": _account(ev.get("SubjectUserName")),
            "task_name": _text(ev.get("TaskName")), "task_command": _task_command(xml)}


def _user_create(ev):
    return {"action": "user_create", "user": _account(ev.get("SubjectUserName")),
            "target_user": _account(ev.get("TargetUserName"))}


def _group_add(ev):
    return {"action": "group_add", "user": _account(ev.get("SubjectUserName")),
            "target_user": _dn_name(ev.get("MemberName")) or _text(ev.get("MemberSid")),
            "group": _text(ev.get("TargetUserName"))}


def _directory(ev):
    return {"action": "directory_access", "user": _account(ev.get("SubjectUserName")),
            "object_type": _text(ev.get("ObjectType")), "access_mask": _text(ev.get("AccessMask")),
            "properties": _text(ev.get("Properties"))}


def _log_clear(ev):
    return {"action": "log_clear", "user": _account(ev.get("SubjectUserName")),
            "log_name": _text(ev.get("Channel")) or "unknown"}


def _audit(ev):
    return {"action": "audit_policy_change", "user": _account(ev.get("SubjectUserName")),
            "subcategory": _first(ev, "SubcategoryId", "SubcategoryGuid"),
            "audit_changes": _text(ev.get("AuditPolicyChanges"))}


def _scriptblock(ev):
    return {"action": "powershell_scriptblock", "user": None, "script_text": _text(ev.get("ScriptBlockText"))}


# (channel, event id) -> translator. Process creation and service installs can come from two sources;
# `translate` keeps only one of them per dataset (see below).
TRANSLATORS = {
    ("sysmon", 1): _sysmon_process, ("security", 4688): _security_process,
    ("sysmon", 3): _sysmon_network, ("sysmon", 10): _sysmon_access, ("sysmon", 11): _sysmon_file,
    ("sysmon", 13): _sysmon_registry, ("sysmon", 22): _sysmon_dns,
    ("security", 4624): _logon, ("security", 4625): _logon,
    ("security", 4697): _service, ("system", 7045): _service,
    ("security", 4698): _task, ("security", 4720): _user_create,
    ("security", 4728): _group_add, ("security", 4732): _group_add, ("security", 4756): _group_add,
    ("security", 4662): _directory, ("security", 1102): _log_clear, ("system", 104): _log_clear,
    ("security", 4719): _audit, ("powershell", 4104): _scriptblock,
}
SOURCE_NAMES = {"sysmon": "sysmon", "security": "security", "system": "windows-system",
                "powershell": "powershell"}


def translate(raw_events: list[dict]) -> list[dict]:
    """Raw Windows events -> events in the shared schema, sorted by time, with ids.

    Where two logs record the same thing, only one is kept so a rule does not alert twice:
    Sysmon process creation is preferred to Security 4688, and Security 4697 to System 7045.
    """
    present = {(_channel(e), _event_id(e)) for e in raw_events}
    skip: set[tuple[str, int]] = set()
    if ("sysmon", 1) in present:
        skip.add(("security", 4688))
    if ("security", 4697) in present:
        skip.add(("system", 7045))

    rows: list[tuple[float, int, dict]] = []
    for n, ev in enumerate(raw_events):
        key = (_channel(ev), _event_id(ev))
        fn = TRANSLATORS.get(key)
        if fn is None or key in skip:
            continue
        t = _event_time(ev)
        if t is None:
            continue
        fields = fn(ev)
        if fields.get("user") is None and key[0] == "sysmon":
            fields.pop("user", None)
        out = {k: v for k, v in fields.items() if v is not None}
        out["host"] = _text(ev.get("Hostname")) or "unknown"
        out["source"] = SOURCE_NAMES.get(key[0], key[0])
        rows.append((t, n, out))
    rows.sort(key=lambda r: (r[0], r[1]))
    events = []
    for i, (t, _, out) in enumerate(rows, start=1):
        events.append({"event_id": f"r{i:06d}", "ts": fmt_ts(int(t)), "_t": t, **out})
    return events


# ---------------------------------------------------------------- replaying

def replay_dataset(rules: list[dict], events: list[dict], use_exclusions: bool = True) -> list:
    return run_rules(events, rules, use_exclusions=use_exclusions)


def label_alert(alert, events_by_id: dict, markers: list | None) -> str:
    """'attack' when the alert's evidence touches an event the dataset's markers describe, else 'other'."""
    if not markers:
        return "unlabeled"
    for eid in alert.event_ids:
        ev = events_by_id.get(eid)
        if ev is not None and matches(ev, markers):
            return "attack"
    return "other"
