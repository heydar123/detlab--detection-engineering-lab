"""The event schema: the field names every log source is translated into.

Rules never look at raw vendor field names. Every event, whether it comes from the synthetic generator
or from a real Windows log, is translated into this small shared vocabulary first (the same idea as
Sigma's field mappings or Elastic's ECS). That is what lets one rule file run on both kinds of data.

Each event has an ``action`` that says what happened, plus the fields listed for that action.
Fields marked "common" can appear on any event.
"""

from __future__ import annotations

import difflib

COMMON_FIELDS = {
    "event_id": "Unique ID of the event inside one dataset.",
    "ts": "Event time in UTC (second resolution, ISO 8601).",
    "action": "What happened. One of the action names in this file.",
    "category": "Broad kind of event (older field, kept for readability).",
    "host": "Computer that recorded the event.",
    "user": "Account that performed the action.",
    "source": "Which log source produced the event, for example sysmon or security.",
}

# action -> (what it means, where it comes from on Windows, {field: meaning})
ACTIONS: dict[str, dict] = {
    "login": {
        "about": "A sign-in to an identity provider, VPN or gateway.",
        "windows": "Identity provider or gateway logs (not a Windows event).",
        "fields": {
            "outcome": "success or failure.",
            "src_ip": "Where the sign-in came from.",
            "country": "Two-letter country of src_ip.",
            "asn": "Network provider (autonomous system) of src_ip.",
            "service": "What was signed in to (o365, rdp, ssh, vpn).",
            "device_id": "Identifier of the device that signed in, when known.",
        },
    },
    "host_logon": {
        "about": "A sign-in to one computer.",
        "windows": "Security 4624 (success) and 4625 (failure).",
        "fields": {
            "outcome": "success or failure.",
            "logon_type": "Windows logon type: 2 console, 3 network, 10 remote desktop.",
            "src_ip": "Where the sign-in came from.",
        },
    },
    "mfa_prompt": {
        "about": "A multi-factor sign-in prompt sent to a person.",
        "windows": "Identity provider logs (not a Windows event).",
        "fields": {
            "outcome": "approved, denied or timeout.",
            "method": "push, sms or totp.",
            "src_ip": "Where the sign-in that triggered the prompt came from.",
            "country": "Two-letter country of src_ip.",
        },
    },
    "process_create": {
        "about": "A program started.",
        "windows": "Sysmon 1, or Security 4688 when Sysmon is not installed.",
        "fields": {
            "process_name": "File name of the program, for example powershell.exe.",
            "process_path": "Full path of the program.",
            "parent_process": "File name of the program that started it.",
            "parent_path": "Full path of the parent.",
            "command_line": "The full command line.",
            "parent_command_line": "Command line of the parent.",
            "original_name": "File name stored inside the program file (helps spot renamed tools).",
            "integrity": "Integrity level (Medium, High, System).",
        },
    },
    "process_access": {
        "about": "One program opened another program's memory.",
        "windows": "Sysmon 10 (ProcessAccess).",
        "fields": {
            "process_name": "The program doing the access (the source).",
            "process_path": "Full path of the source.",
            "target_process": "File name of the program that was accessed.",
            "target_path": "Full path of the target.",
            "granted_access": "Access mask that was granted, as hex text.",
            "call_trace": "Call stack of the access.",
        },
    },
    "registry_set": {
        "about": "A registry value was written.",
        "windows": "Sysmon 13 (RegistryEvent, value set).",
        "fields": {
            "process_name": "Program that wrote the value.",
            "process_path": "Full path of that program.",
            "registry_key": "Full registry path that was written.",
            "registry_value": "The data that was written, as text.",
        },
    },
    "file_create": {
        "about": "A file was created.",
        "windows": "Sysmon 11 (FileCreate).",
        "fields": {
            "process_name": "Program that created the file.",
            "process_path": "Full path of that program.",
            "file_path": "Full path of the new file.",
        },
    },
    "service_install": {
        "about": "A Windows service was installed.",
        "windows": "Security 4697 or System 7045.",
        "fields": {
            "service_name": "Name of the service.",
            "service_path": "Command the service runs.",
            "service_account": "Account the service runs as.",
        },
    },
    "scheduled_task_create": {
        "about": "A scheduled task was created.",
        "windows": "Security 4698.",
        "fields": {
            "task_name": "Name of the task.",
            "task_command": "The command the task runs, with arguments.",
        },
    },
    "user_create": {
        "about": "A new local or domain account was created.",
        "windows": "Security 4720.",
        "fields": {"target_user": "The account that was created."},
    },
    "group_add": {
        "about": "An account was added to a group.",
        "windows": "Security 4728, 4732 and 4756.",
        "fields": {
            "target_user": "The account that was added.",
            "group": "The group it was added to.",
        },
    },
    "directory_access": {
        "about": "A directory object was read with special rights.",
        "windows": "Security 4662.",
        "fields": {
            "object_type": "Kind of directory object.",
            "properties": "Property GUIDs that were accessed.",
            "access_mask": "Access mask, as hex text.",
        },
    },
    "log_clear": {
        "about": "A Windows event log was cleared.",
        "windows": "Security 1102 and System 104.",
        "fields": {"log_name": "Which log was cleared."},
    },
    "audit_policy_change": {
        "about": "The audit policy was changed.",
        "windows": "Security 4719.",
        "fields": {
            "subcategory": "The audit subcategory that changed.",
            "audit_changes": "What changed (success or failure auditing on or off).",
        },
    },
    "powershell_scriptblock": {
        "about": "PowerShell ran a block of script (the decoded text).",
        "windows": "Microsoft-Windows-PowerShell/Operational 4104.",
        "fields": {"script_text": "The script text that ran."},
    },
    "network_connect": {
        "about": "One network connection or flow.",
        "windows": "Sysmon 3, or firewall and flow logs.",
        "fields": {
            "process_name": "Program that made the connection, when known.",
            "process_path": "Full path of that program.",
            "src_ip": "Source address.",
            "src_port": "Source port.",
            "dst_ip": "Destination address.",
            "dst_port": "Destination port.",
            "dst_scope": "internal or external (is the destination outside the network).",
            "protocol": "tcp or udp.",
            "bytes_out": "Bytes sent.",
            "bytes_in": "Bytes received.",
        },
    },
    "dns_query": {
        "about": "A DNS lookup.",
        "windows": "Sysmon 22, or DNS server logs.",
        "fields": {
            "query": "The full name that was looked up.",
            "domain": "The registered domain of the query (for example example.com).",
            "query_type": "Record type, for example A or TXT.",
            "process_name": "Program that asked, when known.",
        },
    },
    "cloud_audit": {
        "about": "A cloud control-plane action (AWS CloudTrail style).",
        "windows": "Cloud audit log (not a Windows event).",
        "fields": {
            "event_name": "API call, for example StopLogging.",
            "event_source": "Cloud service, for example cloudtrail.amazonaws.com.",
            "outcome": "success or failure.",
            "src_ip": "Caller address.",
            "country": "Two-letter country of src_ip.",
            "mfa_used": "true or false: was the session protected by MFA.",
            "target_user": "The account the call changed, when there is one.",
            "resource": "What the call touched.",
        },
    },
}

ALL_FIELDS: dict[str, str] = dict(COMMON_FIELDS)
for _a in ACTIONS.values():
    ALL_FIELDS.update(_a["fields"])

# Fields an engine rule type reads that are not event fields (so they are never linted as such).
RULE_ONLY_KEYS = {"not"}


def known_fields(actions: set[str] | None) -> set[str]:
    """Fields a rule may use. With a known action set the check is tighter."""
    if not actions:
        return set(ALL_FIELDS)
    allowed = set(COMMON_FIELDS)
    for name in actions:
        if name in ACTIONS:
            allowed |= set(ACTIONS[name]["fields"])
    return allowed


def suggest(field: str, allowed: set[str]) -> str:
    close = difflib.get_close_matches(field, sorted(allowed), n=1, cutoff=0.6)
    return f" (did you mean '{close[0]}'?)" if close else ""
