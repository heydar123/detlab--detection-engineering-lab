# Event schema

Rules never read vendor field names. Every log, from the made-up generator or from a real Windows recording, is first translated into one small shared vocabulary, and the rule files use only those names. It is the same idea as Elastic's ECS or Sigma's field mappings, in miniature, and it is why one rule file runs unchanged on both kinds of data.

This page is generated from `detlab/schema.py` by `python tools/make_docs.py`, so it lists exactly what the code accepts. The validator rejects a rule that uses a field name that is not listed here, and suggests the closest one.

## Fields any event can have

| Field | Meaning |
|---|---|
| `event_id` | Unique ID of the event inside one dataset. |
| `ts` | Event time in UTC (second resolution, ISO 8601). |
| `action` | What happened. One of the action names in this file. |
| `category` | Broad kind of event (older field, kept for readability). |
| `host` | Computer that recorded the event. |
| `user` | Account that performed the action. |
| `source` | Which log source produced the event, for example sysmon or security. |

## The 18 kinds of event

The made-up logs use 17 of them. The other one (`audit_policy_change`) appears only in the real recordings and in rule tests.

### `login`

A sign-in to an identity provider, VPN or gateway. Windows source: Identity provider or gateway logs (not a Windows event).

| Field | Meaning |
|---|---|
| `outcome` | success or failure. |
| `src_ip` | Where the sign-in came from. |
| `country` | Two-letter country of src_ip. |
| `asn` | Network provider (autonomous system) of src_ip. |
| `service` | What was signed in to (o365, rdp, ssh, vpn). |
| `device_id` | Identifier of the device that signed in, when known. |

### `host_logon`

A sign-in to one computer. Windows source: Security 4624 (success) and 4625 (failure).

| Field | Meaning |
|---|---|
| `outcome` | success or failure. |
| `logon_type` | Windows logon type: 2 console, 3 network, 10 remote desktop. |
| `src_ip` | Where the sign-in came from. |

### `mfa_prompt`

A multi-factor sign-in prompt sent to a person. Windows source: Identity provider logs (not a Windows event).

| Field | Meaning |
|---|---|
| `outcome` | approved, denied or timeout. |
| `method` | push, sms or totp. |
| `src_ip` | Where the sign-in that triggered the prompt came from. |
| `country` | Two-letter country of src_ip. |

### `process_create`

A program started. Windows source: Sysmon 1, or Security 4688 when Sysmon is not installed.

| Field | Meaning |
|---|---|
| `process_name` | File name of the program, for example powershell.exe. |
| `process_path` | Full path of the program. |
| `parent_process` | File name of the program that started it. |
| `parent_path` | Full path of the parent. |
| `command_line` | The full command line. |
| `parent_command_line` | Command line of the parent. |
| `original_name` | File name stored inside the program file (helps spot renamed tools). |
| `integrity` | Integrity level (Medium, High, System). |

### `process_access`

One program opened another program's memory. Windows source: Sysmon 10 (ProcessAccess).

| Field | Meaning |
|---|---|
| `process_name` | The program doing the access (the source). |
| `process_path` | Full path of the source. |
| `target_process` | File name of the program that was accessed. |
| `target_path` | Full path of the target. |
| `granted_access` | Access mask that was granted, as hex text. |
| `call_trace` | Call stack of the access. |

### `registry_set`

A registry value was written. Windows source: Sysmon 13 (RegistryEvent, value set).

| Field | Meaning |
|---|---|
| `process_name` | Program that wrote the value. |
| `process_path` | Full path of that program. |
| `registry_key` | Full registry path that was written. |
| `registry_value` | The data that was written, as text. |

### `file_create`

A file was created. Windows source: Sysmon 11 (FileCreate).

| Field | Meaning |
|---|---|
| `process_name` | Program that created the file. |
| `process_path` | Full path of that program. |
| `file_path` | Full path of the new file. |

### `service_install`

A Windows service was installed. Windows source: Security 4697 or System 7045.

| Field | Meaning |
|---|---|
| `service_name` | Name of the service. |
| `service_path` | Command the service runs. |
| `service_account` | Account the service runs as. |

### `scheduled_task_create`

A scheduled task was created. Windows source: Security 4698.

| Field | Meaning |
|---|---|
| `task_name` | Name of the task. |
| `task_command` | The command the task runs, with arguments. |

### `user_create`

A new local or domain account was created. Windows source: Security 4720.

| Field | Meaning |
|---|---|
| `target_user` | The account that was created. |

### `group_add`

An account was added to a group. Windows source: Security 4728, 4732 and 4756.

| Field | Meaning |
|---|---|
| `target_user` | The account that was added. |
| `group` | The group it was added to. |

### `directory_access`

A directory object was read with special rights. Windows source: Security 4662.

| Field | Meaning |
|---|---|
| `object_type` | Kind of directory object. |
| `properties` | Property GUIDs that were accessed. |
| `access_mask` | Access mask, as hex text. |

### `log_clear`

A Windows event log was cleared. Windows source: Security 1102 and System 104.

| Field | Meaning |
|---|---|
| `log_name` | Which log was cleared. |

### `audit_policy_change`

The audit policy was changed. Windows source: Security 4719.

| Field | Meaning |
|---|---|
| `subcategory` | The audit subcategory that changed. |
| `audit_changes` | What changed (success or failure auditing on or off). |

### `powershell_scriptblock`

PowerShell ran a block of script (the decoded text). Windows source: Microsoft-Windows-PowerShell/Operational 4104.

| Field | Meaning |
|---|---|
| `script_text` | The script text that ran. |

### `network_connect`

One network connection or flow. Windows source: Sysmon 3, or firewall and flow logs.

| Field | Meaning |
|---|---|
| `process_name` | Program that made the connection, when known. |
| `process_path` | Full path of that program. |
| `src_ip` | Source address. |
| `src_port` | Source port. |
| `dst_ip` | Destination address. |
| `dst_port` | Destination port. |
| `dst_scope` | internal or external (is the destination outside the network). |
| `protocol` | tcp or udp. |
| `bytes_out` | Bytes sent. |
| `bytes_in` | Bytes received. |

### `dns_query`

A DNS lookup. Windows source: Sysmon 22, or DNS server logs.

| Field | Meaning |
|---|---|
| `query` | The full name that was looked up. |
| `domain` | The registered domain of the query (for example example.com). |
| `query_type` | Record type, for example A or TXT. |
| `process_name` | Program that asked, when known. |

### `cloud_audit`

A cloud control-plane action (AWS CloudTrail style). Windows source: Cloud audit log (not a Windows event).

| Field | Meaning |
|---|---|
| `event_name` | API call, for example StopLogging. |
| `event_source` | Cloud service, for example cloudtrail.amazonaws.com. |
| `outcome` | success or failure. |
| `src_ip` | Caller address. |
| `country` | Two-letter country of src_ip. |
| `mfa_used` | true or false: was the session protected by MFA. |
| `target_user` | The account the call changed, when there is one. |
| `resource` | What the call touched. |

## How a real recording becomes these events

`detlab/realdata.py` reads a recording (Windows event logs as JSON lines), looks at the Windows event ID, and writes one event of the matching kind above with the matching field names. Sysmon event 1 becomes `process_create`, Security 4698 becomes `scheduled_task_create`, and so on; the table above names the Windows source of each kind. A recorded event that has no kind in this list is skipped. Nothing in a recording is ever executed: fields are only read as text.
