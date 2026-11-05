# Replay results: the rules on real attack recordings

The made-up logs show that the method works, but the author wrote both the attacks and the rules. This page is the check
that nobody here wrote: Windows event logs recorded while real attack tools (Mimikatz, PsExec, Empire, Covenant and others)
ran in a research lab. They come from the [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) project (MIT
license), are kept exactly as published, and are pinned to one commit. The licence text is in [NOTICE](../NOTICE).

Run it yourself: `python -m detlab replay` (add `--split holdout`, `--alerts`, or `--dataset NAME`).

## The protocol

The point of the protocol is that the result on the holdout recordings cannot have been tuned.

1. **Expectations first.** `replay/manifest.yml` lists every recording with a checksum and the rules that *should* fire on
   it (`expect`). They were decided from the attack technique each recording is named for, before any rule was run on the
   holdout recordings.
2. **The split is a formula, not a choice.** Take the SHA-256 of the zip file name (with `.zip`). An odd first byte means
   holdout, an even one means development. Nobody picked which recordings go where.
3. **Development recordings may be looked at** while writing rules and exclusions. **Holdout recordings were run once**,
   after the rules were frozen. That first result is stored in `replay/holdout-first-run.json`, together with a checksum
   of every rule file and the hash of the manifest. `replay --freeze` refuses to replace it. A second checksum per rule,
   over the detection logic only, was added to that file the same day, because the ATT&CK labels of five rules were
   updated afterwards and that changes a file without changing what the rule detects. The addendum in the file explains how
   this was checked.
4. **Labels came after.** `replay/labels.yml` says which events are the recorded attack. An alert whose evidence contains
   one is labeled `attack`; every other alert is `other` (for example, an event log cleared before the test starts).
   The labels for the holdout recordings were written only after the first run was stored.
5. **Everything is reported.** The first-run numbers and the current numbers both appear below, every miss is explained, and
   the rules changed after the first run are listed with the reason.

## Results

<!-- generated: summary -->
| Set | Recordings | Expected detections | Fired | Missed | Not testable | Alerts | Part of the attack |
|---|---|---|---|---|---|---|---|
| Development | 14 | 17 | 15 | 1 | 1 | 29 | 24 (83%) |
| Holdout, first run | 12 | 12 | 10 | 2 | 0 | 27 | 22 (81%) |
| Holdout, now | 12 | 12 | 11 | 1 | 0 | 27 | 23 (85%) |
| All, now | 26 | 29 | 26 | 2 | 1 | 56 | 47 (84%) |

The holdout first run was stored on 2026-11-04T20:45:07Z in `replay/holdout-first-run.json`. The recordings are pinned to commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` of the OTRF Security-Datasets repository.
<!-- /generated -->

"Expected detections" counts one per rule a recording is expected to trigger. A recording can expect more than one rule.
"Not testable" means the recording holds no events of the kind the rule reads, so it can say nothing about that rule.

"Part of the attack" is the share of alerts that are labeled `attack`. It is **not** a precision figure: these recordings
contain almost no normal activity, so there is nothing to measure false positives against.

## What changed after the first holdout run

Two rules were changed after the first holdout run, because the run showed a real problem. The first-run result above is the
clean one. The current holdout result is better partly because of these fixes, so it is no longer an independent test.

<!-- generated: changes -->
- **DET-009.** The first run raised one alert on the Azure guest agent (CollectGuestLogs.exe), which lists the processes on the machine and opens lsass.exe with read access. An exclusion was added, pinned to the program name, its install folder and the exact access mask (0x1410). The same behaviour through PowerShell remoting still alerts, on purpose, because remoting is also how Invoke-Mimikatz is run.
- **DET-015.** The first run missed the fodhelper recording. Windows logged the registry key under the HKU\<SID>_Classes name and the first pattern only knew the HKCU\Software\Classes name. The pattern now reads both. This turned a real miss into a hit, so the current holdout result is better than the first run, and both are reported.

<!-- /generated -->

## Every recording

"Events" are the events the rules read, after translation into the [event schema](event-schema.md); recorded events with no
kind in the schema are skipped.

<!-- generated: recordings -->
| Recording | Set | Events | Expected | Result | Alerts: attack / other |
|---|---|---|---|---|---|
| `cmd_dumping_ntds_dit_file_ntdsutil` | dev | 8,034 | DET-010 | fired: DET-010 | 1 / 1 |
| `cmd_netsh_fw_mod_open_ports` | dev | 375 | DET-018 | fired: DET-018 | 1 / 1 |
| `cmd_wevtutil_modify_security_eventlog_path` | dev | 16,938 | DET-017 | fired: DET-017 | 1 / 0 |
| `covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges` | dev | 428 | DET-011 | fired: DET-011 | 1 / 0 |
| `covenant_psremoting_command` | dev | 2,324 | DET-020 | MISSED: DET-020 | 1 / 1 |
| `empire_launcher_sct_regsvr32` | dev | 533 | DET-016 | fired: DET-016 | 3 / 0 |
| `empire_launcher_vbs` | dev | 429 | DET-004, DET-021 | fired: DET-004, DET-021 | 3 / 0 |
| `empire_mimikatz_logonpasswords` | dev | 433 | DET-009, DET-021 | fired: DET-009; not testable: DET-021 | 2 / 0 |
| `empire_persistence_registry_modification_run_keys_elevated_user` | dev | 95 | DET-014 | fired: DET-014 | 1 / 0 |
| `empire_shell_net_localgroup_administrators` | dev | 426 | DET-007 | fired: DET-007 | 1 / 0 |
| `empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod` | dev | 1,058 | DET-020 | fired: DET-020 | 4 / 0 |
| `empire_wmic_add_user_backdoor` | dev | 3,051 | DET-019 | fired: DET-019 | 2 / 0 |
| `psh_cmstp_execution_bypassuac` | dev | 536 | DET-016 | fired: DET-016 | 1 / 1 |
| `psh_lsass_memory_dump_comsvcs` | dev | 87 | DET-009, DET-010 | fired: DET-009, DET-010 | 2 / 1 |
| `auditpol_system_user_auditpolicy_modification` | holdout | 11,743 | DET-017 | fired: DET-017 | 1 / 1 |
| `cmd_bitsadmin_download_psh_script` | holdout | 134 | DET-016 | fired: DET-016 | 1 / 1 |
| `cmd_lsass_memory_dumpert_syscalls` | holdout | 71 | DET-009 | fired: DET-009 | 1 / 1 |
| `covenant_installutil` | holdout | 882 | DET-016 | fired: DET-016 | 1 / 0 |
| `covenant_sharpsc_create_dcerpc_smb_svcctl` | holdout | 1,900 | DET-012 | MISSED: DET-012 | 0 / 0 |
| `empire_psexec_dcerpc_tcp_svcctl` | holdout | 1,828 | DET-012 | fired: DET-012 | 4 / 0 |
| `empire_schtasks_creation_standard_user` | holdout | 624 | DET-013 | fired: DET-013 | 1 / 0 |
| `empire_shell_net_local_users` | holdout | 886 | DET-007 | fired: DET-007 | 1 / 0 |
| `empire_shell_reg_dump_sam` | holdout | 421 | DET-010 | fired: DET-010 | 1 / 0 |
| `empire_smbexec_dcerpc_smb_svcctl` | holdout | 4,880 | DET-012 | fired: DET-012 | 4 / 0 |
| `empire_uac_shellapi_fodhelper` | holdout | 1,166 | DET-015 | fired: DET-015 | 6 / 0 |
| `psh_mshta_html_application_execution` | holdout | 615 | DET-016 | fired: DET-016 | 2 / 1 |

<!-- /generated -->

## Misses and recordings that could not test a rule

These notes are the author's reading of each recording, written after the results were known. They never change what a rule
was expected to do: that stays in `replay/manifest.yml`.

<!-- generated: misses -->
- **DET-020 on `covenant_psremoting_command` (dev).** Missed. The start of the remoting session (wsmprovhost.exe) is in the recording, but the command Get-Process ran inside that process and started no program of its own, so DET-020, which looks for programs started by wsmprovhost.exe, has nothing to match. DET-032 was written afterwards for the session start. It is a low-severity rule that adds context to a case. It does not see the command.
- **DET-012 on `covenant_sharpsc_create_dcerpc_smb_svcctl` (holdout).** Missed, and left as a miss. The service is called Cyb3rWard0g and runs C:\Windows\System32\GruntHTTP2.exe, a plain program path. DET-012 looks at what a service command is made of (shells, script hosts, temp folders, admin shares, known tool names) and this one has none of that. Widening the rule to match this file would only prove that a rule can be bent to fit one recording. What would close it: a rule for a service whose program file was created a few minutes earlier, or a list of service names seen before.
- **DET-021 on `empire_mimikatz_logonpasswords` (dev).** Not testable. The recording has no PowerShell script block events, and those are the only events DET-021 reads. This says nothing about whether the rule works.

<!-- /generated -->

## What this does not show

- **No false-positive rate on real data.** The recordings are short attack runs in a research lab. A rule that fires on them
  may also fire all day on a real network. The made-up logs measure that, and they are made up.
- **The labels are one reviewer's judgment.** The four rules for writing them are at the top of `replay/labels.yml`. A
  second reviewer could label some alerts differently.
- **The development recordings shaped the rules.** That is what development recordings are for, and it is why their
  numbers are higher and are not a test.
- **A look at all 26 came before the split.** Before the split was made, every recording was opened once to see which kinds
  of event and which fields it holds, so the translator could be written. That looked at the shape of the data and not at
  rule output, but it means the holdout recordings were not completely unseen.
- **Event times are collection times.** The replay uses the `@timestamp` field the recordings carry, which is when the
  event was collected, not when Windows wrote it. In the recordings where a host time in UTC can be compared, the
  difference is typically one to three seconds. That cannot change whether a single-event rule fires, and it blurs the
  time windows of the other rule types by seconds.
- **The recordings are old tools in a lab.** They show that the rules read real Windows events correctly and catch these
  tool runs. They say nothing about attackers who know the rules.

## How to reproduce

```
python -m detlab replay                      # all recordings, with the documented exclusions
python -m detlab replay --split holdout      # the holdout set, plus a comparison with the stored first run
python -m detlab replay --alerts             # list every alert under its recording
python -m detlab replay --no-exclusions      # the same without exclusions
```

Do not run `--freeze` again. It exists to store the first holdout run once, and it refuses to overwrite it.
