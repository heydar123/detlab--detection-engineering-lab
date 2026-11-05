# Detection report

Synthetic dataset: 11,865 events, 40 users, 14 days starting 2026-10-01 (seed 7). 13 labeled attack scenarios are hidden in ordinary noise that includes deliberate false-positive sources (a vulnerability scanner, a backup job, a VPN, an approved admin).

## Headline

- Tuned rules: **54 alerts, precision 98%, recall 100%** (48 true positives, 1 false positive).
- Same rules with no exclusions: 143 alerts, precision 35%, recall 100% (90 false positives).

## Per-rule results, before and after tuning

| Rule | Title | Severity | Alerts (untuned) | FP (untuned) | Precision (untuned) | Alerts (tuned) | FP (tuned) | Precision (tuned) | Recall (tuned) |
|---|---|---|---|---|---|---|---|---|---|
| DET-001 | Brute force - many failed logins for one account from one source | medium | 4 | 2 | 50% | 2 | 0 | 100% | 100% |
| DET-002 | Password spray - one source failing against many accounts | high | 3 | 2 | 33% | 1 | 0 | 100% | 100% |
| DET-003 | Impossible travel - successful logins from two countries within an hour | medium | 14 | 11 | 21% | 3 | 0 | 100% | 100% |
| DET-004 | Encoded PowerShell command line | high | 17 | 14 | 18% | 3 | 0 | 100% | 100% |
| DET-005 | Possible account compromise - many failures followed by a success | critical | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-006 | Privileged group membership change by an unapproved account | critical | 3 | 1 | 67% | 2 | 0 | 100% | 100% |
| DET-007 | Discovery commands launched from PowerShell or an Office app | medium | 9 | 4 | 56% | 5 | 0 | 100% | 100% |
| DET-008 | Slow password spray - one source failing against many accounts over 24 hours | high | 3 | 2 | 33% | 1 | 0 | 100% | 100% |
| DET-009 | LSASS memory opened by an unexpected program | critical | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-010 | Credential-dumping command (registry hives, NTDS.dit, comsvcs, ProcDump) | critical | 2 | 0 | 100% | 2 | 0 | 100% | 100% |
| DET-011 | DCSync - directory replication requested by a non-domain-controller account | critical | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-012 | Service installed that runs a shell, a script host, or a file from an admin share | high | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-013 | Scheduled task created with a script, shell, or user-folder action | high | 7 | 6 | 14% | 1 | 0 | 100% | 100% |
| DET-014 | Startup (Run key) entry pointing at a script, shell, or user-folder file | high | 7 | 6 | 14% | 1 | 0 | 100% | 100% |
| DET-015 | UAC bypass - per-user registry hijack of an auto-elevating program | high | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-016 | Signed Windows tool used to run remote or script code (mshta, regsvr32, InstallUtil, cmstp, bitsadmin, certutil) | high | 4 | 2 | 50% | 2 | 0 | 100% | 100% |
| DET-017 | Event log cleared or audit policy weakened | high | 4 | 2 | 50% | 2 | 0 | 100% | 100% |
| DET-018 | Firewall opened for inbound traffic, firewall turned off, or port forward created | medium | 2 | 1 | 50% | 1 | 0 | 100% | 100% |
| DET-019 | New account created (audit event or net user /add) | medium | 4 | 3 | 25% | 1 | 0 | 100% | 100% |
| DET-020 | Remote command run through WMI or WinRM | high | 3 | 2 | 33% | 1 | 0 | 100% | 100% |
| DET-021 | Suspicious PowerShell script text (decode-and-run, download-and-run, credential tools, AMSI tampering) | high | 2 | 1 | 50% | 1 | 0 | 100% | 100% |
| DET-022 | Beaconing - one program contacts one external address at a steady rhythm | medium | 8 | 6 | 14% | 2 | 0 | 100% | 100% |
| DET-023 | Large outbound transfer to one external address | high | 15 | 14 | 7% | 1 | 0 | 100% | 100% |
| DET-024 | DNS tunnel - many different names under one domain from one host | medium | 3 | 2 | 33% | 1 | 0 | 100% | 100% |
| DET-025 | MFA fatigue - many refused or ignored prompts, then an approval | high | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-026 | Network logon fan-out - one account signs in to many computers quickly | high | 3 | 2 | 33% | 1 | 0 | 100% | 100% |
| DET-027 | Sign-in from a network provider this account has never used | low | 4 | 1 | 50% | 4 | 1 | 50% | 100% |
| DET-028 | Slow brute force - 40 failed logins for one account from one source in an hour | medium | 2 | 0 | n/a | 2 | 0 | n/a | n/a |
| DET-029 | Cloud audit logging or threat detection switched off | critical | 1 | 0 | 100% | 1 | 0 | 100% | 100% |
| DET-030 | Cloud access key created without MFA | high | 3 | 2 | 33% | 1 | 0 | 100% | 100% |
| DET-031 | Program, shortcut or script dropped into a Startup folder | medium | 2 | 2 | 0% | 0 | 0 | n/a | n/a |
| DET-032 | Incoming PowerShell remoting (WinRM) session started on this computer | low | 8 | 2 | 75% | 6 | 0 | 100% | 100% |

## MITRE ATT&CK coverage

| Tactic | Technique | Rule | Scenarios detected |
|---|---|---|---|
| Credential Access | T1110.001 Password Guessing | DET-001 | 2/2 |
| Credential Access | T1110.003 Password Spraying | DET-002 | 1/1 |
| Initial Access | T1078 Valid Accounts | DET-003 | 2/2 |
| Execution | T1059.001 PowerShell | DET-004 | 3/3 |
| Credential Access | T1110 Brute Force | DET-005 | 1/1 |
| Persistence | T1098 Account Manipulation | DET-006 | 2/2 |
| Discovery | T1033 System Owner/User Discovery | DET-007 | 3/3 |
| Credential Access | T1110.003 Password Spraying | DET-008 | 1/1 |
| Credential Access | T1003.001 LSASS Memory | DET-009 | 1/1 |
| Credential Access | T1003 OS Credential Dumping | DET-010 | 2/2 |
| Credential Access | T1003.006 DCSync | DET-011 | 1/1 |
| Lateral Movement | T1021.002 SMB/Windows Admin Shares | DET-012 | 1/1 |
| Persistence | T1053.005 Scheduled Task | DET-013 | 1/1 |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | DET-014 | 1/1 |
| Privilege Escalation | T1548.002 Bypass User Account Control | DET-015 | 1/1 |
| Stealth | T1218 System Binary Proxy Execution | DET-016 | 1/1 |
| Defense Impairment | T1685.005 Clear Windows Event Logs | DET-017 | 2/2 |
| Defense Impairment | T1686 Disable or Modify System Firewall | DET-018 | 1/1 |
| Persistence | T1136.001 Create Account - Local Account | DET-019 | 1/1 |
| Lateral Movement | T1047 Windows Management Instrumentation | DET-020 | 1/1 |
| Execution | T1059.001 PowerShell | DET-021 | 1/1 |
| Command and Control | T1071.001 Web Protocols | DET-022 | 1/1 |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol | DET-023 | 1/1 |
| Command and Control | T1071.004 DNS | DET-024 | 1/1 |
| Credential Access | T1621 Multi-Factor Authentication Request Generation | DET-025 | 1/1 |
| Lateral Movement | T1021 Remote Services | DET-026 | 1/1 |
| Initial Access | T1078 Valid Accounts | DET-027 | 1/1 |
| Credential Access | T1110.001 Password Guessing | DET-028 | 0/0 |
| Defense Impairment | T1685.002 Disable or Modify Cloud Log | DET-029 | 1/1 |
| Persistence | T1098.001 Additional Cloud Credentials | DET-030 | 1/1 |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | DET-031 | 0/0 |
| Lateral Movement | T1021.006 Windows Remote Management | DET-032 | 1/1 |

## Attack scenario outcomes and time to detect (tuned rules)

Time to detect is measured from the attack's first malicious event to the moment the first expected rule fired. 0s means the rule fired on the very event that was malicious.

| Scenario | Name | Expected rules | Detected | Missed | First rule to fire | Time to detect |
|---|---|---|---|---|---|---|
| SC-01 | External brute force against a single account | DET-001 | DET-001 | - | DET-001 | 38s |
| SC-02 | Password spray across the user base | DET-002, DET-008 | DET-002, DET-008 | - | DET-002 | 6m 00s |
| SC-03 | Account takeover kill chain | DET-001, DET-005, DET-004, DET-007, DET-006 | DET-001, DET-005, DET-004, DET-007, DET-006 | - | DET-001 | 2m 52s |
| SC-04 | Impossible travel (US to Romania) | DET-003 | DET-003 | - | DET-003 | 0s |
| SC-05 | Office document spawns encoded PowerShell | DET-004, DET-007 | DET-004, DET-007 | - | DET-004 | 0s |
| SC-06 | Impossible travel (US to Nigeria) | DET-003 | DET-003 | - | DET-003 | 0s |
| SC-07 | Full intrusion: phishing to domain credential theft | DET-004, DET-021, DET-014, DET-013, DET-007, DET-015, DET-009, DET-010, DET-017, DET-012, DET-020, DET-011 | DET-004, DET-021, DET-014, DET-013, DET-007, DET-015, DET-009, DET-010, DET-017, DET-012, DET-020, DET-011 | - | DET-004 | 0s |
| SC-08 | Cloud account takeover through MFA fatigue | DET-025, DET-027, DET-030, DET-029 | DET-025, DET-027, DET-030, DET-029 | - | DET-025 | 13m 00s |
| SC-09 | Hands-on-keyboard toolkit with a backdoor account | DET-016, DET-019, DET-006, DET-018, DET-010, DET-017 | DET-016, DET-019, DET-006, DET-018, DET-010, DET-017 | - | DET-016 | 0s |
| SC-10 | Beaconing implant on an application server | DET-022 | DET-022 | - | DET-022 | 11m 05s |
| SC-11 | Bulk exfiltration from the file server | DET-023 | DET-023 | - | DET-023 | 11m 40s |
| SC-12 | DNS tunnel from a workstation | DET-024 | DET-024 | - | DET-024 | 3m 15s |
| SC-13 | Network sweep with a stolen service account | DET-026, DET-032 | DET-026, DET-032 | - | DET-032 | 4s |

## Incident cases

54 alerts were grouped into **14 incident cases** (alerts that share an account, source IP, or host within 2 hours are merged). Against the ground truth: 13 attacks found, 0 split across more than one case, 0 cases mixing different attacks, 1 false-positive case.

| Case | Severity | Alerts | Who / what | Tactics in order | Multi-stage | Rules | Scenario |
|---|---|---|---|---|---|---|---|
| CASE-001 | medium | 2 | j.smith | Credential Access | - | DET-001, DET-028 | SC-01 |
| CASE-002 | high | 2 | 203.0.113.99 | Credential Access | - | DET-002, DET-008 | SC-02 |
| CASE-003 | medium | 1 | SRV-APP-01 | Command and Control | - | DET-022 | SC-10 |
| CASE-004 | low | 1 | t.brown | Initial Access | - | DET-027 | - |
| CASE-005 | critical | 7 | d.okafor | Credential Access -> Execution -> Discovery -> Persistence | yes | DET-001, DET-004, DET-005, DET-006, DET-007, DET-028 | SC-03 |
| CASE-006 | medium | 1 | WS-031 | Command and Control | - | DET-024 | SC-12 |
| CASE-007 | critical | 13 | adm.rossi | Execution -> Persistence -> Discovery -> Privilege Escalation -> Credential Access -> Defense Impairment -> Lateral Movement | yes | DET-004, DET-007, DET-009, DET-010, DET-011, DET-012, DET-013, DET-014, DET-015, DET-017, DET-020, DET-021 | SC-07 |
| CASE-008 | critical | 4 | dev.ops, svc_deploy | Credential Access -> Initial Access -> Persistence -> Defense Impairment | yes | DET-025, DET-027, DET-029, DET-030 | SC-08 |
| CASE-009 | high | 2 | SRV-FILE-01 | Exfiltration -> Command and Control | - | DET-022, DET-023 | SC-11 |
| CASE-010 | critical | 7 | o.novak, support | Stealth -> Persistence -> Defense Impairment -> Credential Access | yes | DET-006, DET-010, DET-016, DET-017, DET-018, DET-019 | SC-09 |
| CASE-011 | medium | 2 | r.patel | Initial Access | - | DET-003, DET-027 | SC-04 |
| CASE-012 | high | 7 | svc_patch | Lateral Movement | - | DET-026, DET-032 | SC-13 |
| CASE-013 | high | 2 | k.lee | Execution -> Discovery | - | DET-004, DET-007 | SC-05 |
| CASE-014 | medium | 3 | s.ivanov | Initial Access | - | DET-003, DET-027 | SC-06 |

## Remaining false positives after tuning

| Rule | Entity | Count |
|---|---|---|
| DET-027 | user=t.brown, asn=AS64505 | 1 |

## Alerts raised (tuned rules)

| Alert | Case | Rule | Severity | First event (UTC) | Fired (UTC) | Entity | Verdict | Scenario |
|---|---|---|---|---|---|---|---|---|
| A-0001 | CASE-001 | DET-001 | medium | 2026-10-05T14:00:00Z | 2026-10-05T14:00:38Z | src_ip=203.0.113.45, user=j.smith | TP | SC-01 |
| A-0002 | CASE-001 | DET-028 | medium | 2026-10-05T14:00:00Z | 2026-10-05T14:01:18Z | src_ip=203.0.113.45, user=j.smith | related | SC-01 |
| A-0003 | CASE-002 | DET-002 | high | 2026-10-07T03:00:01Z | 2026-10-07T03:06:01Z | src_ip=203.0.113.99 | TP | SC-02 |
| A-0004 | CASE-002 | DET-008 | high | 2026-10-07T03:00:01Z | 2026-10-07T03:07:26Z | src_ip=203.0.113.99 | TP | SC-02 |
| A-0005 | CASE-003 | DET-022 | medium | 2026-10-08T08:00:00Z | 2026-10-08T08:11:05Z | host=SRV-APP-01, process_name=rundll32.exe, dst_ip=203.0.113.50 | TP | SC-10 |
| A-0006 | CASE-004 | DET-027 | low | 2026-10-08T20:00:00Z | 2026-10-08T20:00:00Z | user=t.brown, asn=AS64505 | FP | - |
| A-0007 | CASE-005 | DET-001 | medium | 2026-10-09T09:30:02Z | 2026-10-09T09:32:54Z | src_ip=203.0.113.77, user=d.okafor | TP | SC-03 |
| A-0008 | CASE-005 | DET-005 | critical | 2026-10-09T09:30:02Z | 2026-10-09T09:37:00Z | user=d.okafor, src_ip=203.0.113.77 | TP | SC-03 |
| A-0009 | CASE-005 | DET-028 | medium | 2026-10-09T09:30:02Z | 2026-10-09T09:35:51Z | src_ip=203.0.113.77, user=d.okafor | related | SC-03 |
| A-0010 | CASE-005 | DET-004 | high | 2026-10-09T09:48:00Z | 2026-10-09T09:48:00Z | user=d.okafor, host=WS-003 | TP | SC-03 |
| A-0011 | CASE-005 | DET-007 | medium | 2026-10-09T09:50:00Z | 2026-10-09T09:50:00Z | user=d.okafor, host=WS-003 | TP | SC-03 |
| A-0012 | CASE-005 | DET-007 | medium | 2026-10-09T09:53:00Z | 2026-10-09T09:53:00Z | user=d.okafor, host=WS-003 | TP | SC-03 |
| A-0013 | CASE-005 | DET-006 | critical | 2026-10-09T10:05:00Z | 2026-10-09T10:05:00Z | user=d.okafor, target_user=d.okafor, group=Domain Admins | TP | SC-03 |
| A-0014 | CASE-006 | DET-024 | medium | 2026-10-09T16:00:00Z | 2026-10-09T16:03:15Z | host=WS-031, domain=example-c2.net | TP | SC-12 |
| A-0015 | CASE-007 | DET-004 | high | 2026-10-10T09:40:00Z | 2026-10-10T09:40:00Z | user=adm.rossi, host=WS-ADM-01 | TP | SC-07 |
| A-0016 | CASE-007 | DET-021 | high | 2026-10-10T09:40:04Z | 2026-10-10T09:40:04Z | host=WS-ADM-01 | TP | SC-07 |
| A-0017 | CASE-007 | DET-014 | high | 2026-10-10T09:40:35Z | 2026-10-10T09:40:35Z | host=WS-ADM-01, process_name=powershell.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1105\Software\Microsoft\Windows\CurrentVersion\Run\Updater | TP | SC-07 |
| A-0018 | CASE-007 | DET-013 | high | 2026-10-10T09:40:50Z | 2026-10-10T09:40:50Z | user=adm.rossi, host=WS-ADM-01 | TP | SC-07 |
| A-0019 | CASE-007 | DET-007 | medium | 2026-10-10T09:42:00Z | 2026-10-10T09:42:00Z | user=adm.rossi, host=WS-ADM-01 | TP | SC-07 |
| A-0020 | CASE-007 | DET-007 | medium | 2026-10-10T09:42:15Z | 2026-10-10T09:42:15Z | user=adm.rossi, host=WS-ADM-01 | TP | SC-07 |
| A-0021 | CASE-007 | DET-015 | high | 2026-10-10T09:44:00Z | 2026-10-10T09:44:00Z | host=WS-ADM-01, process_name=powershell.exe | TP | SC-07 |
| A-0022 | CASE-007 | DET-009 | critical | 2026-10-10T09:47:00Z | 2026-10-10T09:47:00Z | host=WS-ADM-01, process_name=powershell.exe | TP | SC-07 |
| A-0023 | CASE-007 | DET-010 | critical | 2026-10-10T09:49:00Z | 2026-10-10T09:49:00Z | user=adm.rossi, host=WS-ADM-01, process_name=reg.exe | TP | SC-07 |
| A-0024 | CASE-007 | DET-017 | high | 2026-10-10T09:52:00Z | 2026-10-10T09:52:00Z | user=adm.rossi, host=WS-ADM-01 | TP | SC-07 |
| A-0025 | CASE-007 | DET-012 | high | 2026-10-10T10:00:00Z | 2026-10-10T10:00:00Z | host=SRV-FILE-01, service_name=PSEXESVC, user=adm.rossi | TP | SC-07 |
| A-0026 | CASE-007 | DET-020 | high | 2026-10-10T10:01:00Z | 2026-10-10T10:01:00Z | user=adm.rossi, host=SRV-FILE-01, parent_process=wmiprvse.exe, process_name=cmd.exe | TP | SC-07 |
| A-0027 | CASE-007 | DET-011 | critical | 2026-10-10T10:10:00Z | 2026-10-10T10:10:00Z | user=adm.rossi, host=DC-01 | TP | SC-07 |
| A-0028 | CASE-008 | DET-025 | high | 2026-10-11T02:10:00Z | 2026-10-11T02:23:00Z | user=dev.ops | TP | SC-08 |
| A-0029 | CASE-008 | DET-027 | low | 2026-10-11T02:23:30Z | 2026-10-11T02:23:30Z | user=dev.ops, asn=AS64533 | TP | SC-08 |
| A-0030 | CASE-008 | DET-030 | high | 2026-10-11T02:30:00Z | 2026-10-11T02:30:00Z | user=dev.ops, target_user=svc_deploy, src_ip=203.0.113.131 | TP | SC-08 |
| A-0031 | CASE-008 | DET-029 | critical | 2026-10-11T02:41:00Z | 2026-10-11T02:41:00Z | user=dev.ops, event_name=StopLogging, resource=main-trail | TP | SC-08 |
| A-0032 | CASE-009 | DET-022 | medium | 2026-10-11T23:10:00Z | 2026-10-11T23:28:20Z | host=SRV-FILE-01, process_name=rclone.exe, dst_ip=203.0.113.88 | related | SC-11 |
| A-0033 | CASE-009 | DET-023 | high | 2026-10-11T23:10:00Z | 2026-10-11T23:21:40Z | host=SRV-FILE-01, dst_ip=203.0.113.88 | TP | SC-11 |
| A-0034 | CASE-010 | DET-016 | high | 2026-10-12T14:00:00Z | 2026-10-12T14:00:00Z | user=o.novak, host=WS-026, process_name=mshta.exe | TP | SC-09 |
| A-0035 | CASE-010 | DET-016 | high | 2026-10-12T14:00:40Z | 2026-10-12T14:00:40Z | user=o.novak, host=WS-026, process_name=certutil.exe | TP | SC-09 |
| A-0036 | CASE-010 | DET-019 | medium | 2026-10-12T14:01:30Z | 2026-10-12T14:01:30Z | user=o.novak, host=WS-026 | TP | SC-09 |
| A-0037 | CASE-010 | DET-006 | critical | 2026-10-12T14:01:40Z | 2026-10-12T14:01:40Z | user=o.novak, target_user=support, group=Administrators | TP | SC-09 |
| A-0038 | CASE-010 | DET-018 | medium | 2026-10-12T14:02:30Z | 2026-10-12T14:02:30Z | user=o.novak, host=WS-026 | TP | SC-09 |
| A-0039 | CASE-010 | DET-010 | critical | 2026-10-12T14:03:20Z | 2026-10-12T14:03:20Z | user=o.novak, host=WS-026, process_name=reg.exe | TP | SC-09 |
| A-0040 | CASE-010 | DET-017 | high | 2026-10-12T14:04:20Z | 2026-10-12T14:04:20Z | user=o.novak, host=WS-026 | TP | SC-09 |
| A-0041 | CASE-011 | DET-003 | medium | 2026-10-12T14:05:00Z | 2026-10-12T14:22:00Z | user=r.patel, from=US, to=RO | TP | SC-04 |
| A-0042 | CASE-011 | DET-027 | low | 2026-10-12T14:22:00Z | 2026-10-12T14:22:00Z | user=r.patel, asn=AS64530 | related | SC-04 |
| A-0043 | CASE-012 | DET-026 | high | 2026-10-13T11:20:00Z | 2026-10-13T11:21:52Z | user=svc_patch, src_ip=198.51.100.215 | TP | SC-13 |
| A-0044 | CASE-012 | DET-032 | low | 2026-10-13T11:20:04Z | 2026-10-13T11:20:04Z | user=svc_patch, host=SRV-FILE-01 | TP | SC-13 |
| A-0045 | CASE-012 | DET-032 | low | 2026-10-13T11:20:20Z | 2026-10-13T11:20:20Z | user=svc_patch, host=SRV-IAM-01 | TP | SC-13 |
| A-0046 | CASE-012 | DET-032 | low | 2026-10-13T11:20:36Z | 2026-10-13T11:20:36Z | user=svc_patch, host=SRV-PATCH-01 | TP | SC-13 |
| A-0047 | CASE-012 | DET-032 | low | 2026-10-13T11:20:52Z | 2026-10-13T11:20:52Z | user=svc_patch, host=SRV-REPO-01 | TP | SC-13 |
| A-0048 | CASE-012 | DET-032 | low | 2026-10-13T11:21:08Z | 2026-10-13T11:21:08Z | user=svc_patch, host=SRV-LOG-01 | TP | SC-13 |
| A-0049 | CASE-012 | DET-032 | low | 2026-10-13T11:21:24Z | 2026-10-13T11:21:24Z | user=svc_patch, host=SRV-APP-01 | TP | SC-13 |
| A-0050 | CASE-013 | DET-004 | high | 2026-10-13T15:20:00Z | 2026-10-13T15:20:00Z | user=k.lee, host=WS-005 | TP | SC-05 |
| A-0051 | CASE-013 | DET-007 | medium | 2026-10-13T15:21:00Z | 2026-10-13T15:21:00Z | user=k.lee, host=WS-005 | TP | SC-05 |
| A-0052 | CASE-014 | DET-003 | medium | 2026-10-14T16:40:00Z | 2026-10-14T16:48:00Z | user=s.ivanov, from=US, to=NG | TP | SC-06 |
| A-0053 | CASE-014 | DET-003 | medium | 2026-10-14T16:48:00Z | 2026-10-14T17:44:50Z | user=s.ivanov, from=NG, to=US | TP | SC-06 |
| A-0054 | CASE-014 | DET-027 | low | 2026-10-14T16:48:00Z | 2026-10-14T16:48:00Z | user=s.ivanov, asn=AS64534 | related | SC-06 |

## False positives before tuning

| Rule | Entity | False-positive alerts |
|---|---|---|
| DET-001 | src_ip=10.0.5.50, user=svc_backup | 2 |
| DET-002 | src_ip=10.0.5.50 | 2 |
| DET-003 | user=m.garcia | 11 |
| DET-004 | user=svc_backup, host=BACKUP-01 | 14 |
| DET-006 | user=it.admin, target_user=svc_patch, group=Administrators | 1 |
| DET-007 | user=svc_backup, host=BACKUP-01 | 4 |
| DET-008 | src_ip=10.0.5.50 | 2 |
| DET-013 | user=svc_updater, host=WS-020 | 2 |
| DET-013 | user=svc_updater, host=WS-021 | 2 |
| DET-013 | user=svc_updater, host=WS-022 | 2 |
| DET-014 | host=WS-009, process_name=Teams.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1200\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams | 1 |
| DET-014 | host=WS-010, process_name=Teams.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1201\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams | 1 |
| DET-014 | host=WS-011, process_name=Teams.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1202\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams | 1 |
| DET-014 | host=WS-012, process_name=Teams.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1203\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams | 1 |
| DET-014 | host=WS-013, process_name=Teams.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1204\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams | 1 |
| DET-014 | host=WS-014, process_name=Teams.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1205\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams | 1 |
| DET-016 | user=svc_updater, host=SRV-REPO-01, process_name=bitsadmin.exe | 2 |
| DET-017 | user=svc_logrotate, host=SRV-LOG-01 | 2 |
| DET-018 | user=it.admin, host=SRV-FILE-01 | 1 |
| DET-019 | user=it.admin, host=DC-01 | 3 |
| DET-020 | user=svc_monitor, host=SRV-FILE-01, parent_process=wmiprvse.exe, process_name=cmd.exe | 2 |
| DET-021 | host=WS-001 | 1 |
| DET-022 | host=WS-020, process_name=patchagent.exe, dst_ip=192.0.2.200 | 2 |
| DET-022 | host=WS-021, process_name=patchagent.exe, dst_ip=192.0.2.200 | 2 |
| DET-022 | host=WS-022, process_name=patchagent.exe, dst_ip=192.0.2.200 | 2 |
| DET-023 | host=BACKUP-01, dst_ip=192.0.2.180 | 14 |
| DET-024 | host=WS-023, domain=avcloud.example | 2 |
| DET-026 | user=svc_scan, src_ip=10.0.5.50 | 2 |
| DET-027 | user=t.brown, asn=AS64505 | 1 |
| DET-030 | user=svc_ci, target_user=svc_ci, src_ip=10.0.9.20 | 2 |
| DET-031 | host=WS-024, process_name=msiexec.exe | 1 |
| DET-031 | host=WS-025, process_name=msiexec.exe | 1 |
| DET-032 | user=it.admin, host=SRV-APP-01 | 2 |
