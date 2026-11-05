# Red-team report

These attack variants were written after the first version of the rules, on purpose, to slip past them. Each one names the rule that should catch it. A MISSED row is a documented gap, not a hidden one.

**Result: 9 of 15 variants caught** by the current rules, with 1 false positive on this dataset.

The variants are synthetic and were designed against these specific rules. This measures known blind spots, not how the rules would fare against real attackers.

## Results

| Variant | Attack | Rule that should catch it | Result | Caught by | Time to detect |
|---|---|---|---|---|---|
| EV-01 | Low-and-slow brute force | DET-028 | CAUGHT | DET-028 | 31m 30s |
| EV-02 | Slow password spray | DET-008 | CAUGHT | DET-008 | 1h 50m |
| EV-03 | Encoded PowerShell using short flag spellings | DET-004 | CAUGHT | DET-004 | 0s |
| EV-04 | Self-added to Backup Operators | DET-006 | CAUGHT | DET-006 | 0s |
| EV-05 | Stolen login from a same-country proxy | DET-027 | CAUGHT | DET-027 | 0s |
| EV-06 | Encoded flag built at runtime | DET-021 | CAUGHT | DET-021 | 3s |
| EV-07 | Beacon with heavy timing jitter | DET-022 | MISSED | - | - |
| EV-08 | Slow exfiltration | DET-023 | MISSED | - | - |
| EV-09 | Low-rate DNS tunnel | DET-024 | MISSED | - | - |
| EV-10 | Persistence through the Startup folder | DET-031 | CAUGHT | DET-031 | 0s |
| EV-11 | PsExec with a renamed service | DET-012 | MISSED | - | - |
| EV-12 | Renamed copy of a signed Windows tool | DET-016 | CAUGHT | DET-016 | 0s |
| EV-13 | Backdoor account named like the help desk names accounts | DET-019 | MISSED | - | - |
| EV-14 | Allowed installer address hidden in a comment | DET-021 | CAUGHT | DET-021 | 0s |
| EV-15 | Slow MFA fatigue | DET-025 | MISSED | - | - |

## Gaps found and closed

- **EV-01 Low-and-slow brute force**: 60 failed RDP logins against t.brown from one IP, sent as four bursts of 15 failures with a 10 minute pause between them, so no 5 minute window ever reaches 20. Closed by DET-028. DET-001 (20 failures in 5 minutes) cannot see this. It was closed by adding DET-028 (40 failures in one hour), which was measured against the same scanner noise before shipping. Lockout policy and MFA also stop it.
- **EV-02 Slow password spray**: One IP tries 12 different accounts, one attempt every 10 minutes for 2 hours, so no 30 minute window sees 10 accounts. Closed by DET-008. Count distinct accounts over 24 hours instead of 30 minutes (rule DET-008).
- **EV-03 Encoded PowerShell using short flag spellings**: Two Excel-spawned PowerShell commands that use -ec and -encodedc instead of -enc / -EncodedCommand. Closed by DET-004. Match every accepted shorthand of -EncodedCommand, not just the common ones. The list comes from TrustedSec's article; it was not independently tested on a live host.
- **EV-04 Self-added to Backup Operators**: j.smith adds their own account to Backup Operators on a domain controller. Not Domain Admins, but still a privileged group. Closed by DET-006. Cover the other privileged built-in groups (Backup, Account and Server Operators, Schema Admins).
- **EV-05 Stolen login from a same-country proxy**: a.nguyen logs in from their normal US IP, then an attacker logs in 6 minutes later from a different US IP. Both logins are in the same country. Closed by DET-027. A country-level rule (DET-003) cannot see this. It was closed by DET-027, which learns each account's usual network providers (ASN) for a week and flags a new one. A person who really travels also triggers it, which is accepted at low severity.
- **EV-06 Encoded flag built at runtime**: The command line builds the -ec flag from pieces ('-e'+'c') so the literal flag never appears in the logged command line. TrustedSec describes this approach. Closed by DET-021. A command-line pattern (DET-004) cannot match text that is not there. It was closed by DET-021, which reads the PowerShell script block log, where the decoded script appears whatever the command line looked like.
- **EV-10 Persistence through the Startup folder**: A shortcut is written into the user's Startup folder instead of a Run registry key. Closed by DET-031. DET-014 only watches the Run keys, so it could not see this. DET-031 was written after this test and now covers the Startup folders.
- **EV-12 Renamed copy of a signed Windows tool**: mshta.exe copied to C:\Users\Public\ms.exe and run against a remote HTA page. Closed by DET-016. The tool rules match the name stored inside the program file (original_name) as well as the file name, so a copy with a new name is still caught.
- **EV-14 Allowed installer address hidden in a comment**: On the help desk workstation, a download-and-run script has the Chocolatey installer address added as a comment, which is what the exclusion looks for. Closed by DET-021. Fixed in v5. The first version of the exclusion matched the address as plain text anywhere in the script. It now matches only the whole documented one-line installer.

## Open gaps and what would close them

### EV-07 - Beacon with heavy timing jitter

The implant on SRV-DB-01 still calls out about every minute, but each wait is a random 30 to 90 seconds instead of 60 plus or minus 8 percent.

**What would close it:** The rule only accepts gaps that vary by less than 15 percent. Raising that limit also lets ordinary traffic through, so it needs a second signal (a destination no other host ever contacts, or a program that has no business making outside connections). Not fixed.

### EV-08 - Slow exfiltration

40 MiB per hour to one outside address for five days (4.7 GiB in total), so no single hour reaches 1 GiB.

**What would close it:** Add a 24 hour rule with a threshold near 2 GiB per destination, then measure how much noise it adds from backups before shipping it. Not fixed.

### EV-09 - Low-rate DNS tunnel

One lookup of a new random name every 20 seconds for two hours, so only 30 names per 10 minutes.

**What would close it:** Add a longer window plus a measure of how random the left-most label looks (entropy), or watch for one domain that is only ever asked TXT questions. Not fixed.

### EV-11 - PsExec with a renamed service

PsExec started with its rename option, so the service is called svcupd and the program is %SystemRoot%\svcupd.exe instead of PSEXESVC.

**What would close it:** DET-012 looks for known tool names and risky paths, and a plain name under SystemRoot looks normal. It needs the file creation that comes first (a program written over the network into ADMIN$) joined to the service install. Not fixed.

### EV-13 - Backdoor account named like the help desk names accounts

Using the help desk admin's login on the domain controller, the attacker creates an account called z.contractor, which fits the onboarding naming pattern.

**What would close it:** This is the price of the documented exclusion. It stays narrow (one admin, one host, one naming pattern) but it cannot tell a real new hire from a lookalike. A ticket check or a daily review of new accounts would close it. Not fixed.

### EV-15 - Slow MFA fatigue

Six prompts are refused 35 minutes apart, then one is approved, so no 30 minute window contains more than a couple of failures.

**What would close it:** Add a rule over a longer window (for example 3 failures in 4 hours then an approval from a new address). Not fixed.

