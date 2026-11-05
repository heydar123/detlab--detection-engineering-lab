# Case study: writing detection rules, then trying to break them

> A lab on made-up and public data, not production experience. The numbers below describe this lab.

## The question

A detection rule is easy to write and hard to trust. It fires on the test the author had in mind. Then it meets a backup job,
a vulnerability scanner or an attacker who spells a flag differently, and the author learns what it really does. This
project asks: *what evidence would make a rule worth putting into production, and how much of that evidence can one person
produce in a lab?*

## The approach: four layers of evidence

| Layer | What it checks | What it cannot tell you |
|---|---|---|
| Unit tests inside each rule | The rule fires on what it should and stays quiet on near misses, at the edges of its time windows and its grouping. | Anything about real traffic. |
| Made-up logs with 13 labeled attacks | Precision, recall and time to detect, before and after tuning, with the answer known. | How the rules do on a real network: the same author wrote the attacks and the rules. |
| A red team written to slip past the rules | Where the logic is narrower than the idea behind it. | What other people or real attackers would find. |
| 26 public recordings of real attack tools, split before the results were seen | Whether the rules read real Windows events correctly and catch real tool runs. | A false-positive rate: the recordings hold almost no normal activity. |

On top of the four layers sit two checks of the checks. The mutation check edits each rule in small ways to see whether the
tests notice. The Sigma comparison runs an independent reader over the exported rules to see whether they mean what the
engine means.

## What each layer found

**Unit tests, and a test that tests the tests.** Every rule file carries its own tests, 320 in all. A test is only worth
having if it can fail, so two checks try to make them fail. Each of the 28 exclusions is removed in turn, and a test must go
red (28 of 28 do). Then every rule is edited in small ways (a condition deleted, a listed value dropped, a threshold or a time
window moved by one, a `group_by` field dropped, the alert throttling removed), and some test must notice each of the 247
edits (247 of 247 do). Getting there was not free. The first version of the check edited conditions, listed values and
counts, but not time windows, grouping or throttling. When it was widened, together with the Sigma damage check below, it
exposed rules with no test at the edge of their window (DET-026's 15-minute window had no test at 900 and 901 seconds, for
example) and no test that the count is kept per group, per account or per address. Writing those tests took the suite
from 272 to 320.

**Made-up logs.** Without any exclusions the 32 rules raise 143 alerts, 90 of them false alarms (35% precision). With the
28 documented exclusions: 54 alerts, 1 false positive (98%), and all 13 attacks found. Each exclusion is as narrow as the benign
thing it silences, with a written reason. DET-004's, for example, covers the backup account on the backup server only, so the same
command from another host still alerts. The one false positive left is DET-027, which flags a sign-in from a network provider the account has never used.
A person who travels triggers it. It is kept at low severity on purpose, because it is the rule that catches a stolen login
from the same country (EV-05), which a country check cannot see. A false positive that has a reason is a trade-off made
in the open.

**The red team.** Fifteen attack variants were written to get past the rules, and the report lists nine gaps found and closed.
Examples: the first DET-004 matched `-enc` but not `-ec` or the longer partial spellings of `-EncodedCommand` (EV-03);
building the flag at run time kept it out of every command line, so DET-021 reads the PowerShell script block log instead
(EV-06); and an exclusion for one documented installer address matched the address anywhere in the script, so an attacker
could hide it in a comment (EV-14). The exclusion now matches only the whole documented one-line installer. Six variants
still get through: a jittered beacon, slow exfiltration, a low-rate DNS tunnel, PsExec with a renamed service, a backdoor
account named like the help desk names accounts, and slow MFA fatigue. Each is listed with what would close it. They are
documented rather than patched, because a fix that has not been measured against normal noise is a guess.

**Real recordings.** Of the 29 expectations (written from each recording's attack technique, and for the holdout half before any
rule ran on it), 26 fire. On the holdout half, run once after the rules were frozen, 10 of 12 fired. Two rules were then changed, and the stored first run is kept next to the current result
(11 of 12) so that the improvement is visible and so is its source. DET-009 raised a false alarm on the Azure guest agent,
which opens `lsass.exe` with read rights while listing processes, and got an exclusion pinned to the program, its install
folder and the exact access mask. DET-015 missed the `fodhelper` UAC bypass because Windows logged the registry key under
the `HKU\<SID>_Classes` name, which the first pattern did not know. The two remaining misses are DET-012 on a SharpSC recording
and DET-020 on a PowerShell remoting recording (DET-032 was written afterwards for the start of that session; it adds
context to a case and does not see the command). One expectation, DET-021, could not be tested because its recording
has no PowerShell script-block events. All of it is in
[replay-results.md](replay-results.md).

**Sigma.** Nineteen of the 32 rules export to Sigma. The other 13 need things Sigma cannot say (a sequence, a distance
between two logins, a baseline, a spread of gaps between events, and more), and the reason for each is in [`sigma/INDEX.md`](../sigma/INDEX.md).
To know whether an export means what the rule means, a second, independent reader interprets the Sigma files and is compared
with the engine on 74,549 events times 19 files: no disagreements. That result is worth only as much as the comparison can
notice, so 215 Sigma files were damaged by one edit each: it noticed 170 (79%). The conversions to Splunk and Sentinel
queries were made with pySigma and never run on a live SIEM; two Sentinel conversions failed and two are partial, and the table
says so.

## Time to detect on the made-up logs

Counted from the attack's first malicious event to the first rule that fires.

<!-- generated: time-to-detect -->
| Attack | What it is | First rule to fire | Time to detect |
|---|---|---|---|
| SC-01 | External brute force against a single account | DET-001 | 38s |
| SC-02 | Password spray across the user base | DET-002 | 6m 00s |
| SC-03 | Account takeover kill chain | DET-001 | 2m 52s |
| SC-04 | Impossible travel (US to Romania) | DET-003 | 0s |
| SC-05 | Office document spawns encoded PowerShell | DET-004 | 0s |
| SC-06 | Impossible travel (US to Nigeria) | DET-003 | 0s |
| SC-07 | Full intrusion: phishing to domain credential theft | DET-004 | 0s |
| SC-08 | Cloud account takeover through MFA fatigue | DET-025 | 13m 00s |
| SC-09 | Hands-on-keyboard toolkit with a backdoor account | DET-016 | 0s |
| SC-10 | Beaconing implant on an application server | DET-022 | 11m 05s |
| SC-11 | Bulk exfiltration from the file server | DET-023 | 11m 40s |
| SC-12 | DNS tunnel from a workstation | DET-024 | 3m 15s |
| SC-13 | Network sweep with a stolen service account | DET-032 | 4s |

<!-- /generated -->

Most single-event attacks fire on the event itself (0s). The slow ones are the ones that must see a pattern first. DET-025
(MFA fatigue) fires on the approval that ends a storm of refused prompts, which is 13 minutes after the first prompt.

## Decisions worth explaining

- **Rules are data, not code.** A small matching language in YAML (a mapping means AND, a list means OR, `not:` negates, plus
  modifiers such as `contains`, `regex` and `gt`) keeps rules reviewable, diffable and exportable.
- **Every exclusion has a reason, a test, and a proof it is needed.** The validator rejects an exclusion with no reason.
- **One event schema.** Rules never read vendor field names. The generator and the real recordings are both translated into
  the same 18 kinds of event ([event-schema.md](event-schema.md)), which is why one rule file runs on both.
- **Report both numbers when they differ.** The holdout first run and the current run both appear, with the changes between
  them written up.
- **Export only what Sigma can express, and say what it cannot.** Exclusions are not exported as logic. They appear as known
  false positives.
- **Nothing to install.** The pure-Python part of PyYAML is bundled, so the lab runs on a locked-down laptop.
- **Documents that cannot go stale.** The result tables and the sample reports are generated, and a test fails when any of
  them differs from the lab's current output.

## Open problems

- The six open red-team gaps above.
- A false-positive rate on real data: the lab has no benign baseline from a real network.
- Running the Splunk and Sentinel queries on live data, and recording what had to change.
- More coverage: 28 of 227 ATT&CK parent techniques have a rule.
- A second reviewer for the recording labels.

## Where to look first

1. [`rules/DET-021.yml`](../rules/DET-021.yml): one rule with its logic, exclusion, triage, response and tests.
2. [replay-results.md](replay-results.md): the protocol and every recording.
3. [sample-evasion-report.md](sample-evasion-report.md): what got through and what would close it.
4. [sample-case-report.md](sample-case-report.md): an incident as an analyst would receive it.
5. `python -m detlab app`: the same material as a web page.
