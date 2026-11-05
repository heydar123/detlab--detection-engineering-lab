"""Synthetic log generator with labeled attack scenarios.

Everything here is fake: IPs come from the RFC 5737 documentation ranges, users
are invented, and the "encoded PowerShell" payloads decode to harmless echo
statements. The generator is seeded, so the same seed always produces the same
dataset, which makes detection results reproducible.

Ground truth is kept in a separate file (event IDs per attack scenario plus the
rules each scenario is expected to trigger). Detection rules never see it.
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .generate_v5 import EVASION_V5, SCENARIOS_V5, add_v5
from .models import fmt_ts

START = datetime(2026, 10, 1, tzinfo=timezone.utc)  # a Thursday
MIN_DAYS = 14
N_USERS = 40

SCANNER_IP = "10.0.5.50"       # approved vulnerability scanner (benign noise)
VPN_EGRESS_IP = "192.0.2.77"   # corporate VPN exit node in the Netherlands (benign noise)
BACKUP_HOST = "BACKUP-01"

NAMED_USERS = ["a.nguyen", "j.smith", "d.okafor", "r.patel", "k.lee", "m.garcia", "s.ivanov", "t.brown"]
FIRST_INITIALS = list("bcefghlnoprvw")
LAST_NAMES = ["silva", "chen", "khan", "rossi", "novak", "larsen", "murphy", "cohen", "dubois", "sato",
              "reyes", "walker", "hughes", "moreau", "adams", "fischer", "kowalski", "mendez", "yamada",
              "oneill", "castro", "baker", "ortiz", "lindgren"]

BENIGN_PROCESSES = [
    ("chrome.exe", "explorer.exe", "chrome.exe --profile-directory=Default"),
    ("excel.exe", "explorer.exe", "EXCEL.EXE /e"),
    ("powershell.exe", "explorer.exe", "powershell.exe -NoProfile -Command Get-Process"),
    ("powershell.exe", "explorer.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1"),
    ("cmd.exe", "explorer.exe", "cmd.exe /c ipconfig /all"),
    ("teams.exe", "explorer.exe", "Teams.exe --process-start-args"),
]

SCENARIOS = {
    "SC-01": {
        "name": "External brute force against a single account",
        "description": "120 failed RDP logins against j.smith from one external IP in about 4 minutes. No success.",
        "expected_rules": ["DET-001"],
    },
    "SC-02": {
        "name": "Password spray across the user base",
        "description": "One external IP tries two passwords against 30 accounts over 40 minutes; one weak password works.",
        "expected_rules": ["DET-002", "DET-008"],
    },
    "SC-03": {
        "name": "Account takeover kill chain",
        "description": ("Brute force on d.okafor succeeds over RDP, followed by encoded PowerShell on the user's "
                        "workstation, two discovery commands, and the account adding itself to Domain Admins."),
        "expected_rules": ["DET-001", "DET-005", "DET-004", "DET-007", "DET-006"],
    },
    "SC-04": {
        "name": "Impossible travel (US to Romania)",
        "description": "r.patel logs in from the US, then from Romania 17 minutes later.",
        "expected_rules": ["DET-003"],
    },
    "SC-05": {
        "name": "Office document spawns encoded PowerShell",
        "description": "winword.exe launches a hidden, encoded PowerShell command on k.lee's workstation, then runs whoami.",
        "expected_rules": ["DET-004", "DET-007"],
    },
    "SC-06": {
        "name": "Impossible travel (US to Nigeria)",
        "description": "s.ivanov logs in from the US, then from Nigeria 8 minutes later.",
        "expected_rules": ["DET-003"],
    },
}


# Red-team variants: attacks written to slip past the rules. They are only added when
# generate(..., evasion=True). Each names the rule that SHOULD catch it, so a miss is measurable.
EVASION_SCENARIOS = {
    "EV-01": {
        "name": "Low-and-slow brute force",
        "description": ("60 failed RDP logins against t.brown from one IP, sent as four bursts of 15 failures "
                        "with a 10 minute pause between them, so no 5 minute window ever reaches 20."),
        "expected_rules": ["DET-028"],
        "mitigation": ("DET-001 (20 failures in 5 minutes) cannot see this. It was closed by adding DET-028 (40 "
                       "failures in one hour), which was measured against the same scanner noise before shipping. "
                       "Lockout policy and MFA also stop it."),
    },
    "EV-02": {
        "name": "Slow password spray",
        "description": ("One IP tries 12 different accounts, one attempt every 10 minutes for 2 hours, so no "
                        "30 minute window sees 10 accounts."),
        "expected_rules": ["DET-008"],
        "mitigation": "Count distinct accounts over 24 hours instead of 30 minutes (rule DET-008).",
    },
    "EV-03": {
        "name": "Encoded PowerShell using short flag spellings",
        "description": ("Two Excel-spawned PowerShell commands that use -ec and -encodedc instead of "
                        "-enc / -EncodedCommand."),
        "expected_rules": ["DET-004"],
        "mitigation": ("Match every accepted shorthand of -EncodedCommand, not just the common ones. The list "
                       "comes from TrustedSec's article; it was not independently tested on a live host."),
    },
    "EV-04": {
        "name": "Self-added to Backup Operators",
        "description": ("j.smith adds their own account to Backup Operators on a domain controller. Not Domain "
                        "Admins, but still a privileged group."),
        "expected_rules": ["DET-006"],
        "mitigation": "Cover the other privileged built-in groups (Backup, Account and Server Operators, Schema Admins).",
    },
    "EV-05": {
        "name": "Stolen login from a same-country proxy",
        "description": ("a.nguyen logs in from their normal US IP, then an attacker logs in 6 minutes later from a "
                        "different US IP. Both logins are in the same country."),
        "expected_rules": ["DET-027"],
        "mitigation": ("A country-level rule (DET-003) cannot see this. It was closed by DET-027, which learns each "
                       "account's usual network providers (ASN) for a week and flags a new one. A person who "
                       "really travels also triggers it, which is accepted at low severity."),
    },
    "EV-06": {
        "name": "Encoded flag built at runtime",
        "description": ("The command line builds the -ec flag from pieces ('-e'+'c') so the literal flag never "
                        "appears in the logged command line. TrustedSec describes this approach."),
        "expected_rules": ["DET-021"],
        "mitigation": ("A command-line pattern (DET-004) cannot match text that is not there. It was closed by "
                       "DET-021, which reads the PowerShell script block log, where the decoded script appears "
                       "whatever the command line looked like."),
    },
}


SCENARIOS.update(SCENARIOS_V5)
EVASION_SCENARIOS.update(EVASION_V5)


def enc_ps(command: str) -> str:
    """PowerShell -EncodedCommand format: base64 of UTF-16LE text."""
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def _make_users(rng: random.Random) -> list[dict]:
    names = list(NAMED_USERS)
    seen = set(names)
    while len(names) < N_USERS:
        candidate = f"{rng.choice(FIRST_INITIALS)}.{rng.choice(LAST_NAMES)}"
        if candidate not in seen:
            seen.add(candidate)
            names.append(candidate)
    octets = list(range(10, 250))
    rng.shuffle(octets)
    return [
        {"name": n, "ip": f"198.51.100.{octets[i]}", "host": f"WS-{i + 1:03d}", "country": "US"}
        for i, n in enumerate(names)
    ]


def generate(seed: int = 7, days: int = MIN_DAYS, evasion: bool = False) -> tuple[list[dict], dict]:
    """Return (events, ground_truth). Events are sorted and have event IDs.

    With evasion=True the red-team variants (EV-01..EV-15) are added on top of the normal dataset.
    They use no shared randomness, so evasion=False output is unchanged by them. The version 5 additions
    (generate_v5.py) have their own random generator, so the original events keep their content.
    """
    if days < MIN_DAYS:
        raise ValueError(f"days must be at least {MIN_DAYS} so every attack scenario fits")

    rng = random.Random(seed)
    users = _make_users(rng)
    by_name = {u["name"]: u for u in users}
    raw: list[dict] = []

    def at(day: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
        return START + timedelta(days=day, hours=hour, minutes=minute, seconds=second)

    def emit(t: datetime, sc: str | None, **fields) -> None:
        raw.append({"_t": t, "_sc": sc, **fields})

    def login(t, user, ip, country, outcome, service, sc=None):
        emit(t, sc, category="authentication", action="login", outcome=outcome, user=user,
             src_ip=ip, country=country, service=service, host="auth-gw")

    def proc(t, user, host, name, parent, cmd, sc=None):
        emit(t, sc, category="process", action="process_create", user=user, host=host,
             process_name=name, parent_process=parent, command_line=cmd)

    def group_add(t, actor, target, group, host, sc=None):
        emit(t, sc, category="iam", action="group_add", user=actor, target_user=target,
             group=group, host=host)

    # ------------------------------------------------------------ benign noise
    for day in range(days):
        weekend = at(day).weekday() >= 5
        for u in users:
            if u["name"] == "t.brown" and day == 7:
                continue  # travelling: handled explicitly below
            if weekend and rng.random() > 0.15:
                continue
            for _ in range(rng.randint(1, 2)):
                t = at(day) + timedelta(seconds=rng.randint(12 * 3600, 22 * 3600))
                service = rng.choices(["o365", "rdp", "ssh"], weights=[60, 25, 15])[0]
                if rng.random() < 0.06:  # ordinary typo before a successful login
                    typos = rng.randint(1, 2)
                    for i in range(typos):
                        login(t - timedelta(seconds=(typos - i) * rng.randint(5, 20)),
                              u["name"], u["ip"], u["country"], "failure", service)
                login(t, u["name"], u["ip"], u["country"], "success", service)
            for _ in range(rng.randint(3, 6)):
                t = at(day) + timedelta(seconds=rng.randint(12 * 3600, 22 * 3600))
                name, parent, cmd = rng.choice(BENIGN_PROCESSES)
                proc(t, u["name"], u["host"], name, parent, cmd)

    # Nightly backup job runs an encoded PowerShell command (false-positive source for DET-004).
    backup_cmd = f"powershell.exe -NoProfile -EncodedCommand {enc_ps('Start-Backup -Target D:')}"
    for day in range(days):
        login(at(day, 3, 0), "svc_backup", "10.0.8.10", "US", "success", "ssh")
        proc(at(day, 3, 5), "svc_backup", BACKUP_HOST, "powershell.exe", "taskeng.exe", backup_cmd)

    # Weekly vulnerability scan makes failed logins against everyone (FP source for DET-001, DET-002).
    for day in (5, 11):
        k = 0
        t0 = at(day, 2, 0)
        for u in users:
            for _ in range(2):
                login(t0 + timedelta(seconds=k * 3), u["name"], SCANNER_IP, "US", "failure", "ssh")
                k += 1
        for j in range(30):
            login(t0 + timedelta(seconds=k * 3 + j * 4), "svc_backup", SCANNER_IP, "US", "failure", "ssh")

    # VPN user: US login, then a login that exits via the Netherlands (FP source for DET-003).
    for day in range(days):
        if at(day).weekday() < 5:
            t = at(day, 14, 0) + timedelta(seconds=rng.randint(0, 1800))
            login(t, "m.garcia", by_name["m.garcia"]["ip"], "US", "success", "o365")
            login(t + timedelta(minutes=10), "m.garcia", VPN_EGRESS_IP, "NL", "success", "vpn")

    # Genuine traveller: US one day, UK the next day. Hours apart, so not impossible travel.
    login(at(6, 21, 30), "t.brown", by_name["t.brown"]["ip"], "US", "success", "o365")
    login(at(7, 20, 0), "t.brown", "192.0.2.150", "GB", "success", "o365")

    # Approved admin change (FP source for DET-006), plus an unrelated group change.
    group_add(at(7, 15, 0), "it.admin", "svc_patch", "Administrators", "SRV-FILE-01")
    group_add(at(9, 11, 0), "it.admin", "m.garcia", "VPN-Users", "SRV-IAM-01")

    # Discovery commands that are NOT attacks (test material for DET-007).
    # 1) A weekly inventory script on the backup server (false-positive source, excluded by user AND host).
    for day in (3, 10):  # Sundays
        proc(at(day, 3, 10), "svc_backup", BACKUP_HOST, "whoami.exe", "powershell.exe", "whoami.exe /all")
        proc(at(day, 3, 11), "svc_backup", BACKUP_HOST, "systeminfo.exe", "powershell.exe", "systeminfo.exe")
    # 2) A help desk technician runs whoami from a normal command prompt (parent cmd.exe: should not alert).
    proc(at(2, 10, 30), "it.admin", by_name["a.nguyen"]["host"], "whoami.exe", "cmd.exe", "whoami.exe /all")

    # ------------------------------------------------------- attack scenarios
    # SC-01: external brute force against j.smith
    for i in range(120):
        login(at(4, 14, 0, i * 2), "j.smith", "203.0.113.45", "RU", "failure", "rdp", "SC-01")

    # SC-02: password spray; two rounds across 30 accounts, one weak password succeeds
    targets = rng.sample([u for u in users if u["name"] != "a.nguyen"], 29) + [by_name["a.nguyen"]]
    for rnd in range(2):
        for i, u in enumerate(targets):
            t = at(6, 3, 0) + timedelta(minutes=rnd * 20, seconds=i * 40 + rng.randint(0, 10))
            login(t, u["name"], "203.0.113.99", "CN", "failure", "o365", "SC-02")
    login(at(6, 3, 42), "a.nguyen", "203.0.113.99", "CN", "success", "o365", "SC-02")

    # SC-03: brute force -> success -> encoded PowerShell -> self-added to Domain Admins
    okafor = by_name["d.okafor"]
    for i in range(40):
        login(at(8, 9, 30, i * 9 + rng.randint(0, 3)), "d.okafor", "203.0.113.77", "BR", "failure", "rdp", "SC-03")
    login(at(8, 9, 37), "d.okafor", "203.0.113.77", "BR", "success", "rdp", "SC-03")
    payload = enc_ps("Write-Output 'detlab-sample-payload'")
    proc(at(8, 9, 48), "d.okafor", okafor["host"], "powershell.exe", "cmd.exe",
         f"powershell.exe -nop -w hidden -enc {payload}", "SC-03")
    proc(at(8, 9, 50), "d.okafor", okafor["host"], "whoami.exe", "powershell.exe", "whoami.exe /groups", "SC-03")
    proc(at(8, 9, 53), "d.okafor", okafor["host"], "net.exe", "powershell.exe",
         'net.exe group "Domain Admins" /domain', "SC-03")
    group_add(at(8, 10, 5), "d.okafor", "d.okafor", "Domain Admins", "DC-01", "SC-03")

    # SC-04: impossible travel, US then Romania
    login(at(11, 14, 5), "r.patel", by_name["r.patel"]["ip"], "US", "success", "o365")
    login(at(11, 14, 22), "r.patel", "203.0.113.120", "RO", "success", "o365", "SC-04")

    # SC-05: Word spawns hidden, encoded PowerShell, then discovery
    lee = by_name["k.lee"]
    proc(at(12, 15, 20), "k.lee", lee["host"], "powershell.exe", "winword.exe",
         f"powershell.exe -nop -w hidden -enc {enc_ps('Write-Output detlab-sample-stage1')}", "SC-05")
    proc(at(12, 15, 21), "k.lee", lee["host"], "whoami.exe", "powershell.exe", "whoami.exe /all", "SC-05")

    # SC-06: impossible travel, US then Nigeria
    login(at(13, 16, 40), "s.ivanov", by_name["s.ivanov"]["ip"], "US", "success", "o365")
    login(at(13, 16, 48), "s.ivanov", "203.0.113.180", "NG", "success", "o365", "SC-06")

    # ------------------------------------------------- red-team (evasion) variants
    all_scenarios = dict(SCENARIOS)
    if evasion:
        all_scenarios.update(EVASION_SCENARIOS)

        # EV-01: four bursts of 15 failures, 10 minutes apart (never 20 in 5 minutes)
        for burst in range(4):
            for i in range(15):
                login(at(9, 13, 0) + timedelta(minutes=burst * 15, seconds=i * 10),
                      "t.brown", "203.0.113.201", "VN", "failure", "rdp", "EV-01")

        # EV-02: 12 accounts, one attempt every 10 minutes
        for i, u in enumerate(users[10:22]):
            login(at(10, 2, 0) + timedelta(minutes=i * 10), u["name"], "203.0.113.202", "UA",
                  "failure", "o365", "EV-02")

        # EV-03: short spellings of the encoded-command flag
        sample = enc_ps("Write-Output 'detlab-sample-ev03'")
        smith = by_name["j.smith"]
        proc(at(11, 10, 15), "j.smith", smith["host"], "powershell.exe", "excel.exe",
             f"powershell.exe -nop -w hidden -ec {sample}", "EV-03")
        proc(at(11, 10, 17), "j.smith", smith["host"], "powershell.exe", "excel.exe",
             f"powershell.exe -nop -w hidden -encodedc {sample}", "EV-03")

        # EV-04: self-added to a privileged group that is not Domain Admins
        group_add(at(9, 16, 0), "j.smith", "j.smith", "Backup Operators", "DC-01", "EV-04")

        # EV-05: real login, then an attacker login from another US address
        nguyen = by_name["a.nguyen"]
        login(at(12, 9, 0), "a.nguyen", nguyen["ip"], "US", "success", "o365")
        login(at(12, 9, 6), "a.nguyen", "198.51.100.250", "US", "success", "o365", "EV-05")

        # EV-06: the encoded flag is assembled at runtime, so it is not in the logged command line
        lee2 = by_name["k.lee"]
        proc(at(12, 14, 30), "k.lee", lee2["host"], "powershell.exe", "winword.exe",
             f"powershell.exe -nop -w hidden -c \"$f='-e'+'c'; powershell $f {sample}\"", "EV-06")

    # ------------------------------------------------ version 5: more log types, noise, scenarios
    add_v5({"emit": emit, "at": at, "raw": raw, "users": users, "by_name": by_name, "days": days,
            "evasion": evasion, "seed": seed})

    # ---------------------------------------------------------------- finalize
    raw.sort(key=lambda e: e["_t"])  # stable sort keeps generation order for ties
    events: list[dict] = []
    scenario_events: dict[str, list[str]] = {sc: [] for sc in all_scenarios}
    scenario_first: dict[str, str] = {}
    for i, row in enumerate(raw, start=1):
        event_id = f"e{i:06d}"
        sc = row.pop("_sc")
        t = row.pop("_t")
        events.append({"event_id": event_id, "ts": fmt_ts(t.timestamp()), **row})
        if sc:
            scenario_events[sc].append(event_id)
            scenario_first.setdefault(sc, events[-1]["ts"])

    truth = {
        "meta": {"seed": seed, "days": days, "start": START.strftime("%Y-%m-%d"),
                 "events": len(events), "users": len(users), "evasion": evasion},
        "scenarios": {sc: {**info, "event_ids": scenario_events[sc], "first_ts": scenario_first.get(sc)}
                      for sc, info in all_scenarios.items()},
    }
    return events, truth


def write_dataset(events: list[dict], truth: dict, out_dir: str | Path) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "events.jsonl", "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
    with open(out / "ground_truth.json", "w", encoding="utf-8") as fh:
        json.dump(truth, fh, indent=2)
