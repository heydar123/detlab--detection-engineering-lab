"""Markdown output: detection report and per-user incident case file."""

from __future__ import annotations

from collections import Counter, defaultdict

from .models import SEVERITY_ORDER, Alert, fmt_ts
from .timeline import describe_event


def _count(n: int, one: str, many: str | None = None) -> str:
    """'1 case', '2 cases', '0 cases'."""
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def _dur(seconds) -> str:
    """Seconds as a short human duration: 38s, 2m 52s, 1h 50m."""
    if seconds is None:
        return "-"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def _table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def _fmt_entity(entity: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in entity.items())


def render_report(rules: list[dict], alerts: list[Alert], truth: dict, tuned: dict, untuned: dict,
                  cases: list | None = None, case_eval: dict | None = None) -> str:
    meta = truth["meta"]
    lines = [
        "# Detection report",
        "",
        f"Synthetic dataset: {meta['events']:,} events, {meta['users']} users, {meta['days']} days "
        f"starting {meta['start']} (seed {meta['seed']}). {len(truth['scenarios'])} labeled attack scenarios "
        "are hidden in ordinary noise that includes deliberate false-positive sources "
        "(a vulnerability scanner, a backup job, a VPN, an approved admin).",
        "",
        "## Headline",
        "",
    ]
    t, u = tuned["overall"], untuned["overall"]
    lines += [
        f"- Tuned rules: **{t['alerts']} alerts, precision {_pct(t['precision'])}, recall {_pct(t['recall'])}** "
        f"({_count(t['tp'], 'true positive')}, {_count(t['fp'], 'false positive')}).",
        f"- Same rules with no exclusions: {u['alerts']} alerts, precision {_pct(u['precision'])}, "
        f"recall {_pct(u['recall'])} ({_count(u['fp'], 'false positive')}).",
        "",
        "## Per-rule results, before and after tuning",
        "",
    ]
    rows = []
    for r in rules:
        rid = r["id"]
        a, b = untuned["per_rule"][rid], tuned["per_rule"][rid]
        rows.append([rid, r["title"], r["severity"], a["alerts"], a["fp"], _pct(a["precision"]),
                     b["alerts"], b["fp"], _pct(b["precision"]), _pct(b["recall"])])
    lines.append(_table(
        ["Rule", "Title", "Severity", "Alerts (untuned)", "FP (untuned)", "Precision (untuned)",
         "Alerts (tuned)", "FP (tuned)", "Precision (tuned)", "Recall (tuned)"], rows))

    lines += ["", "## MITRE ATT&CK coverage", ""]
    lines.append(_table(
        ["Tactic", "Technique", "Rule", "Scenarios detected"],
        [[r["attack"]["tactic"], f"{r['attack']['technique']} {r['attack']['technique_name']}", r["id"],
          f"{tuned['per_rule'][r['id']]['detected']}/{tuned['per_rule'][r['id']]['expected']}"] for r in rules]))

    lines += ["", "## Attack scenario outcomes and time to detect (tuned rules)", "",
              "Time to detect is measured from the attack's first malicious event to the moment the first "
              "expected rule fired. 0s means the rule fired on the very event that was malicious.", ""]
    rows = []
    for sc, res in tuned["scenarios"].items():
        rows.append([sc, res["name"], ", ".join(res["expected"]), ", ".join(res["detected"]) or "-",
                     ", ".join(res["missed"]) or "-", res["first_rule"] or "-", _dur(res["ttd_seconds"])])
    lines.append(_table(["Scenario", "Name", "Expected rules", "Detected", "Missed", "First rule to fire",
                         "Time to detect"], rows))

    if cases is not None and case_eval is not None:
        lines += ["", "## Incident cases", "",
                  f"{case_eval['alerts']} alerts were grouped into **{len(cases)} incident cases** "
                  "(alerts that share an account, source IP, or host within 2 hours are merged). "
                  f"Against the ground truth: {_count(case_eval['scenarios_found'], 'attack')} found, "
                  f"{len(case_eval['split_scenarios'])} split across more than one case, "
                  f"{_count(len(case_eval['merged_cases']), 'case')} mixing different attacks, "
                  f"{_count(len(case_eval['false_positive_cases']), 'false-positive case')}.", ""]
        rows = []
        for c in cases:
            rows.append([c.case_id, c.severity, len(c.alerts), c.title, " -> ".join(c.tactics),
                         "yes" if c.kill_chain else "-", ", ".join(c.rules),
                         ", ".join(case_eval["case_scenarios"][c.case_id]) or "-"])
        lines.append(_table(["Case", "Severity", "Alerts", "Who / what", "Tactics in order", "Multi-stage",
                             "Rules", "Scenario"], rows))

    lines += ["", "## Remaining false positives after tuning", ""]
    groups: Counter = Counter()
    for a in alerts:
        v = tuned["verdicts"].get(a.alert_id)
        if v and v["verdict"] == "FP":
            groups[(a.rule_id, _fmt_entity(a.entity))] += 1
    if groups:
        lines.append(_table(["Rule", "Entity", "Count"], [[k[0], k[1], n] for k, n in groups.most_common()]))
    else:
        lines.append("None. Each exclusion that achieved this is documented in its rule file with a written "
                     "reason, and should be reviewed regularly.")

    lines += ["", "## Alerts raised (tuned rules)", ""]
    case_of = {a.alert_id: c.case_id for c in (cases or []) for a in c.alerts}
    rows = []
    for a in alerts:
        v = tuned["verdicts"][a.alert_id]
        rows.append([a.alert_id, case_of.get(a.alert_id, "-"), a.rule_id, a.severity, a.first_ts, a.fired_ts,
                     _fmt_entity(a.entity), v["verdict"], ", ".join(v["scenarios"]) or "-"])
    lines.append(_table(["Alert", "Case", "Rule", "Severity", "First event (UTC)", "Fired (UTC)", "Entity",
                         "Verdict", "Scenario"], rows))
    lines.append("")
    return "\n".join(lines)


def render_untuned_fp_table(untuned_alerts: list[Alert], untuned: dict) -> str:
    groups: Counter = Counter()
    for a in untuned_alerts:
        if untuned["verdicts"][a.alert_id]["verdict"] == "FP":
            entity = dict(a.entity)
            if a.rule_id == "DET-003":
                entity = {"user": entity.get("user")}
            groups[(a.rule_id, _fmt_entity(entity))] += 1
    rows = [[k[0], k[1], n] for k, n in sorted(groups.items())]
    return _table(["Rule", "Entity", "False-positive alerts"], rows)


# ------------------------------------------------------------------ case file

def _describe(ev: dict) -> str:
    if ev["action"] == "login":
        return (f"{ev['outcome']} {ev['service']} login for `{ev['user']}` from {ev['src_ip']} ({ev['country']})")
    if ev["action"] == "process_create":
        cmd = ev["command_line"]
        cmd = cmd if len(cmd) <= 110 else cmd[:110] + "..."
        return f"`{ev['process_name']}` started on {ev['host']} by `{ev['user']}` (parent `{ev['parent_process']}`): `{cmd}`"
    if ev["action"] == "group_add":
        return f"`{ev['user']}` added `{ev['target_user']}` to **{ev['group']}** on {ev['host']}"
    text, detail = describe_event(ev)             # every other kind of event: the same plain sentence the web page shows
    return f"{text}: `{detail}`" if detail else text


def render_case(user: str, events: list[dict], alerts: list[Alert], rules: list[dict]) -> str:
    by_id = {e["event_id"]: e for e in events}
    rule_by_id = {r["id"]: r for r in rules}

    def involves(a: Alert) -> bool:
        for eid in a.event_ids:
            ev = by_id.get(eid, {})
            if user in (ev.get("user"), ev.get("target_user")):
                return True
        return False

    mine = [a for a in alerts if involves(a)]
    if not mine:
        return f"# Incident case: {user}\n\nNo alerts involve this user.\n"

    start = min(a.first_t for a in mine) - 1800
    end = max(a.last_t for a in mine) + 1800
    cited = defaultdict(list)
    for a in mine:
        for eid in a.event_ids:
            cited[eid].append(a.alert_id)

    window = [e for e in events if start <= e["_t"] <= end and
              (e.get("user") == user or e.get("target_user") == user)]

    # collapse runs of failed logins from the same source into one timeline row
    rows: list[list] = []
    i = 0
    while i < len(window):
        ev = window[i]
        if ev["action"] == "login" and ev["outcome"] == "failure":
            j = i
            while (j + 1 < len(window) and window[j + 1]["action"] == "login"
                   and window[j + 1]["outcome"] == "failure" and window[j + 1]["src_ip"] == ev["src_ip"]):
                j += 1
            run = window[i:j + 1]
            refs = sorted({r for e in run for r in cited.get(e["event_id"], [])})
            rows.append([run[0]["ts"], f"{len(run)} failed {ev['service']} logins for `{user}` from "
                         f"{ev['src_ip']} ({ev['country']}), last at {run[-1]['ts'][11:19]}Z", ", ".join(refs) or "-"])
            i = j + 1
            continue
        rows.append([ev["ts"], _describe(ev), ", ".join(cited.get(ev["event_id"], [])) or "-"])
        i += 1

    sev = max(mine, key=lambda a: SEVERITY_ORDER[a.severity]).severity
    tactics = []
    for a in sorted(mine, key=lambda a: a.first_t):
        if a.tactic not in tactics:
            tactics.append(a.tactic)

    seen = set()
    triage, response = [], []
    for a in mine:
        if a.rule_id in seen:
            continue
        seen.add(a.rule_id)
        rule = rule_by_id[a.rule_id]
        triage += [f"{rule['id']}: {s}" for s in rule["triage"]]
        response += [f"{rule['id']}: {s}" for s in rule["response"]]

    lines = [
        f"# Incident case file: `{user}`",
        "",
        "_Generated from synthetic lab data by detlab. Every name, IP, and host in this file is fictional._",
        "",
        "## Summary",
        "",
        f"- Highest severity: **{sev}**",
        f"- Alerts involving this account: {len(mine)} across {len(seen)} detection rules",
        f"- Observed tactic sequence: {' -> '.join(tactics)}",
        f"- Window: {fmt_ts(start + 1800)} to {fmt_ts(end - 1800)} (UTC)",
        "",
        "## Alerts",
        "",
        _table(["Alert", "Evidence starts (UTC)", "Fired (UTC)", "Rule", "Severity", "ATT&CK", "What fired"],
               [[a.alert_id, a.first_ts, a.fired_ts, a.rule_id, a.severity, a.technique, a.summary]
                for a in sorted(mine, key=lambda a: (a.first_t, a.fired_t))]),
        "",
        "## Timeline",
        "",
        _table(["Time (UTC)", "Event", "Alert"], rows),
        "",
        "## Triage questions",
        "",
        *[f"- {s}" for s in triage],
        "",
        "## Recommended response",
        "",
        *[f"- {s}" for s in response],
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------- console and red-team output

def cases_text(cases: list) -> str:
    head = f"{'Case':<9} {'Severity':<9} {'Alerts':>6}  {'Who / what':<22} Attack chain"
    out = [head, "-" * 86]
    for c in cases:
        flag = "   [multi-stage]" if c.kill_chain else ""
        out.append(f"{c.case_id:<9} {c.severity:<9} {len(c.alerts):>6}  {c.title[:22]:<22} "
                   f"{' -> '.join(c.tactics)}{flag}")
    return "\n".join(out)


def ttd_text(result: dict) -> str:
    head = f"{'Attack':<7} {'First rule':<11} {'Time to detect':>14}  Name"
    out = [head, "-" * 70]
    for sc, res in result["scenarios"].items():
        out.append(f"{sc:<7} {(res['first_rule'] or '-'):<11} {_dur(res['ttd_seconds']):>14}  {res['name']}")
    return "\n".join(out)


def evasion_text(evasion: dict) -> str:
    head = f"{'Variant':<7} {'Result':<7} {'Caught by':<10} Name"
    out = [head, "-" * 70]
    for r in evasion["rows"]:
        out.append(f"{r['id']:<7} {('CAUGHT' if r['caught'] else 'MISSED'):<7} "
                   f"{(', '.join(r['detected_by']) or '-'):<10} {r['name']}")
    out.append("-" * 70)
    out.append(f"{evasion['caught']} of {evasion['total']} caught, {_count(evasion['false_positives'], 'false positive')}")
    gaps = [r for r in evasion["rows"] if not r["caught"]]
    if gaps:
        out += ["", "OPEN GAPS (documented, not fixed):"]
        for r in gaps:
            out += [f"  {r['id']} {r['name']}", f"    What would close it: {r['mitigation']}"]
    return "\n".join(out)


def render_evasion_report(evasion: dict) -> str:
    rows, caught, total = evasion["rows"], evasion["caught"], evasion["total"]
    lines = [
        "# Red-team report",
        "",
        "These attack variants were written after the first version of the rules, on purpose, to slip past them. "
        "Each one names the rule that should catch it. A MISSED row is a documented gap, not a hidden one.",
        "",
        f"**Result: {caught} of {total} variants caught** by the current rules, "
        f"with {_count(evasion['false_positives'], 'false positive')} on this dataset.",
        "",
        "The variants are synthetic and were designed against these specific rules. This measures known blind "
        "spots, not how the rules would fare against real attackers.",
        "",
        "## Results",
        "",
        _table(["Variant", "Attack", "Rule that should catch it", "Result", "Caught by", "Time to detect"],
               [[r["id"], r["name"], ", ".join(r["expected"]), "CAUGHT" if r["caught"] else "MISSED",
                 ", ".join(r["detected_by"]) or "-", _dur(r["ttd_seconds"])] for r in rows]),
        "",
        "## Gaps found and closed",
        "",
    ]
    closed = [r for r in rows if r["caught"]]
    lines += [f"- **{r['id']} {r['name']}**: {r['description']} Closed by {', '.join(r['detected_by'])}. "
              f"{r['mitigation']}" for r in closed] or ["None."]
    lines += ["", "## Open gaps and what would close them", ""]
    open_gaps = [r for r in rows if not r["caught"]]
    for r in open_gaps:
        lines += [f"### {r['id']} - {r['name']}", "", r["description"], "",
                  f"**What would close it:** {r['mitigation']}", ""]
    if not open_gaps:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)
