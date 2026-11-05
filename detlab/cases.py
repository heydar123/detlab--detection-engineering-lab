"""Group related alerts into incident cases.

One intrusion usually trips several rules: a brute force, then a login, then PowerShell, then a
privilege change. Analysts work incidents, not individual alerts, so alerts that share an account,
a source IP, or a host and happen close together are merged into one case.

Linking is deliberately simple and explainable:
  - two alerts are linked when they share an account, source IP, or host, and
  - the gap between them is at most CASE_WINDOW_SECONDS.
Links chain (A-B and B-C puts A, B, C in one case).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .models import SEVERITY_ORDER, Alert

CASE_WINDOW_SECONDS = 2 * 60 * 60   # alerts further apart than this are not linked
KILL_CHAIN_MIN_TACTICS = 3          # a case spanning this many ATT&CK tactics is flagged

# The risk score of a case. It is a sum you can read, not a model: every point has a reason that is shown.
SEVERITY_POINTS = {"low": 1, "medium": 3, "high": 6, "critical": 10}   # once per distinct rule, at its highest severity
BREADTH_POINTS = 4                  # for every ATT&CK tactic beyond the first (the attack is moving forward)
ASSET_POINTS = 5                    # a domain controller, a server or a backup host is involved
ACCOUNT_POINTS = 5                  # an administrator or service account is involved
# Stand-ins for an asset inventory (CMDB). A real deployment reads these from its own inventory.
CRITICAL_HOST_PREFIXES = ("DC", "SRV", "BACKUP")
PRIVILEGED_ACCOUNT_PREFIXES = ("adm.", "svc_", "it.admin", "administrator")
RISK_LEVELS = ((30, "critical"), (18, "high"), (8, "medium"), (0, "low"))


def _identities(alert: Alert) -> set[tuple[str, str]]:
    ids: set[tuple[str, str]] = set()
    for key in ("user", "target_user"):          # actor and target are both "an account"
        if alert.entity.get(key):
            ids.add(("account", str(alert.entity[key])))
    if alert.entity.get("src_ip"):
        ids.add(("ip", str(alert.entity["src_ip"])))
    if alert.entity.get("host"):
        ids.add(("host", str(alert.entity["host"])))
    return ids


@dataclass
class Case:
    case_id: str
    alerts: list[Alert]

    @property
    def first_t(self) -> float:
        return min(a.first_t for a in self.alerts)

    @property
    def last_t(self) -> float:
        return max(a.last_t for a in self.alerts)

    @property
    def first_fired_t(self) -> float:
        return min(a.fired_t for a in self.alerts)

    @property
    def severity(self) -> str:
        return max((a.severity for a in self.alerts), key=lambda s: SEVERITY_ORDER[s])

    @property
    def tactics(self) -> list[str]:
        """ATT&CK tactics in the order the alerts started, each listed once."""
        seen: list[str] = []
        for a in sorted(self.alerts, key=lambda a: (a.first_t, a.fired_t, a.rule_id)):
            if a.tactic not in seen:
                seen.append(a.tactic)
        return seen

    @property
    def kill_chain(self) -> bool:
        return len(self.tactics) >= KILL_CHAIN_MIN_TACTICS

    @property
    def rules(self) -> list[str]:
        return sorted({a.rule_id for a in self.alerts})

    def values(self, kind: str) -> list[str]:
        out: set[str] = set()
        for a in self.alerts:
            out |= {v for k, v in _identities(a) if k == kind}
        return sorted(out)

    @property
    def title(self) -> str:
        return ", ".join(self.values("account")) or ", ".join(self.values("ip")) or ", ".join(self.values("host")) or "-"


def build_cases(alerts: list[Alert], window: int = CASE_WINDOW_SECONDS) -> list[Case]:
    """Merge related alerts into cases, ordered by start time (CASE-001, CASE-002, ...)."""
    ordered = sorted(alerts, key=lambda a: (a.first_t, a.fired_t, a.rule_id))
    parent = list(range(len(ordered)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    ids = [_identities(a) for a in ordered]
    for j in range(len(ordered)):
        for i in range(j):
            if ids[i] & ids[j] and ordered[j].first_t - ordered[i].last_t <= window:
                parent[find(j)] = find(i)

    groups: dict[int, list[Alert]] = defaultdict(list)
    for idx, alert in enumerate(ordered):
        groups[find(idx)].append(alert)

    cases = [Case("", members) for members in groups.values()]
    cases.sort(key=lambda c: (c.first_t, c.rules))
    for n, case in enumerate(cases, start=1):
        case.case_id = f"CASE-{n:03d}"
    return cases


def risk(case: Case) -> dict:
    """Score a case from what is in it. Returns the score, a level, and the list of reasons behind every point."""
    best: dict[str, str] = {}
    for a in case.alerts:
        if a.rule_id not in best or SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[best[a.rule_id]]:
            best[a.rule_id] = a.severity
    factors = [{"label": f"{rid} ({sev})", "points": SEVERITY_POINTS[sev]} for rid, sev in sorted(best.items())]
    extra_tactics = len(case.tactics) - 1
    if extra_tactics > 0:
        factors.append({"label": f"{len(case.tactics)} ATT&CK tactics: {', '.join(case.tactics)}",
                        "points": BREADTH_POINTS * extra_tactics})
    hosts = [h for h in case.values("host") if h.upper().startswith(CRITICAL_HOST_PREFIXES)]
    if hosts:
        factors.append({"label": f"critical host: {', '.join(hosts)}", "points": ASSET_POINTS})
    accounts = [a for a in case.values("account") if a.lower().startswith(PRIVILEGED_ACCOUNT_PREFIXES)]
    if accounts:
        factors.append({"label": f"privileged account: {', '.join(accounts)}", "points": ACCOUNT_POINTS})
    score = sum(f["points"] for f in factors)
    level = next(name for floor, name in RISK_LEVELS if score >= floor)
    return {"score": score, "level": level, "factors": factors}


def rank_cases(cases: list[Case]) -> list[tuple[Case, dict]]:
    """Cases from the highest risk to the lowest (ties: the older case first)."""
    scored = [(c, risk(c)) for c in cases]
    scored.sort(key=lambda x: (-x[1]["score"], x[0].first_t, x[0].case_id))
    return scored


def evaluate_ranking(cases: list[Case], case_eval: dict) -> dict:
    """How well did the risk score put real attacks above false alarms?

    A "false case" is a case with no planted attack in it. ``pairs_ordered`` is the share of (attack case, false
    case) pairs in which the attack case has the higher score; it is None when there is no false case.
    """
    scores = {c.case_id: risk(c)["score"] for c in cases}
    attack = [cid for cid, hit in case_eval["case_scenarios"].items() if hit]
    false = case_eval["false_positive_cases"]
    pairs = [(a, f) for a in attack for f in false]
    order = [c.case_id for c, _ in rank_cases(cases)]
    return {
        "attack_cases": len(attack), "false_cases": len(false),
        "pairs_ordered": (sum(1 for a, f in pairs if scores[a] > scores[f]) / len(pairs)) if pairs else None,
        "pairs_tied": sum(1 for a, f in pairs if scores[a] == scores[f]),
        "false_case_ranks": [order.index(f) + 1 for f in false],
        "top_k_all_attacks": all(cid in attack for cid in order[:len(attack)]),
    }


def evaluate_cases(cases: list[Case], truth: dict) -> dict:
    """How well did grouping match the real attacks?

    split    - one attack ended up in more than one case (grouping missed a link)
    merged   - one case mixes alerts from different attacks (grouping linked too much)
    fp cases - cases whose alerts contain no malicious event at all
    """
    malicious = {eid: sc for sc, s in truth["scenarios"].items() for eid in s["event_ids"]}
    case_scenarios: dict[str, list[str]] = {}
    scenario_cases: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        hit = sorted({malicious[e] for a in case.alerts for e in a.event_ids if e in malicious})
        case_scenarios[case.case_id] = hit
        for sc in hit:
            scenario_cases[sc].add(case.case_id)
    return {
        "cases": len(cases),
        "alerts": sum(len(c.alerts) for c in cases),
        "scenarios_found": len(scenario_cases),
        "case_scenarios": case_scenarios,
        "false_positive_cases": [cid for cid, hit in case_scenarios.items() if not hit],
        "split_scenarios": {sc: sorted(ids) for sc, ids in scenario_cases.items() if len(ids) > 1},
        "merged_cases": {cid: hit for cid, hit in case_scenarios.items() if len(hit) > 1},
    }
