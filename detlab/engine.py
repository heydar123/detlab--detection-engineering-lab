"""Detection engine: runs YAML rules over a list of events and returns alerts.

Events must already carry the parsed epoch time in ``_t`` (see ``models.prepare_events``).
Every rule type works on a time-sorted stream. Rule exclusions are applied up front, so a
documented exclusion removes those events from that rule only.

Rule types:
  match               one alert per matching event (optionally merged when repeated)
  threshold           N matching events for one group inside a window
  distinct_threshold  N distinct values of a field for one group inside a window
  sum_threshold       the total of a number field for one group inside a window
  beaconing           matching events that repeat at very regular intervals
  first_seen          a value that a group has never shown before (after a learning period)
  impossible_travel   sign-ins from two countries too close together in time
  fail_then_success   N failures followed by a success for one group
"""

from __future__ import annotations

import statistics
from collections import defaultdict, deque

from .matching import excluded, filter_actions, matches
from .models import Alert


def _entity(ev: dict, fields: list[str]) -> dict:
    return {f: ev.get(f) for f in fields}


def _new_alert(rule: dict, entity: dict, evs: list[dict]) -> Alert:
    return Alert(
        rule_id=rule["id"],
        title=rule["title"],
        severity=rule["severity"],
        tactic=rule["attack"]["tactic"],
        technique=rule["attack"]["technique"],
        entity=entity,
        first_t=evs[0]["_t"],
        last_t=evs[-1]["_t"],
        event_ids=[e["event_id"] for e in evs],
        fired_t=evs[-1]["_t"],  # the last event in the evidence is the one that tripped the rule
    )


def _fmt_entity(entity: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in entity.items())


def _number(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _fmt_size(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_secs(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    return f"{seconds / 3600:.1f} h"


# ---------------------------------------------------------------- rule types

def run_match(rule: dict, events: list[dict]) -> list[Alert]:
    """One alert per event that satisfies the filter.

    With ``suppress_seconds`` set, repeats for the same entity inside that many seconds are folded into
    the first alert instead of raising a new one (alert throttling).
    """
    suppress = rule.get("suppress_seconds", 0)
    open_alert: dict[tuple, Alert] = {}
    alerts: list[Alert] = []
    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        entity = _entity(ev, rule["entity_fields"])
        key = tuple(entity.values())
        current = open_alert.get(key)
        if suppress and current and ev["_t"] - current.last_t <= suppress:
            current.event_ids.append(ev["event_id"])
            current.last_t = ev["_t"]
            continue
        alert = _new_alert(rule, entity, [ev])
        alert.summary = f"{rule['title']} ({_fmt_entity(entity)})"
        alerts.append(alert)
        open_alert[key] = alert
    for a in alerts:
        if len(a.event_ids) > 1:
            a.summary = f"{rule['title']} ({_fmt_entity(a.entity)}), repeated {len(a.event_ids)} times"
    return alerts


def run_threshold(rule: dict, events: list[dict]) -> list[Alert]:
    """N matching events for the same group inside a sliding window.

    Once an alert is open, further matching events inside the window extend it
    rather than creating a new alert for every event.
    """
    window, threshold = rule["window_seconds"], rule["threshold"]
    buckets: dict[tuple, deque] = defaultdict(deque)
    open_alert: dict[tuple, Alert] = {}
    alerts: list[Alert] = []

    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        key = tuple(ev.get(f) for f in rule["group_by"])
        dq = buckets[key]
        dq.append(ev)
        while dq and ev["_t"] - dq[0]["_t"] > window:
            dq.popleft()

        current = open_alert.get(key)
        if current and ev["_t"] - current.last_t <= window:
            current.event_ids.append(ev["event_id"])
            current.last_t = ev["_t"]
        elif len(dq) >= threshold:
            alert = _new_alert(rule, _entity(ev, rule["group_by"]), list(dq))
            open_alert[key] = alert
            alerts.append(alert)

    for a in alerts:
        a.summary = (f"{len(a.event_ids)} matching events over {int(a.last_t - a.first_t)}s "
                     f"({_fmt_entity(a.entity)})")
    return alerts


def run_distinct_threshold(rule: dict, events: list[dict]) -> list[Alert]:
    """N distinct values of one field (e.g. usernames) from the same group in a window."""
    window, threshold, dfield = rule["window_seconds"], rule["threshold"], rule["distinct_field"]
    buckets: dict[tuple, deque] = defaultdict(deque)
    open_alert: dict[tuple, Alert] = {}
    alerts: list[Alert] = []
    distinct_seen: dict[int, set] = {}

    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        key = tuple(ev.get(f) for f in rule["group_by"])
        dq = buckets[key]
        dq.append(ev)
        while dq and ev["_t"] - dq[0]["_t"] > window:
            dq.popleft()

        current = open_alert.get(key)
        if current and ev["_t"] - current.last_t <= window:
            current.event_ids.append(ev["event_id"])
            current.last_t = ev["_t"]
            distinct_seen[id(current)].add(ev.get(dfield))
        elif len({e.get(dfield) for e in dq}) >= threshold:
            alert = _new_alert(rule, _entity(ev, rule["group_by"]), list(dq))
            open_alert[key] = alert
            distinct_seen[id(alert)] = {e.get(dfield) for e in dq}
            alerts.append(alert)

    for a in alerts:
        n = len(distinct_seen[id(a)])
        a.summary = (f"{n} distinct {dfield} values, {len(a.event_ids)} events over "
                     f"{int(a.last_t - a.first_t)}s ({_fmt_entity(a.entity)})")
    return alerts


def run_sum_threshold(rule: dict, events: list[dict]) -> list[Alert]:
    """The total of one number field (for example bytes sent) for a group inside a window."""
    window, threshold, sfield = rule["window_seconds"], rule["threshold"], rule["sum_field"]
    buckets: dict[tuple, deque] = defaultdict(deque)
    running: dict[tuple, float] = defaultdict(float)
    open_alert: dict[tuple, Alert] = {}
    totals: dict[int, float] = {}
    alerts: list[Alert] = []

    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        key = tuple(ev.get(f) for f in rule["group_by"])
        value = _number(ev.get(sfield))
        dq = buckets[key]
        dq.append((ev, value))
        running[key] += value
        while dq and ev["_t"] - dq[0][0]["_t"] > window:
            _, old = dq.popleft()
            running[key] -= old

        current = open_alert.get(key)
        if current and ev["_t"] - current.last_t <= window:
            current.event_ids.append(ev["event_id"])
            current.last_t = ev["_t"]
            totals[id(current)] += value
        elif running[key] >= threshold:
            alert = _new_alert(rule, _entity(ev, rule["group_by"]), [e for e, _ in dq])
            open_alert[key] = alert
            totals[id(alert)] = running[key]
            alerts.append(alert)

    for a in alerts:
        a.summary = (f"{_fmt_size(totals[id(a)])} of {rule['sum_field']} in {len(a.event_ids)} events over "
                     f"{_fmt_secs(a.last_t - a.first_t)} ({_fmt_entity(a.entity)})")
    return alerts


def run_beaconing(rule: dict, events: list[dict]) -> list[Alert]:
    """Events that repeat at very regular intervals, the way malware checks in with its controller.

    For each group, look at the gaps between consecutive events inside the window. If there are at
    least ``min_events`` of them, the average gap is between ``min_interval_seconds`` and
    ``max_interval_seconds``, and the gaps vary very little (standard deviation divided by the mean
    is at most ``max_cv``), raise an alert. Random human traffic has a high variation; a timer does not.
    """
    window = rule["window_seconds"]
    need, max_cv = rule["min_events"], rule["max_cv"]
    lo, hi = rule["min_interval_seconds"], rule["max_interval_seconds"]
    buckets: dict[tuple, deque] = defaultdict(deque)
    open_alert: dict[tuple, Alert] = {}
    stats: dict[int, tuple[float, float]] = {}
    alerts: list[Alert] = []

    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        key = tuple(ev.get(f) for f in rule["group_by"])
        dq = buckets[key]
        dq.append(ev)
        while dq and ev["_t"] - dq[0]["_t"] > window:
            dq.popleft()

        current = open_alert.get(key)
        if current and ev["_t"] - current.last_t <= hi * 3:
            current.event_ids.append(ev["event_id"])
            current.last_t = ev["_t"]
            continue
        if len(dq) < need:
            continue
        times = [e["_t"] for e in dq]
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps)
        if not lo <= mean <= hi:
            continue
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if cv <= max_cv:
            alert = _new_alert(rule, _entity(ev, rule["group_by"]), list(dq))
            open_alert[key] = alert
            stats[id(alert)] = (mean, cv)
            alerts.append(alert)

    for a in alerts:
        mean, cv = stats[id(a)]
        a.summary = (f"{len(a.event_ids)} connections about every {_fmt_secs(mean)} "
                     f"(variation {cv:.0%}) over {_fmt_secs(a.last_t - a.first_t)} ({_fmt_entity(a.entity)})")
    return alerts


def run_first_seen(rule: dict, events: list[dict]) -> list[Alert]:
    """A value this group has never shown before, once a learning period is over.

    During the first ``learning_seconds`` of matching data the rule only learns. After that, an event whose
    ``value_field`` was never seen for its group raises an alert (once per new value). Groups that were
    not seen at all during learning are skipped by default, because there is nothing to compare with.
    """
    learn = rule["learning_seconds"]
    vfield = rule["value_field"]
    need_baseline = rule.get("require_baseline", True)
    known: dict[tuple, set] = defaultdict(set)
    baselined: set[tuple] = set()
    start = None
    alerts: list[Alert] = []

    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        value = ev.get(vfield)
        if value is None or value == "":
            continue
        if start is None:
            start = ev["_t"]
        key = tuple(ev.get(f) for f in rule["group_by"])
        if ev["_t"] - start < learn:
            known[key].add(value)
            baselined.add(key)
            continue
        if value in known[key]:
            continue
        had_baseline = key in baselined
        known[key].add(value)
        if need_baseline and not had_baseline:
            continue
        entity = _entity(ev, rule["group_by"])
        entity[vfield] = value
        alert = _new_alert(rule, entity, [ev])
        alert.summary = (f"{_fmt_entity(_entity(ev, rule['group_by']))}: new {vfield} {value}, "
                         f"not seen in the first {_fmt_secs(learn)}")
        alerts.append(alert)
    return alerts


def run_impossible_travel(rule: dict, events: list[dict]) -> list[Alert]:
    """Successful logins for one user from two countries within max_minutes."""
    limit = rule["max_minutes"] * 60
    last: dict[str, dict] = {}
    alerts: list[Alert] = []
    for ev in events:
        if not matches(ev, rule["filter"]):
            continue
        user, prev = ev.get("user"), last.get(ev.get("user"))
        if prev and prev.get("country") != ev.get("country") and ev["_t"] - prev["_t"] <= limit:
            entity = {"user": user, "from": prev.get("country"), "to": ev.get("country")}
            alert = _new_alert(rule, entity, [prev, ev])
            gap = int((ev["_t"] - prev["_t"]) // 60)
            alert.summary = (f"{user} logged in from {prev.get('country')} then {ev.get('country')} "
                             f"{gap} min apart")
            alerts.append(alert)
        last[user] = ev
    return alerts


def run_fail_then_success(rule: dict, events: list[dict]) -> list[Alert]:
    """min_failures failed logins followed by a success, same group, inside a window."""
    window, minimum = rule["window_seconds"], rule["min_failures"]
    fails: dict[tuple, deque] = defaultdict(deque)
    alerts: list[Alert] = []
    for ev in events:
        key = tuple(ev.get(f) for f in rule["group_by"])
        if matches(ev, rule["failure_filter"]):
            dq = fails[key]
            dq.append(ev)
            while dq and ev["_t"] - dq[0]["_t"] > window:
                dq.popleft()
        elif matches(ev, rule["success_filter"]):
            dq = fails.get(key)
            if not dq:
                continue
            while dq and ev["_t"] - dq[0]["_t"] > window:
                dq.popleft()
            if len(dq) >= minimum:
                alert = _new_alert(rule, _entity(ev, rule["group_by"]), list(dq) + [ev])
                alert.summary = (f"{len(dq)} failures then a success within {window}s "
                                 f"({_fmt_entity(alert.entity)})")
                alerts.append(alert)
                dq.clear()
    return alerts


RUNNERS = {
    "match": run_match,
    "threshold": run_threshold,
    "distinct_threshold": run_distinct_threshold,
    "sum_threshold": run_sum_threshold,
    "beaconing": run_beaconing,
    "first_seen": run_first_seen,
    "impossible_travel": run_impossible_travel,
    "fail_then_success": run_fail_then_success,
}


def rule_actions(rule: dict) -> set[str] | None:
    """The event actions a rule can possibly look at, or None when it is not limited to some actions."""
    merged: set[str] = set()
    for key in ("filter", "failure_filter", "success_filter"):
        if key in rule:
            sub = filter_actions(rule[key])
            if sub is None:
                return None
            merged |= sub
    return merged or None


def run_rules(events: list[dict], rules: list[dict], use_exclusions: bool = True) -> list[Alert]:
    """Run every rule and return alerts ordered by time, with stable alert IDs.

    Each rule only sees events whose ``action`` it can match, which makes a large rule set fast. This
    never changes the result: a test compares it with a full scan.
    """
    ordered = sorted(events, key=lambda e: (e["_t"], e["event_id"]))
    by_actions: dict[frozenset, list[dict]] = {}
    alerts: list[Alert] = []
    for rule in rules:
        acts = rule_actions(rule)
        if acts is None:
            stream = ordered
        else:
            key = frozenset(acts)
            if key not in by_actions:
                by_actions[key] = [e for e in ordered if str(e.get("action", "")).casefold() in key]
            stream = by_actions[key]
        if use_exclusions and rule.get("exclusions"):
            stream = [e for e in stream if not excluded(e, rule["exclusions"])]
        alerts.extend(RUNNERS[rule["type"]](rule, stream))
    alerts.sort(key=lambda a: (a.first_t, a.rule_id))
    for i, alert in enumerate(alerts, start=1):
        alert.alert_id = f"A-{i:04d}"
    return alerts
