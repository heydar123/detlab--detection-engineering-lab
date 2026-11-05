from detlab.engine import run_rules

ATTACK = {"tactic": "Credential Access", "technique": "T1110", "technique_name": "Brute Force"}


def rule(**kw):
    base = {"id": "DET-999", "title": "test", "severity": "low", "attack": ATTACK}
    base.update(kw)
    return base


def login(i, t, user="u1", ip="1.1.1.1", outcome="failure", country="US"):
    return {"event_id": f"e{i:04d}", "_t": float(t), "action": "login", "outcome": outcome,
            "user": user, "src_ip": ip, "country": country}


def fails(n, spacing=1, start=0, **kw):
    return [login(i, start + i * spacing, **kw) for i in range(n)]


THRESHOLD = rule(type="threshold", filter={"action": "login", "outcome": "failure"},
                 group_by=["src_ip", "user"], window_seconds=60, threshold=5)


def test_threshold_fires_at_exactly_n():
    assert len(run_rules(fails(5), [THRESHOLD])) == 1


def test_threshold_does_not_fire_below_n():
    assert run_rules(fails(4), [THRESHOLD]) == []


def test_threshold_respects_window():
    # 5 failures but spread over 5 minutes - never 5 inside any 60s window
    assert run_rules(fails(5, spacing=75), [THRESHOLD]) == []


def test_threshold_groups_are_independent():
    evs = fails(3, user="a") + [login(10 + i, i, user="b") for i in range(3)]
    assert run_rules(evs, [THRESHOLD]) == []


def test_threshold_merges_one_burst_into_one_alert():
    alerts = run_rules(fails(40), [THRESHOLD])
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 40


def test_threshold_new_alert_after_quiet_gap():
    evs = fails(6) + fails(6, start=1000)
    for i, e in enumerate(evs):
        e["event_id"] = f"e{i:04d}"
    assert len(run_rules(evs, [THRESHOLD])) == 2


SPRAY = rule(type="distinct_threshold", filter={"action": "login", "outcome": "failure"},
             group_by=["src_ip"], distinct_field="user", window_seconds=600, threshold=4)


def test_distinct_threshold_counts_users_not_events():
    one_user = fails(20, user="same")
    assert run_rules(one_user, [SPRAY]) == []
    many = [login(i, i * 5, user=f"u{i}") for i in range(4)]
    alerts = run_rules(many, [SPRAY])
    assert len(alerts) == 1 and "4 distinct user" in alerts[0].summary


TRAVEL = rule(type="impossible_travel", filter={"action": "login", "outcome": "success"}, max_minutes=60)


def test_impossible_travel_fires_for_two_countries_in_window():
    evs = [login(1, 0, outcome="success", country="US"), login(2, 600, outcome="success", country="RO")]
    alerts = run_rules(evs, [TRAVEL])
    assert len(alerts) == 1 and alerts[0].entity["to"] == "RO"


def test_impossible_travel_ignores_same_country_and_slow_travel():
    same = [login(1, 0, outcome="success"), login(2, 60, outcome="success")]
    slow = [login(1, 0, outcome="success", country="US"), login(2, 7200, outcome="success", country="GB")]
    assert run_rules(same, [TRAVEL]) == []
    assert run_rules(slow, [TRAVEL]) == []


def test_impossible_travel_is_per_user():
    evs = [login(1, 0, user="a", outcome="success", country="US"),
           login(2, 60, user="b", outcome="success", country="RO")]
    assert run_rules(evs, [TRAVEL]) == []


FTS = rule(type="fail_then_success", failure_filter={"action": "login", "outcome": "failure"},
           success_filter={"action": "login", "outcome": "success"}, group_by=["user", "src_ip"],
           window_seconds=300, min_failures=5)


def test_fail_then_success_fires():
    evs = fails(6) + [login(100, 10, outcome="success")]
    alerts = run_rules(evs, [FTS])
    assert len(alerts) == 1 and alerts[0].event_ids[-1] == "e0100"


def test_fail_then_success_needs_enough_failures_and_same_source():
    assert run_rules(fails(3) + [login(100, 10, outcome="success")], [FTS]) == []
    other_ip = fails(6) + [login(100, 10, outcome="success", ip="9.9.9.9")]
    assert run_rules(other_ip, [FTS]) == []


def test_fail_then_success_failures_must_be_recent():
    evs = fails(6) + [login(100, 5000, outcome="success")]
    assert run_rules(evs, [FTS]) == []


MATCH = rule(type="match", filter={"action": "group_add", "group|in": ["Domain Admins"]},
             entity_fields=["user", "target_user"])


def grp(i, t, actor, group):
    return {"event_id": f"g{i}", "_t": float(t), "action": "group_add", "user": actor,
            "target_user": "x", "group": group}


def test_match_rule_one_alert_per_event():
    evs = [grp(1, 0, "eve", "Domain Admins"), grp(2, 5, "eve", "VPN-Users")]
    alerts = run_rules(evs, [MATCH])
    assert len(alerts) == 1 and alerts[0].entity == {"user": "eve", "target_user": "x"}


def test_exclusions_apply_per_rule_and_can_be_disabled():
    excl = dict(MATCH, exclusions=[{"match": {"user": "it.admin"}, "reason": "approved"}])
    evs = [grp(1, 0, "it.admin", "Domain Admins"), grp(2, 5, "eve", "Domain Admins")]
    assert len(run_rules(evs, [excl])) == 1
    assert len(run_rules(evs, [excl], use_exclusions=False)) == 2


def test_threshold_fired_time_is_the_nth_event_not_the_last():
    alerts = run_rules(fails(40), [THRESHOLD])
    assert alerts[0].fired_t == 4.0   # the 5th failure (t=4) tripped the rule
    assert alerts[0].last_t == 39.0   # the evidence kept growing afterwards, the fire time did not


def test_fail_then_success_fires_at_the_success():
    evs = fails(6) + [login(100, 10, outcome="success")]
    assert run_rules(evs, [FTS])[0].fired_t == 10.0


def test_impossible_travel_fires_at_the_second_login():
    evs = [login(1, 0, outcome="success", country="US"), login(2, 600, outcome="success", country="RO")]
    assert run_rules(evs, [TRAVEL])[0].fired_t == 600.0


def test_match_rule_fires_at_its_event():
    assert run_rules([grp(1, 42, "eve", "Domain Admins")], [MATCH])[0].fired_t == 42.0


def test_alert_round_trips_through_dict_including_fire_time():
    from detlab.models import Alert
    alert = run_rules(fails(5), [THRESHOLD])[0]
    assert Alert.from_dict(alert.to_dict()).fired_t == alert.fired_t


def test_alert_ids_are_sequential_and_time_ordered():
    evs = [grp(1, 50, "a", "Domain Admins"), grp(2, 10, "b", "Domain Admins")]
    alerts = run_rules(evs, [MATCH])
    assert [a.alert_id for a in alerts] == ["A-0001", "A-0002"]
    assert alerts[0].first_t < alerts[1].first_t
