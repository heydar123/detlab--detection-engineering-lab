"""Command line interface: python -m detlab <command>."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cases import build_cases, evaluate_cases
from .engine import run_rules
from .evaluate import evaluate
from .evasion import run_evasion
from .generate import MIN_DAYS, generate, write_dataset
from .models import Alert, load_events, prepare_events, read_jsonl, write_jsonl
from .report import (_count, _pct, cases_text, evasion_text, render_case, render_evasion_report, render_report,
                     render_untuned_fp_table, ttd_text)
from .rules import load_rules, validate_rules, yaml


class UserError(Exception):
    """A problem the person can fix (a wrong folder, a missing file). The message says how and is printed on its own."""


def _rules(path) -> list[dict]:
    """Load the rule files of a folder, or explain in plain words what is wrong with the folder or a file."""
    folder = Path(path)
    if not folder.is_dir():
        raise UserError(f"I cannot find the rules folder '{path}'. Open the detection-lab folder first (the one that "
                        "contains the folders 'rules' and 'detlab'), then run the command again.")
    files = sorted(folder.glob("*.yml"))
    if not files:
        raise UserError(f"There are no rule files (*.yml) in '{path}'.")
    rules = []
    for f in files:
        try:
            rules += load_rules(f)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" (line {mark.line + 1})" if mark else ""
            problem = (getattr(exc, "problem", None) or str(exc) or "the text cannot be read").splitlines()[0]
            raise UserError(f"{f.name} is not valid YAML{where}: {problem}") from exc
        except (ValueError, OSError) as exc:
            raise UserError(str(exc)) from exc
    return sorted(rules, key=lambda r: r.get("id", ""))


def _file(path, how_to_make_it: str) -> Path:
    path = Path(path)
    if not path.is_file():
        raise UserError(f"I cannot find {path}. {how_to_make_it}")
    return path


def _make_logs(seed: int, days: int):
    try:
        return generate(seed, days)
    except ValueError as exc:
        raise UserError(f"I cannot make the logs: {exc}.") from exc


def _summary_table(rules: list[dict], result: dict) -> str:
    head = f"{'Rule':<8} {'Alerts':>6} {'TP':>4} {'FP':>4} {'Precision':>10} {'Recall':>8}  Title"
    lines = [head, "-" * len(head)]
    for r in rules:
        row = result["per_rule"][r["id"]]
        lines.append(f"{r['id']:<8} {row['alerts']:>6} {row['tp']:>4} {row['fp']:>4} "
                     f"{_pct(row['precision']):>10} {_pct(row['recall']):>8}  {r['title']}")
    o = result["overall"]
    lines.append("-" * len(head))
    lines.append(f"{'ALL':<8} {o['alerts']:>6} {o['tp']:>4} {o['fp']:>4} "
                 f"{_pct(o['precision']):>10} {_pct(o['recall']):>8}")
    return "\n".join(lines)


def _case_quality(ce: dict) -> str:
    bits = [_count(ce["scenarios_found"], "attack"),
            "none split" if not ce["split_scenarios"] else f"{len(ce['split_scenarios'])} split across cases",
            "none merged" if not ce["merged_cases"] else f"{_count(len(ce['merged_cases']), 'case')} mix attacks",
            _count(len(ce["false_positive_cases"]), "false-positive case")]
    return ", ".join(bits)


def cmd_validate(args) -> int:
    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("Rule validation FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"OK: {len(rules)} rules valid")
    return 0


def cmd_test_rules(args) -> int:
    from .unit_tests import exclusion_checks, run_rule_tests

    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("Rule validation FAILED:\n  " + "\n  ".join(errors))
        return 1
    rows = run_rule_tests(rules, only=args.rule)
    if not rows:
        print(f"No tests found{' for ' + args.rule if args.rule else ''}.")
        return 1
    by_rule: dict[str, list[dict]] = {}
    for row in rows:
        by_rule.setdefault(row["rule"], []).append(row)
    failed = [r for r in rows if not r["passed"]]
    for rid, items in by_rule.items():
        ok = sum(1 for r in items if r["passed"])
        print(f"{rid}  {ok}/{len(items)} tests passed")
        for r in items:
            if not r["passed"] or args.verbose:
                mark = "PASS" if r["passed"] else "FAIL"
                extra = f" - {r['message']}" if r["message"] else ""
                print(f"    {mark}  [{r['expect']}] {r['name']}{extra}")
    print(f"\n{len(rows) - len(failed)} of {len(rows)} rule tests passed across {len(by_rule)} rules.")
    checks = exclusion_checks(rules, only=args.rule)
    untested = [c for c in checks if not c["exercised"]]
    if checks:
        print(f"{len(checks) - len(untested)} of {len(checks)} exclusions are proven by a test "
              "(taking the exclusion away makes a test produce more alerts).")
    for c in untested:
        print(f"    MISSING  {c['rule']} exclusion #{c['index']} has no test that depends on it: {c['reason'][:80]}")
    missed: list[dict] = []
    if args.mutate and not failed:
        from .unit_tests import mutation_checks

        edits = mutation_checks(rules, only=args.rule)
        missed = [e for e in edits if not e["caught"]]
        print(f"{len(edits) - len(missed)} of {len(edits)} small edits to the rules are caught by a test "
              "(taking out a branch, a condition or a listed value, moving a threshold or a time window by one, "
              "dropping a group_by field, or taking out the alert throttling, turns a test red).")
        for e in missed:
            print(f"    NOT CAUGHT  {e['rule']}: {e['edit']}")
    return 1 if failed or untested or missed else 0


def cmd_replay(args) -> int:
    from . import replay as rp

    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("Rule validation FAILED:\n  " + "\n  ".join(errors))
        return 1
    if args.freeze:
        if args.split != "holdout" or args.dataset:
            print("--freeze runs all holdout datasets, so use: replay --split holdout --freeze")
            return 1
        try:
            record = rp.freeze_holdout(args.rules, args.dir)
        except (FileExistsError, ValueError) as exc:
            print(exc)
            return 1
        s = record["summary"]
        print(f"Stored the first holdout run in {Path(args.dir) / rp.FIRST_RUN_FILE}")
        print(f"  rules fingerprint {record['rules_fingerprint'][:16]}...  ({record['rule_count']} rules)")
        print(f"  {s['expectations_hit']} of {s['expectations']} expectations hit "
              f"({s['expectations_missed']} missed, {s['expectations_no_data']} not testable), {s['alerts']} alerts")
        return 0
    try:
        out = rp.replay(rules, args.dir, split=args.split, only=args.dataset, use_exclusions=not args.no_exclusions)
    except (OSError, ValueError) as exc:
        print(f"Could not replay: {exc}")
        return 1
    head = f"{'Dataset':<66} {'Split':<8} {'Events':>7} {'Alerts':>6}  {'Expected':<18} {'Result':<8} Labels (attack/other/unlabeled)"
    print(head)
    print("-" * len(head))
    for r in out["results"]:
        lab = r["labels"]
        if r["missed"]:
            verdict = "PARTIAL" if r["hit"] else "MISS"
        elif r["no_data"]:
            verdict = "HIT*" if r["hit"] else "NO DATA"
        else:
            verdict = "HIT"
        print(f"{r['id']:<66} {r['split']:<8} {r['events']:>7} {len(r['alerts']):>6}  "
              f"{','.join(r['expected']):<18} {verdict:<8} {lab['attack']}/{lab['other']}/{lab['unlabeled']}")
        if args.alerts:
            for a in r["alerts"]:
                ent = ", ".join(f"{k}={v}" for k, v in a["entity"].items())
                print(f"      {a['label']:<9} {a['rule_id']}  {a['first_ts']}  {a['events']:>3} ev  {ent[:90]}")
    s = out["summary"]
    print("-" * len(head))
    print(f"{s['datasets']} datasets, {s['events']:,} events, {s['alerts']} alerts. "
          f"Expectations hit: {s['expectations_hit']} of {s['expectations']} "
          f"({s['expectations_missed']} missed, {s['expectations_no_data']} not testable because the recording has "
          f"no events of the kind the rule reads); datasets fully hit: {s['datasets_fully_hit']} of {s['datasets']}.")
    lab = s["labels"]
    if lab["attack"] + lab["other"]:
        print(f"Alert labels: {lab['attack']} attack, {lab['other']} other, {lab['unlabeled']} unlabeled "
              f"({s['attack_share']:.0%} of labeled alerts are part of the recorded attack).")
    first = rp.load_first_run(args.dir)
    if first and args.split in ("holdout", "all"):
        diff = rp.compare_to_first_run(rules, first)
        fs = first["summary"]
        print(f"First holdout run (stored {first['ran_at']}): {fs['expectations_hit']} of {fs['expectations']} "
              f"expectations hit, {fs['alerts']} alerts.")
        if diff["unchanged"]:
            print("The rules have not changed since that run.")
        else:
            parts = [f"{k}: {', '.join(diff[k])}" for k in ("changed", "added", "removed") if diff[k]]
            print("Rules changed since that run (" + "; ".join(parts) + "), so the numbers above are no longer "
                  "an independent test. The first-run numbers stay the honest estimate.")
    return 0


def cmd_generate(args) -> int:
    events, truth = _make_logs(args.seed, args.days)
    write_dataset(events, truth, args.out)
    print(f"Wrote {len(events)} events and ground truth to {args.out}/")
    return 0


def cmd_detect(args) -> int:
    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("\n".join(errors))
        return 1
    events = load_events(_file(Path(args.data) / "events.jsonl",
                               f"Make the logs first with: python -m detlab generate --out {args.data}"))
    alerts = run_rules(events, rules, use_exclusions=not args.no_exclusions)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "alerts.jsonl", [a.to_dict() for a in alerts])
    print(f"{len(alerts)} alerts written to {out / 'alerts.jsonl'}")
    truth_path = Path(args.data) / "ground_truth.json"
    if truth_path.exists():
        truth = json.loads(truth_path.read_text())
        print()
        print(_summary_table(rules, evaluate(alerts, truth, rules)))
    return 0


def cmd_run(args) -> int:
    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("Rule validation FAILED:\n  " + "\n  ".join(errors))
        return 1

    events, truth = _make_logs(args.seed, args.days)
    out = Path(args.out)
    write_dataset(events, truth, out)
    prepare_events(events)

    tuned_alerts = run_rules(events, rules, use_exclusions=True)
    untuned_alerts = run_rules(events, rules, use_exclusions=False)
    tuned = evaluate(tuned_alerts, truth, rules)
    untuned = evaluate(untuned_alerts, truth, rules)

    write_jsonl(out / "alerts.jsonl", [a.to_dict() for a in tuned_alerts])
    write_jsonl(out / "alerts_untuned.jsonl", [a.to_dict() for a in untuned_alerts])

    cases = build_cases(tuned_alerts)
    case_eval = evaluate_cases(cases, truth)
    evasion = run_evasion(rules, args.seed, args.days)       # the logs above were made with the same seed and days

    report = render_report(rules, tuned_alerts, truth, tuned, untuned, cases=cases, case_eval=case_eval)
    report += "\n## False positives before tuning\n\n" + render_untuned_fp_table(untuned_alerts, untuned) + "\n"
    (out / "detection_report.md").write_text(report, encoding="utf-8")
    (out / "evasion_report.md").write_text(render_evasion_report(evasion), encoding="utf-8")

    print(f"Generated {len(events)} events ({args.days} days, seed {args.seed})\n")
    print("WITHOUT tuning (no exclusions):")
    print(_summary_table(rules, untuned))
    print("\nWITH tuning (documented exclusions applied):")
    print(_summary_table(rules, tuned))
    print("\nTIME TO DETECT (tuned rules):")
    print(ttd_text(tuned))
    print(f"\nINCIDENT CASES: {len(tuned_alerts)} alerts grouped into {len(cases)} cases "
          f"({_case_quality(case_eval)})")
    print(cases_text(cases))
    gaps = evasion["total"] - evasion["caught"]
    print(f"\nRED TEAM: {evasion['caught']} of {evasion['total']} evasion attacks caught, {gaps} open gaps "
          "documented. Details: python -m detlab evasion")
    print(f"\nReports: {out / 'detection_report.md'} and {out / 'evasion_report.md'}")
    return 0


def cmd_case(args) -> int:
    rules = _rules(args.rules)           # first, like every other command: a wrong rules folder is explained before anything else
    data = Path(args.data)
    events = load_events(_file(data / "events.jsonl", f"Make the logs first with: python -m detlab run --out {data}"))
    alerts = [Alert.from_dict(d) for d in read_jsonl(_file(data / "alerts.jsonl",
                                                           f"Make the alerts first with: python -m detlab run --out {data}"))]
    text = render_case(args.user, events, alerts, rules)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Case file written to {args.out}")
    else:
        print(text)
    return 0


def cmd_evasion(args) -> int:
    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("Rule validation FAILED:\n  " + "\n  ".join(errors))
        return 1
    try:
        evasion = run_evasion(rules, args.seed, args.days)
    except ValueError as exc:
        raise UserError(f"I cannot make the logs: {exc}.") from exc
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evasion_report.md").write_text(render_evasion_report(evasion), encoding="utf-8")
    print(evasion_text(evasion))
    print(f"\nReport: {out / 'evasion_report.md'}")
    return 0


def cmd_cases(args) -> int:
    alerts = [Alert.from_dict(d) for d in read_jsonl(_file(Path(args.data) / "alerts.jsonl",
                                                           f"Make the alerts first with: python -m detlab run --out {args.data}"))]
    cases = build_cases(alerts)
    print(f"{len(alerts)} alerts grouped into {len(cases)} incident cases\n")
    print(cases_text(cases))
    return 0


def cmd_app(args) -> int:
    from .app import MAX_DAYS, MAX_SEED, serve   # imported here so other commands start instantly

    if not 0 <= args.seed <= MAX_SEED:
        print(f"The seed must be a whole number from 0 to {MAX_SEED:,}.")
        return 1
    if not MIN_DAYS <= args.days <= MAX_DAYS:
        print(f"Days must be a whole number from {MIN_DAYS} to {MAX_DAYS}.")
        return 1
    if not Path(args.rules).is_dir():
        print(f"I cannot find the rules folder '{args.rules}'. Open the detection-lab folder first, "
              "then run this command again.")
        return 1
    try:
        return serve(args.rules, args.seed, args.days, args.port, open_browser=not args.no_browser)
    except (OSError, ValueError) as exc:
        print(f"The app could not start: {exc}")
        return 1


def cmd_export_sigma(args) -> int:
    from . import sigma

    rules = _rules(args.rules)
    errors = validate_rules(rules)
    if errors:
        print("Rule validation FAILED:\n  " + "\n  ".join(errors))
        return 1
    if args.check:                       # for CI: change nothing, fail when sigma/ no longer matches the rules
        problems = sigma.check_sigma(rules, args.out)
        if problems:
            print(f"{args.out}/ does not match the rules:\n  " + "\n  ".join(problems))
            return 1
        print(f"OK: {args.out}/ matches the {len(rules)} rules (Sigma files, INDEX.md and the hashes of the SIEM queries)")
        return 0
    result = sigma.write_sigma(rules, args.out)
    print(f"Wrote {len(result['exported'])} Sigma files and INDEX.md to {args.out}/")
    print(f"{len(result['not_exported'])} rules are not exported (Sigma cannot express them):")
    for rid, reason in result["not_exported"].items():
        print(f"  {rid}  {reason}")
    print("The Splunk and Sentinel queries in sigma/queries/ come from tools/make_sigma_queries.py, which needs pySigma. "
          "This command does not rewrite them.")
    return 0


def cmd_coverage(args) -> int:
    from .app import Lab
    from .coverage import group_gaps, render_text

    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        print(f"I cannot find the rules folder '{args.rules}'. Open the detection-lab folder first.")
        return 1
    try:
        lab = Lab(rules_dir, args.seed, args.days)       # runs the lab and the replay, so the levels are measured
    except ValueError as exc:
        print(exc)
        return 1
    cov = lab.coverage
    gap = None
    if args.group:
        gap = group_gaps(cov, args.group, limit=args.limit)
        if gap is None:
            print(f"No group named '{args.group}' in ATT&CK v{cov['attack']['version']}.")
            return 1
    if args.json:
        print(json.dumps({"attack": cov["attack"], "summary": cov["summary"], "group": gap,
                          "tactics": [{"name": c["name"], "with_a_rule": c["mapped"], "techniques": len(c["cells"])}
                                      for c in cov["columns"]]}, indent=2))
    else:
        print(render_text(cov, gap))
    return 1 if cov["problems"] else 0


def cmd_export_site(args) -> int:
    from .app import Lab
    from .site import build_site

    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        print(f"I cannot find the rules folder '{args.rules}'. Open the detection-lab folder first.")
        return 1
    print("Building the lab (this takes a moment)...")
    try:
        lab = Lab(rules_dir, args.seed, args.days)
        info = build_site(lab, args.out)
    except (OSError, ValueError) as exc:
        print(f"Could not write the site: {exc}")
        return 1
    print(f"Wrote {info['directory']}/index.html ({info['bytes'] / 1e6:.2f} MB). It needs no server: open it in a browser, "
          "or publish the folder on GitHub Pages.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detlab", description="Detection-as-code lab")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="lint the rule files")
    v.add_argument("--rules", default="rules")
    v.set_defaults(func=cmd_validate)

    t = sub.add_parser("test-rules", help="run the unit tests written inside each rule file")
    t.add_argument("--rules", default="rules")
    t.add_argument("--rule", help="only this rule, for example DET-004")
    t.add_argument("-v", "--verbose", action="store_true", help="list every test, not only failures")
    t.add_argument("--mutate", action="store_true",
                   help="also edit each rule in small ways (delete a condition, drop a listed value, move a threshold or "
                        "a time window by one, drop a group_by field, take out the alert throttling) and fail if some "
                        "edit is not noticed by any test")
    t.set_defaults(func=cmd_test_rules)

    rp = sub.add_parser("replay", help="run the rules over real public attack recordings (replay/manifest.yml)")
    rp.add_argument("--dir", default="replay")
    rp.add_argument("--rules", default="rules")
    rp.add_argument("--split", choices=["dev", "holdout", "all"], default="dev")
    rp.add_argument("--dataset", help="only this dataset id")
    rp.add_argument("--no-exclusions", action="store_true", help="ignore documented exclusions")
    rp.add_argument("--alerts", action="store_true", help="list every alert under its dataset")
    rp.add_argument("--freeze", action="store_true",
                    help="store the FIRST holdout run in replay/holdout-first-run.json (only once)")
    rp.set_defaults(func=cmd_replay)

    g = sub.add_parser("generate", help="generate a synthetic dataset")
    g.add_argument("--out", default="build")
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--days", type=int, default=MIN_DAYS)
    g.set_defaults(func=cmd_generate)

    d = sub.add_parser("detect", help="run rules over an existing dataset")
    d.add_argument("--data", default="build")
    d.add_argument("--rules", default="rules")
    d.add_argument("--out", default="build")
    d.add_argument("--no-exclusions", action="store_true", help="ignore documented exclusions")
    d.set_defaults(func=cmd_detect)

    r = sub.add_parser("run", help="generate, detect, score, and write the report")
    r.add_argument("--out", default="build")
    r.add_argument("--rules", default="rules")
    r.add_argument("--seed", type=int, default=7)
    r.add_argument("--days", type=int, default=MIN_DAYS)
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("case", help="build an incident case file for one user")
    c.add_argument("--user", required=True)
    c.add_argument("--data", default="build")
    c.add_argument("--rules", default="rules")
    c.add_argument("--out", help="write markdown here instead of stdout")
    c.set_defaults(func=cmd_case)

    cs = sub.add_parser("cases", help="group existing alerts into incident cases")
    cs.add_argument("--data", default="build")
    cs.set_defaults(func=cmd_cases)

    e = sub.add_parser("evasion", help="red-team check: attacks written to slip past the rules")
    e.add_argument("--rules", default="rules")
    e.add_argument("--out", default="build")
    e.add_argument("--seed", type=int, default=7)
    e.add_argument("--days", type=int, default=MIN_DAYS)
    e.set_defaults(func=cmd_evasion)

    sg = sub.add_parser("export-sigma", help="write the rules that Sigma can express to sigma/")
    sg.add_argument("--rules", default="rules")
    sg.add_argument("--out", default="sigma")
    sg.add_argument("--check", action="store_true",
                    help="change nothing; exit 1 if sigma/ (or the hashes of its SIEM queries) no longer match the rules")
    sg.set_defaults(func=cmd_export_sigma)

    cv = sub.add_parser("coverage", help="print the ATT&CK coverage of the rules")
    cv.add_argument("--rules", default="rules")
    cv.add_argument("--seed", type=int, default=7)
    cv.add_argument("--days", type=int, default=MIN_DAYS)
    cv.add_argument("--group", help="also list the techniques of this ATT&CK group that no rule maps to, e.g. APT29")
    cv.add_argument("--limit", type=int, default=12, help="how many gaps to list for a group")
    cv.add_argument("--json", action="store_true", help="print JSON instead of text")
    cv.set_defaults(func=cmd_coverage)

    es = sub.add_parser("export-site", help="write a read-only copy of the web page that needs no server (for GitHub Pages)")
    es.add_argument("--rules", default="rules")
    es.add_argument("--out", default="site")
    es.add_argument("--seed", type=int, default=7)
    es.add_argument("--days", type=int, default=MIN_DAYS)
    es.set_defaults(func=cmd_export_site)

    a = sub.add_parser("app", help="open the lab as a web page on this computer")
    a.add_argument("--rules", default="rules")
    a.add_argument("--seed", type=int, default=7)
    a.add_argument("--days", type=int, default=MIN_DAYS)
    a.add_argument("--port", type=int, default=8765)
    a.add_argument("--no-browser", action="store_true", help="do not open a browser tab automatically")
    a.set_defaults(func=cmd_app)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except UserError as exc:
        print(exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
