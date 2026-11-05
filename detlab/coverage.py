"""ATT&CK coverage: which techniques the rules map to, and how much evidence there is that they work.

The technique list, the tactic order and the groups come from the official MITRE ATT&CK Enterprise data
(``detlab/data/attack.json``, built by ``tools/build_attack_data.py``). ATT&CK(R) is a registered trademark of The MITRE
Corporation and the data is used under the ATT&CK Terms of Use, see the notice stored in that file.

Each technique gets one of four levels:

    0  no rule maps to it
    1  mapped: a rule lists it, as its main technique or under ``also``
    2  exercised in the lab: the main technique of a rule that caught at least one planted attack
    3  seen in a real recording: the main technique of a rule that fired on a recording it was expected to fire on

Only a rule's MAIN technique counts as evidence for levels 2 and 3. A technique under ``also`` is only "mapped".
A rule that fires does not prove it catches every way of using the technique. Coverage is a map of where to look,
not a score of how safe a network is.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / "data" / "attack.json"
LEVEL_NAMES = {0: "no rule", 1: "mapped", 2: "exercised in the lab", 3: "seen in a real recording"}


@lru_cache(maxsize=1)
def load_attack() -> dict:
    with open(DATA_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def resolve(attack: dict, technique_id: str) -> str:
    """Follow a revoked technique to the one that replaced it (it may take more than one step)."""
    seen = set()
    while technique_id in attack["revoked_by"] and technique_id not in seen:
        seen.add(technique_id)
        technique_id = attack["revoked_by"][technique_id]
    return technique_id


def rule_mapping_problems(rules: list[dict]) -> list[str]:
    """Techniques named by a rule that are not in the current ATT&CK data (revoked, replaced, or misspelled)."""
    attack = load_attack()
    out = []
    for r in rules:
        for tid in [r["attack"]["technique"], *r["attack"].get("also", [])]:
            if tid not in attack["techniques"]:
                new = resolve(attack, tid)
                hint = f" (replaced by {new})" if new != tid else ""
                out.append(f"{r['id']}: {tid} is not a current ATT&CK technique{hint}")
    return out


def compute(rules: list[dict], lab_rules: set[str], real_rules: set[str]) -> dict:
    """The coverage matrix and the group lens.

    ``lab_rules`` are the rules that caught a planted attack in the lab run; ``real_rules`` are the rules that
    fired on a real recording they were expected to fire on.
    """
    attack = load_attack()
    techniques = attack["techniques"]

    mapped: dict[str, set[str]] = {}          # technique -> rules that list it
    level: dict[str, int] = {}
    for r in rules:
        main = r["attack"]["technique"]
        for tid in {main, *r["attack"].get("also", [])}:
            if tid not in techniques:
                continue
            mapped.setdefault(tid, set()).add(r["id"])
            lvl = 1
            if tid == main:
                lvl = 3 if r["id"] in real_rules else 2 if r["id"] in lab_rules else 1
            level[tid] = max(level.get(tid, 0), lvl)

    children: dict[str, list[str]] = {}
    for tid, t in techniques.items():
        if t["p"]:
            children.setdefault(t["p"], []).append(tid)

    def cell(tid: str) -> dict:
        subs = sorted(children.get(tid, []))
        own = level.get(tid, 0)
        sub_levels = [level.get(s, 0) for s in subs]
        return {"id": tid, "name": techniques[tid]["n"], "level": own,
                "rules": sorted(mapped.get(tid, [])),
                "subs": [{"id": s, "name": techniques[s]["n"], "level": level.get(s, 0),
                          "rules": sorted(mapped.get(s, []))} for s in subs],
                "best": max([own, *sub_levels]), "subs_total": len(subs), "subs_mapped": sum(1 for v in sub_levels if v)}

    columns = []
    for tac in attack["tactics"]:
        parents = sorted((tid for tid, t in techniques.items() if not t["p"] and tac["short"] in t["t"]),
                         key=lambda tid: techniques[tid]["n"].lower())
        cells = [cell(tid) for tid in parents]
        columns.append({"id": tac["id"], "short": tac["short"], "name": tac["name"], "cells": cells,
                        "mapped": sum(1 for c in cells if c["best"] > 0)})

    all_ids = set(techniques)
    groups = []
    for g in attack["groups"]:
        ids = [t for t in g["techniques"] if t in all_ids]
        hit = [t for t in ids if level.get(t, 0) > 0]
        groups.append({"id": g["id"], "name": g["name"], "aliases": g["aliases"], "total": len(ids),
                       "mapped": len(hit), "share": (len(hit) / len(ids)) if ids else 0.0,
                       "techniques": {t: level.get(t, 0) for t in ids}})

    parents_all = [t for t, v in techniques.items() if not v["p"]]
    by_level = {n: sum(1 for v in level.values() if v == n) for n in (1, 2, 3)}
    return {
        "attack": {"version": attack["source"]["version"], "modified": attack["source"]["modified"][:10],
                   "notice": attack["notice"], "techniques": len(techniques), "parents": len(parents_all),
                   "groups": len(attack["groups"])},
        "levels": LEVEL_NAMES,
        "columns": columns,
        "summary": {"mapped_ids": len(level), "by_level": by_level,
                    "parents_with_any": sum(1 for p in parents_all if any(level.get(x, 0) for x in [p, *children.get(p, [])])),
                    "parents": len(parents_all), "rules": len(rules)},
        "groups": groups,
        "problems": rule_mapping_problems(rules),
    }


def group_gaps(cov: dict, group_name: str, limit: int = 12) -> dict | None:
    """The techniques a group uses that no rule maps to, using the group names and aliases of ATT&CK."""
    attack = load_attack()
    wanted = group_name.casefold()
    group = next((g for g in cov["groups"] if g["name"].casefold() == wanted
                  or wanted in (a.casefold() for a in g["aliases"])), None)
    if group is None:
        return None
    gaps = [t for t, lvl in group["techniques"].items() if lvl == 0]
    return {**group, "gaps": [(t, attack["techniques"][t]["n"]) for t in gaps[:limit]], "gap_count": len(gaps)}


def render_text(cov: dict, group: dict | None = None) -> str:
    """The coverage as plain text: one line per tactic, the levels, and (optionally) the gaps of one group."""
    s, a = cov["summary"], cov["attack"]
    by = s["by_level"]
    share = round(100 * s["parents_with_any"] / s["parents"]) if s["parents"] else 0
    lines = [f"ATT&CK v{a['version']} (modified {a['modified']}): {s['parents_with_any']} of {s['parents']} techniques "
             f"have a rule ({share}%).",
             f"{s['mapped_ids']} technique IDs are mapped by {s['rules']} rules: "
             f"{by.get(3, 0)} seen in a real recording, {by.get(2, 0)} exercised in the lab, {by.get(1, 0)} only mapped.",
             "", f"{'Tactic':<22} {'With a rule':>11} {'Techniques':>11}", "-" * 46]
    for col in cov["columns"]:
        lines.append(f"{col['name']:<22} {col['mapped']:>11} {len(col['cells']):>11}")
    lines += ["", "Coverage is a map of where to look, not a score for how safe a network is."]
    if cov["problems"]:
        lines += ["", "Problems:"] + [f"  {p}" for p in cov["problems"]]
    if group:
        lines += ["", f"{group['name']} uses {group['total']} techniques and sub-techniques; {group['mapped']} have a rule "
                      f"({round(100 * group['share'])}%), {group['gap_count']} do not. First gaps:"]
        lines += [f"  {tid:<10} {name}" for tid, name in group["gaps"]]
    return "\n".join(lines)
