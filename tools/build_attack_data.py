"""Build detlab/data/attack.json from the official MITRE ATT&CK Enterprise STIX bundle.

The bundle is 55 MB. The lab only needs the tactics, the techniques, which technique replaced a revoked one, and
which techniques each group is known to use, so those are written to a small JSON file that is committed.

    curl -o enterprise-attack-20.0.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json
    python tools/build_attack_data.py enterprise-attack-20.0.json

The STIX file is only read as JSON text; nothing in it is executed.
"""

import hashlib
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "detlab" / "data" / "attack.json"
NOTICE = ("Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The "
          "MITRE Corporation. This file is a reduced copy of the ATT&CK Enterprise data, used under the ATT&CK "
          "Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/")


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main(path: str) -> None:
    raw = Path(path).read_bytes()
    bundle = json.loads(raw)
    objs = {o["id"]: o for o in bundle["objects"]}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")          # noqa: E731

    collection = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    matrix = next(o for o in bundle["objects"] if o["type"] == "x-mitre-matrix")
    tactics = [{"id": attack_id(objs[r]), "short": objs[r]["x_mitre_shortname"], "name": objs[r]["name"]}
               for r in matrix["tactic_refs"]]

    techniques, by_stix = {}, {}
    for o in bundle["objects"]:
        if o["type"] == "attack-pattern" and live(o) and attack_id(o):
            tid = attack_id(o)
            techniques[tid] = {"n": o["name"], "t": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
                               "p": tid.split(".")[0] if "." in tid else None}
            by_stix[o["id"]] = tid

    revoked_by = {}
    for o in bundle["objects"]:
        if o["type"] == "relationship" and o["relationship_type"] == "revoked-by":
            old, new = objs.get(o["source_ref"]), objs.get(o["target_ref"])
            if old and new and old["type"] == "attack-pattern" and attack_id(old) and attack_id(new):
                revoked_by[attack_id(old)] = attack_id(new)

    uses: dict[str, set] = {}
    for o in bundle["objects"]:
        if (o["type"] == "relationship" and o["relationship_type"] == "uses" and not o.get("revoked")
                and not o.get("x_mitre_deprecated") and o["source_ref"].startswith("intrusion-set--")
                and o["target_ref"] in by_stix):
            uses.setdefault(o["source_ref"], set()).add(by_stix[o["target_ref"]])
    groups = []
    for sid, techs in uses.items():
        g = objs[sid]
        if live(g) and attack_id(g):
            groups.append({"id": attack_id(g), "name": g["name"],
                           "aliases": [a for a in g.get("aliases", []) if a != g["name"]],
                           "techniques": sorted(techs)})
    groups.sort(key=lambda g: g["name"].lower())

    data = {"source": {"name": "MITRE ATT&CK Enterprise", "version": collection["x_mitre_version"],
                       "modified": collection["modified"], "stix_sha256": hashlib.sha256(raw).hexdigest(),
                       "built_by": "tools/build_attack_data.py"},
            "notice": NOTICE, "tactics": tactics, "techniques": techniques, "revoked_by": revoked_by, "groups": groups}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"ATT&CK {data['source']['version']}: {len(tactics)} tactics, {len(techniques)} techniques, "
          f"{len(groups)} groups, {len(revoked_by)} replaced techniques -> {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tools/build_attack_data.py enterprise-attack-<version>.json")
    main(sys.argv[1])
