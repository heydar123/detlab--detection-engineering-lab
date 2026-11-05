"""Turn the Sigma files in sigma/ into Splunk and Microsoft Sentinel (KQL) queries with pySigma.

This is a build step, not part of the lab: the finished queries are committed under sigma/queries/, so nobody has to
run it. Run it again after the rules change (python -m detlab export-sigma first), once per backend:

    pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon pysigma-pipeline-windows
    python tools/make_sigma_queries.py splunk

    pip install "pysigma<2" pysigma-backend-kusto pysigma-pipeline-sysmon pysigma-pipeline-windows
    python tools/make_sigma_queries.py kusto

The two backends need different pySigma major versions at the time of writing, so use two virtual environments.
A rule that a backend cannot convert is recorded with its error message instead of being hidden.
"""

import hashlib
import json
import sys
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIGMA = ROOT / "sigma"
OUT = SIGMA / "queries"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def splunk_backend():
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    from sigma.pipelines.sysmon import sysmon_pipeline
    return lambda: SplunkBackend(processing_pipeline=sysmon_pipeline() + splunk_windows_pipeline()), "spl", "splunk"


def kusto_backend():
    """Process, file and registry events go to the Defender XDR tables; Windows Security events to SecurityEvent."""
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.azuremonitor import azure_monitor_pipeline
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    def make(doc_text: str = ""):
        security = "service: security" in doc_text or ("product: windows\n" in doc_text and "category:" not in doc_text)
        pipeline = azure_monitor_pipeline(query_table="SecurityEvent") if security else microsoft_xdr_pipeline()
        return KustoBackend(processing_pipeline=pipeline)
    return make, "kql", "kql"


# A document that a backend cannot be asked to convert, with the reason that goes into the manifest.
def skip_reason(which: str, doc: str) -> str | None:
    if which == "kusto" and "correlation:" in doc:
        return "pysigma-backend-kusto has no support for correlation rules"
    if which == "kusto" and "product: aws" in doc:
        return "no standard pySigma pipeline maps CloudTrail field names to the AWSCloudTrail table"
    return None


def main(which: str) -> int:
    from sigma.collection import SigmaCollection

    make, ext, folder = {"splunk": splunk_backend, "kusto": kusto_backend}[which]()
    manifest_path = OUT / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"rules": {}, "tools": {}}
    manifest["tools"][which] = {"pysigma": version("pysigma"),
                                "backend": version("pysigma-backend-splunk" if which == "splunk" else "pysigma-backend-kusto")}
    (OUT / folder).mkdir(parents=True, exist_ok=True)
    ok = failed = 0
    for path in sorted(SIGMA.glob("DET-*.yml")):
        rid = path.stem
        entry = manifest["rules"].setdefault(rid, {})
        entry["sigma_sha256"] = sha(path)
        target = OUT / folder / f"{rid}.{ext}"
        try:
            text = path.read_text(encoding="utf-8")
            notes = []
            if which == "kusto":      # one document at a time, because the right table depends on the log source
                queries = []
                for doc in text.split("\n---\n"):
                    why = skip_reason(which, doc)
                    if why:
                        notes.append(why)
                        continue
                    try:
                        queries += make(doc).convert(SigmaCollection.from_yaml(doc))
                    except Exception as exc:          # keep what converted and say what did not
                        notes.append(f"{type(exc).__name__}: {str(exc)[:160]}".replace("\n", " "))
            else:                     # a fresh collection each time: convert() edits the rules it is given
                queries = make().convert(SigmaCollection.from_yaml(text))
            if not queries:
                raise ValueError("; ".join(notes) or "the backend returned no query")
            target.write_text("\n\n".join(f"-- {rid} query {i}\n{q}" if which == "kusto" else f"# {rid} query {i}\n{q}"
                                          for i, q in enumerate(queries, start=1)) + "\n", encoding="utf-8")
            entry[which] = {"status": "ok", "queries": len(queries), "sha256": sha(target), "notes": notes}
            ok += 1
        except Exception as exc:                                   # record every failure with its reason
            if target.exists():
                target.unlink()
            entry[which] = {"status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
            failed += 1
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sys.path.insert(0, str(ROOT))
    from detlab.rules import load_rules
    from detlab.sigma import export_all, write_index
    rules = load_rules(ROOT / "rules")
    write_index(rules, export_all(rules), SIGMA)
    print(f"{which}: {ok} converted, {failed} failed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("splunk", "kusto"):
        sys.exit("usage: python tools/make_sigma_queries.py splunk|kusto")
    sys.exit(main(sys.argv[1]))
