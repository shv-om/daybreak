"""python scripts/run_content_discovery.py --scope config/scope.lab.intrusive.json
GETs scope.discovery_prefixes x the small, checked-in wordlist (config/content_discovery_wordlist.json)
- read-only, no approval needed, no external tool (no ffuf/wfuzz/gobuster) - see
pagent.discover.run_content_discovery / pagent.tools.dir_probe for exactly what is sent and why
this is safe without a human approval step. Writes a JSON+Markdown report of what responded with
anything other than 404. Nothing found is fetched further and nothing is added to scope
automatically: review the report, then add whatever you want to keep testing to crawl_seeds (read-
only fetch) or allowed_probe_targets (active probing) in the scope file.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.audit import AuditLog
from pagent.discover import run_content_discovery
from pagent.policy import PolicyGateway
from pagent.report import build_report, to_markdown
from pagent.rules import candidates_from_discovery
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.dir_probe import make_dir_probe
from pagent.wordlist import WordlistError

ap = argparse.ArgumentParser()
ap.add_argument("--scope", default="config/scope.lab.json")
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--audit", default="audit/audit.jsonl")
ap.add_argument("--out", default="reports")
a = ap.parse_args()
for p in (a.db, a.audit):
    os.makedirs(os.path.dirname(p), exist_ok=True)
os.makedirs(a.out, exist_ok=True)

scope = Scope.load(a.scope)
if not scope.discovery_prefixes:
    sys.exit("scope.discovery_prefixes is empty - add at least one prefix (e.g. \"/\") to the scope file first")
if "dir_probe" not in scope.allowed_tools:
    sys.exit("'dir_probe' is not in scope.allowed_tools - add it to the scope file to enable content discovery")
gw = PolicyGateway(scope, {"dir_probe": make_dir_probe(scope)}, AuditLog(a.audit))
store = Store(a.db)

try:
    summary = run_content_discovery(gw, store, scope)
except WordlistError as e:
    sys.exit(f"wordlist error: {e}")
except ValueError as e:
    sys.exit(str(e))
print(json.dumps(summary, indent=2))
findings = candidates_from_discovery(store, summary["run_id"])
for f in findings:
    store.save_finding(summary["run_id"], f.to_dict())

report = build_report(summary["run_id"], scope, findings)
base = os.path.join(a.out, f"content-discovery-run{summary['run_id']}")
with open(base + ".json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
with open(base + ".md", "w", encoding="utf-8") as f:
    f.write(to_markdown(report))
print(json.dumps(report["summary"], indent=2))
print("wrote", base + ".json", "and", base + ".md", "| audit chain intact:", AuditLog.verify(a.audit))
