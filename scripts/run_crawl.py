"""python scripts/run_crawl.py --scope config/scope.lab.json
Fetches EXACTLY scope.crawl_seeds (read-only GET, no approval needed - see pagent.discover.run_crawl)
and writes a JSON+Markdown report of what was discovered. Nothing discovered is fetched further and
nothing is added to scope automatically: review the report, then add whatever you want crawled next
to crawl_seeds, or whatever you want actively probed to allowed_probe_targets, in the scope file."""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.audit import AuditLog
from pagent.discover import run_crawl
from pagent.policy import PolicyGateway
from pagent.report import build_report, to_markdown
from pagent.rules import candidates_from_crawl
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.http_get import make_http_get

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
if not scope.crawl_seeds:
    sys.exit("scope.crawl_seeds is empty - add at least one path (e.g. \"/\") to the scope file before crawling")
gw = PolicyGateway(scope, {"http_get": make_http_get(scope)}, AuditLog(a.audit))
store = Store(a.db)

summary = run_crawl(gw, store, scope)
print(json.dumps(summary, indent=2))
findings = candidates_from_crawl(store, summary["run_id"])
for f in findings:
    store.save_finding(summary["run_id"], f.to_dict())

report = build_report(summary["run_id"], scope, findings)
base = os.path.join(a.out, f"crawl-run{summary['run_id']}")
with open(base + ".json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
with open(base + ".md", "w", encoding="utf-8") as f:
    f.write(to_markdown(report))
print(json.dumps(report["summary"], indent=2))
print("wrote", base + ".json", "and", base + ".md", "| audit chain intact:", AuditLog.verify(a.audit))
