"""python scripts/run_discovery.py --scope config/scope.lab.json
Real HTTP HEAD requests to the lab target(s) listed in the scope file, through the policy gateway."""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.audit import AuditLog
from pagent.discover import run_discovery
from pagent.parse import model_view
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.http_head import make_http_head

ap = argparse.ArgumentParser()
ap.add_argument("--scope", default="config/scope.lab.json")
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--audit", default="audit/audit.jsonl")
a = ap.parse_args()
for p in (a.db, a.audit):
    os.makedirs(os.path.dirname(p), exist_ok=True)
scope = Scope.load(a.scope)
gw = PolicyGateway(scope, {"http_head": make_http_head()}, AuditLog(a.audit))
store = Store(a.db)
summary = run_discovery(gw, store, scope)
print(json.dumps(summary, indent=2))
print(json.dumps(model_view(store.observations(summary["run_id"])), indent=2))
print("audit chain intact:", AuditLog.verify(a.audit))
