"""python scripts/run_assessment.py --scope config/scope.lab.json
Discovery -> candidate rules -> verification -> CWE enrichment -> JSON + Markdown report in reports/.
Findings are also persisted (keyed by their stable id) so scripts/log_manual_action.py can find them later."""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.audit import AuditLog
from pagent.discover import run_discovery, run_port_discovery
from pagent.kb.mapping import check_mapping, enrich_findings, load_mapping
from pagent.kb.store import KBStore
from pagent.policy import PolicyGateway
from pagent.report import build_report, to_markdown
from pagent.rules import candidates_from_observations, open_port_findings
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.http_head import make_http_head
from pagent.tools.nmap_tcp import make_nmap_tcp
from pagent.verify import verify_candidates

ap = argparse.ArgumentParser()
ap.add_argument("--scope", default="config/scope.lab.json")
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--audit", default="audit/audit.jsonl")
ap.add_argument("--out", default="reports")
ap.add_argument("--kb", default="data/kb.db")
ap.add_argument("--mapping", default="config/cwe_mapping.json")
ap.add_argument("--include-proposed", action="store_true", help="also attach CWE mappings not yet marked reviewed")
a = ap.parse_args()
for p in (a.db, a.audit):
    os.makedirs(os.path.dirname(p), exist_ok=True)
os.makedirs(a.out, exist_ok=True)

scope = Scope.load(a.scope)
gw = PolicyGateway(scope, {"http_head": make_http_head(), "nmap_tcp": make_nmap_tcp()}, AuditLog(a.audit))
store = Store(a.db)
run_id = store.start_run(scope)
open_ports = run_port_discovery(gw, store, scope, run_id) if "nmap_tcp" in scope.allowed_tools else None
if open_ports is not None:
    print("open ports:", json.dumps(open_ports))
summary = run_discovery(gw, store, scope, run_id=run_id, open_ports=open_ports)
findings = open_port_findings(store, run_id) + candidates_from_observations(store, run_id)
verify_candidates(gw, store, run_id, findings)

if os.path.exists(a.kb):
    mapping = load_mapping(a.mapping)
    problems = check_mapping(mapping)
    if problems:
        sys.exit("mapping problems: " + "; ".join(problems))
    print("cwe enrichment:", json.dumps(enrich_findings(findings, KBStore(a.kb), mapping, a.include_proposed)))
else:
    print("no knowledge base at", a.kb, "- weakness IDs left empty (run scripts/kb_update.py first)")

for f in findings:
    store.save_finding(run_id, f.to_dict())

report = build_report(run_id, scope, findings)
base = os.path.join(a.out, f"run{run_id}")
with open(base + ".json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
with open(base + ".md", "w", encoding="utf-8") as f:
    f.write(to_markdown(report))
print(json.dumps(report["summary"], indent=2))
print("wrote", base + ".json", "and", base + ".md", "| audit chain intact:", AuditLog.verify(a.audit))
