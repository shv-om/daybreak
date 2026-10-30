"""Intrusive probes: require intrusive_allowed in scope AND a human approval per exact call.
  1) python scripts/run_intrusive.py --scope config/scope.lab.intrusive.json       (requests approval, exits)
  2) python scripts/approve.py list                                                (see pending request)
  3) python scripts/approve.py approve <id>      (repeat for every pending request shown)
  4) python scripts/run_intrusive.py --scope config/scope.lab.intrusive.json       (now executes)

If a probe signals, the finding stays a 'candidate' - this script never sends an exploit payload.
To record a human-performed confirmation afterwards, use scripts/log_manual_action.py.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.fuzz import reflect_fuzz_finding, sqli_fuzz_finding
from pagent.intrusive import LOGIN_TARGETS, login_sqli_finding, reflect_finding, sqli_finding
from pagent.policy import PolicyGateway
from pagent.report import build_report, to_markdown
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.fuzz_probe import make_fuzz_probe
from pagent.tools.login_sqli_probe import make_login_sqli_probe
from pagent.tools.reflect_probe import make_reflect_probe
from pagent.tools.sqli_probe import make_sqli_probe

ap = argparse.ArgumentParser()
ap.add_argument("--scope", required=True)
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--audit", default="audit/audit.jsonl")
ap.add_argument("--approvals", default="data/approvals.db")
ap.add_argument("--out", default="reports")
a = ap.parse_args()
for p in (a.db, a.audit, a.approvals):
    os.makedirs(os.path.dirname(p), exist_ok=True)
os.makedirs(a.out, exist_ok=True)

scope = Scope.load(a.scope)
if not scope.allowed_probe_targets:
    sys.exit("scope.allowed_probe_targets is empty: nothing is authorized for active probing")

tools = {"reflect_probe": make_reflect_probe(scope), "sqli_probe": make_sqli_probe(scope),
         "login_sqli_probe": make_login_sqli_probe(scope)}
run_fuzz = "fuzz_probe" in scope.allowed_tools   # opt-in via scope, same as every other tool here
if run_fuzz:
    tools["fuzz_probe"] = make_fuzz_probe(scope)
gw = PolicyGateway(scope, tools, AuditLog(a.audit), approvals=ApprovalStore(a.approvals))
store = Store(a.db)
run_id = store.start_run(scope)
host = sorted(scope.allowed_hosts)[0] if scope.allowed_hosts else "localhost"
port = min(scope.allowed_ports)
findings = []

for path, param in scope.allowed_probe_targets:
    if (path, param) in LOGIN_TARGETS:
        jobs = [("login_sqli_probe", {"host": host, "port": port, "path": path, "field": param}, login_sqli_finding)]
    else:
        jobs = [("reflect_probe", {"host": host, "port": port, "path": path, "param": param}, reflect_finding),
                ("sqli_probe", {"host": host, "port": port, "path": path, "param": param}, sqli_finding)]
        if run_fuzz:   # payload fuzzing: an expanded, still fully fixed-in-code diagnostic battery - see pagent.tools.fuzz_probe
            jobs += [("fuzz_probe", {"host": host, "port": port, "path": path, "param": param, "category": "sql_injection"}, sqli_fuzz_finding),
                    ("fuzz_probe", {"host": host, "port": port, "path": path, "param": param, "category": "reflected_input"}, reflect_fuzz_finding)]
    for tool, args, build in jobs:
        r = gw.execute(tool, args, proposed_by="deterministic")
        call_id = store.record_tool_call(run_id, tool, args, r)
        if not r["ok"]:
            print(f"{tool} {path}?{param}: NOT RUN - {r['error']}" +
                 (f" (approval id {r['approval_request_id']})" if "approval_request_id" in r else ""))
            continue
        sha = store.tool_call_row(call_id)["output_sha256"]
        findings.append(build(call_id, sha, f"{host}:{port}", path, param, r["untrusted_output"]))
        print(f"{tool} {path}?{param}: ran (approval id {r.get('approval_id')})")

for f in findings:
    store.save_finding(run_id, f.to_dict())

if findings:
    report = build_report(run_id, scope, findings)
    base = os.path.join(a.out, f"intrusive-run{run_id}")
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(to_markdown(report))
    print(json.dumps(report["summary"], indent=2))
    print("wrote", base + ".json", "and", base + ".md")
print("audit chain intact:", AuditLog.verify(a.audit))
