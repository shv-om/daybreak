"""Execute ONE approved, human-reviewed PayloadProposal through the existing policy gateway.

Does not pass the model's payload string into any adapter (see pagent.execution for why); it
resolves the proposal's category to one of the existing fixed-shape adapters and requests/uses
approval for that adapter's own exact, deterministic arguments - the same approval lifecycle
scripts/run_intrusive.py already uses.

  1) python scripts/propose_tests.py --scope <scope> --model <model>       (writes a proposals-run<id>.json)
  2) python scripts/execute_proposal.py --proposals <file> --payload-id <id> --scope <scope>
                                                                            (requests approval, exits)
  3) python scripts/approve.py list                                       (see the pending request)
  4) python scripts/approve.py approve <id>
  5) python scripts/execute_proposal.py --proposals <file> --payload-id <id> --scope <scope>
                                                                            (now executes)

The original proposals-run<id>.json is never modified. A candidate finding from a successful run
is saved the same way scripts/run_intrusive.py saves one, using the same Finding builders - this
script adds no new finding type and no new storage schema.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.execution import ProposalExecutionError, resolve_from_file
from pagent.intrusive import login_sqli_finding, reflect_finding, sqli_finding
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.login_sqli_probe import make_login_sqli_probe
from pagent.tools.reflect_probe import make_reflect_probe
from pagent.tools.sqli_probe import make_sqli_probe

FINDING_BUILDERS = {"reflect_probe": reflect_finding, "sqli_probe": sqli_finding, "login_sqli_probe": login_sqli_finding}

ap = argparse.ArgumentParser()
ap.add_argument("--proposals", required=True, help="path to a proposals-run<id>.json file from scripts/propose_tests.py")
ap.add_argument("--payload-id", required=True, help="the P-... id of the one payload to execute")
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
with open(a.proposals, encoding="utf-8") as f:
    proposals_doc = json.load(f)

try:
    resolved = resolve_from_file(proposals_doc, a.payload_id, scope)
except ProposalExecutionError as e:
    sys.exit(f"not executable: {e}")

tools = {"reflect_probe": make_reflect_probe(scope), "sqli_probe": make_sqli_probe(scope),
         "login_sqli_probe": make_login_sqli_probe(scope)}
gw = PolicyGateway(scope, tools, AuditLog(a.audit), approvals=ApprovalStore(a.approvals))
store = Store(a.db)
run_id = store.start_run(scope)

print(f"resolved payload {resolved.payload_id} (category={resolved.category}) -> {resolved.tool} {resolved.args}")
r = gw.execute(resolved.tool, resolved.args, proposed_by=f"proposal:{resolved.hypothesis_id}")
call_id = store.record_tool_call(run_id, resolved.tool, resolved.args, r)

if not r["ok"]:
    msg = f"NOT RUN - {r['error']}"
    if "approval_request_id" in r:
        msg += f" (approval id {r['approval_request_id']}; run scripts/approve.py list, then approve.py approve <id>, then rerun this exact command)"
    print(msg)
    sys.exit(0)

host, port = resolved.args["host"], resolved.args["port"]
sha = store.tool_call_row(call_id)["output_sha256"]
build = FINDING_BUILDERS[resolved.tool]
param_or_field = resolved.args.get("param") or resolved.args.get("field")
finding = build(call_id, sha, f"{host}:{port}", resolved.args["path"], param_or_field, r["untrusted_output"])
store.save_finding(run_id, finding.to_dict())

receipt = {
    "schema_version": "0.1", "run_id": run_id, "tool_call_id": call_id,
    "proposal": {"hypothesis_id": resolved.hypothesis_id, "payload_id": resolved.payload_id, "category": resolved.category,
                "model": proposals_doc.get("model"), "proposals_run_id": proposals_doc.get("run_id")},
    "approval_id": r.get("approval_id"), "tool": resolved.tool, "args": resolved.args,
    "finding": finding.to_dict(),
}
receipt_path = os.path.join(a.out, f"proposal-execution-{resolved.payload_id}.json")
with open(receipt_path, "w", encoding="utf-8") as f:
    json.dump(receipt, f, indent=2)

print(f"{resolved.tool} {resolved.args['path']}{'#' if 'field' in resolved.args else '?'}{param_or_field}: "
     f"ran (approval id {r.get('approval_id')})")
print(f"finding: {finding.id} - {finding.title} (status={finding.status})")
print("wrote", receipt_path)
print("audit chain intact:", AuditLog.verify(a.audit))
