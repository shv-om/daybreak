"""Run a bounded batch of already-generated PayloadProposal values through payload_fuzz.

The first invocation requests approval and sends nothing.  Approve the exact tool+args with
scripts/approve.py, then rerun the identical command.  The approved args contain the exact payload
strings, so any payload change requires a new approval.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.fuzzing import PayloadFuzzError, payload_fuzz_finding, resolve_payload_batch
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.store import Store
from pagent.tools.payload_fuzz import make_payload_fuzz

ap = argparse.ArgumentParser()
ap.add_argument("--proposals", required=True)
ap.add_argument("--payload-id", action="append", required=True,
                help="P-... id to include; repeat this option for multiple payloads (same target only)")
ap.add_argument("--scope", required=True)
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--audit", default="audit/audit.jsonl")
ap.add_argument("--approvals", default="data/approvals.db")
ap.add_argument("--out", default="reports")
a = ap.parse_args()
for p in (a.db, a.audit, a.approvals):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
os.makedirs(a.out, exist_ok=True)

scope = Scope.load(a.scope)
with open(a.proposals, encoding="utf-8") as f:
    proposals_doc = json.load(f)
try:
    resolved = resolve_payload_batch(proposals_doc, a.payload_id, scope)
except PayloadFuzzError as e:
    sys.exit(f"not fuzzable: {e}")

gw = PolicyGateway(scope, {"payload_fuzz": make_payload_fuzz(scope)}, AuditLog(a.audit),
                   approvals=ApprovalStore(a.approvals))
store = Store(a.db)
run_id = store.start_run(scope)

print(f"resolved {len(resolved.payload_ids)} payload(s) -> {resolved.tool} {resolved.args}")
r = gw.execute(resolved.tool, resolved.args, proposed_by="proposal-fuzz:" + ",".join(resolved.hypothesis_ids))
call_id = store.record_tool_call(run_id, resolved.tool, resolved.args, r)
if not r["ok"]:
    msg = f"NOT RUN - {r['error']}"
    if "approval_request_id" in r:
        msg += (f" (approval id {r['approval_request_id']}; review with scripts/approve.py list, approve it, "
                "then rerun this exact command)")
    print(msg)
    sys.exit(0)

sha = store.tool_call_row(call_id)["output_sha256"]
args = resolved.args
finding = payload_fuzz_finding(call_id, sha, f"{args['host']}:{args['port']}", args["path"], args["param"],
                               r["untrusted_output"], resolved.payload_ids)
store.save_finding(run_id, finding.to_dict())
receipt = {
    "schema_version": "0.1",
    "run_id": run_id,
    "tool_call_id": call_id,
    "proposal": {"payload_ids": list(resolved.payload_ids), "hypothesis_ids": list(resolved.hypothesis_ids),
                 "model": proposals_doc.get("model"), "proposals_run_id": proposals_doc.get("run_id")},
    "approval_id": r.get("approval_id"),
    "tool": resolved.tool,
    "args": resolved.args,
    "finding": finding.to_dict(),
}
path = os.path.join(a.out, f"payload-fuzz-run{run_id}-call{call_id}.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(receipt, f, indent=2)
print(f"ran {len(resolved.payload_ids)} payload(s) (approval id {r.get('approval_id')})")
print(f"finding: {finding.id} - {finding.title} (status={finding.status})")
print("wrote", path)
print("audit chain intact:", AuditLog.verify(a.audit))
