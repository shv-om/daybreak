"""python scripts/show_evidence.py --run-id 5 [--asset-prefix "localhost:5000"] [--max-calls 12]

Read-only inspection of exactly what pagent.evidence.build_evidence would hand a model for this
run - lets you see what Phase 1 captured before anything in Phase 2/3 actually consumes it. Makes
no tool call and sends nothing to any target; only reads from the existing evidence DB.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.evidence import DEFAULT_MAX_BODY_CHARS, DEFAULT_MAX_CALLS, build_evidence
from pagent.store import Store

ap = argparse.ArgumentParser()
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--run-id", type=int, required=True)
ap.add_argument("--asset-prefix", default=None, help='e.g. "localhost:5000" or "localhost:5000/rest/"')
ap.add_argument("--max-calls", type=int, default=DEFAULT_MAX_CALLS)
ap.add_argument("--max-body-chars", type=int, default=DEFAULT_MAX_BODY_CHARS)
a = ap.parse_args()

store = Store(a.db)
entries = build_evidence(store, a.run_id, asset_prefix=a.asset_prefix, max_calls=a.max_calls,
                         max_body_chars=a.max_body_chars)
if not entries:
    sys.exit(f"no tool calls found for run_id={a.run_id} (asset_prefix={a.asset_prefix!r})")

for e in entries:
    print(f"--- tool_call #{e['tool_call_id']}  {e['tool']}  allowed={e['allowed']}" + (f"  reason={e['reason']}" if e['reason'] else ""))
    print("args:", json.dumps(e["args"]))
    if e["output_excerpt"] is not None:
        print(f"output (untrusted target response){' [TRUNCATED]' if e['output_truncated'] else ''}:")
        print(e["output_excerpt"])
    print()
print(f"{len(entries)} call(s) shown, most recent first")
