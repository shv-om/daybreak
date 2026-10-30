"""Record what happened when you manually tried a model-suggested payload. This script sends
NOTHING to any target - it only writes down what you, the operator, already did yourself and
observed, against the exact payload text copied from the proposals file (not re-typed, so the
record can't drift from what was actually suggested).

This does NOT update the underlying Finding. If a payload's outcome is "confirmed_signal" and you
want the Finding itself marked confirmed, use scripts/log_manual_action.py with the same payload
text as --payload-sent.

Usage:
  python scripts/log_proposal_outcome.py --proposals reports/proposals-run5.json \\
      --payload-id P-xxxxxxxxxxxx --outcome confirmed_signal --tested-by "your name" \\
      --observed-result "Boolean pair produced different status codes vs baseline, reproduced 3x" \\
      --i-tested-this-manually

  python scripts/log_proposal_outcome.py --proposals reports/proposals-run5.json --summary
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.store import Store
from pagent.suggestions.outcomes import (OUTCOMES, ProposalOutcomeError, build_outcome_record,
                                         summarize)

ap = argparse.ArgumentParser()
ap.add_argument("--proposals", required=True, help="path to a reports/proposals-run<id>.json file")
ap.add_argument("--payload-id", help="the P-... id of the suggested payload you tested")
ap.add_argument("--outcome", choices=OUTCOMES)
ap.add_argument("--tested-by")
ap.add_argument("--observed-result", help="exactly what you observed, verbatim")
ap.add_argument("--notes", default="")
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--summary", action="store_true", help="instead of logging, print the outcome tally for this run")
ap.add_argument("--i-tested-this-manually", action="store_true",
                help="required confirmation that a human, not this tool, tried the payload")
a = ap.parse_args()

with open(a.proposals, encoding="utf-8") as f:
    proposals = json.load(f)
store = Store(a.db)

if a.summary:
    rows = store.proposal_outcomes_for_run(proposals.get("run_id"))
    print(json.dumps(summarize(rows), indent=2))
    sys.exit(0)

missing = [opt for opt, val in (("--payload-id", a.payload_id), ("--outcome", a.outcome),
                                ("--tested-by", a.tested_by), ("--observed-result", a.observed_result))
          if not val]
if missing:
    sys.exit("missing required argument(s): " + ", ".join(missing))
if not a.i_tested_this_manually:
    sys.exit("refusing to log an outcome without --i-tested-this-manually")

try:
    record = build_outcome_record(proposals, a.payload_id, a.outcome, a.tested_by, a.observed_result, a.notes)
except ProposalOutcomeError as e:
    sys.exit(f"error: {e}")

store.record_proposal_outcome(**record)
print(f"logged outcome '{a.outcome}' for payload {a.payload_id} (hypothesis {record['hypothesis_id']})")
print(json.dumps(summarize(store.proposal_outcomes_for_run(proposals.get("run_id"))), indent=2))
