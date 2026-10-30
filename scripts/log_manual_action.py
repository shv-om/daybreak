"""Record a human-performed confirmation against an existing finding. This script sends NOTHING to
any target - it only writes down what you, the operator, already did yourself and observed.

Typical use: you reviewed a 'candidate' SQLi/XSS signal, manually tested a real payload yourself
(browser / curl / Burp) against the authorized lab target, and want that recorded as evidence.

Usage:
  python scripts/log_manual_action.py --finding-id F-xxxxxxxxxx --performed-by "your name" \\
      --action "Submitted login form with crafted email field" \\
      --payload-sent "attacker@test.com' OR 1=1--" \\
      --observed-result "Received 200 with a valid auth token; logged in as admin@juice-sh.op" \\
      --i-performed-this-manually
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.manual_confirm import ManualConfirmError, apply_manual_action
from pagent.report import finding_markdown
from pagent.store import Store

ap = argparse.ArgumentParser()
ap.add_argument("--finding-id", required=True)
ap.add_argument("--performed-by", required=True)
ap.add_argument("--action", required=True, dest="action_description")
ap.add_argument("--payload-sent", required=True, help="exactly what you sent, verbatim")
ap.add_argument("--observed-result", required=True, help="exactly what you observed, verbatim")
ap.add_argument("--notes", default="")
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--out", default="reports")
ap.add_argument("--i-performed-this-manually", action="store_true", required=True,
                help="required confirmation that a human, not this tool, performed the action above")
a = ap.parse_args()

store = Store(a.db)
run_id, finding = store.get_finding(a.finding_id)
if finding is None:
    sys.exit(f"no finding with id {a.finding_id} in {a.db} (run the assessment/intrusive scripts first)")
try:
    updated = apply_manual_action(finding, a.performed_by, a.action_description, a.payload_sent, a.observed_result, a.notes)
except ManualConfirmError as e:
    sys.exit(f"error: {e}")
store.add_manual_action(a.finding_id, a.performed_by, a.action_description, a.payload_sent, a.observed_result, a.notes)
store.save_finding(run_id, updated)
os.makedirs(a.out, exist_ok=True)
base = os.path.join(a.out, f"manual-confirmation-{a.finding_id}")
json.dump(updated, open(base + ".json", "w", encoding="utf-8"), indent=2)
open(base + ".md", "w", encoding="utf-8").write(finding_markdown(updated))
print(f"finding {a.finding_id} status is now: {updated['status']}")
print("wrote", base + ".json", "and", base + ".md")
