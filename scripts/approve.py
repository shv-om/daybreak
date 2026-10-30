"""Human approval console.   python scripts/approve.py list | approve ID | deny ID
Approvals expire (default 15 min), apply to the exact tool+arguments shown, and work once."""
import argparse, getpass, json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.approvals import ApprovalStore
ap = argparse.ArgumentParser()
ap.add_argument("action", choices=["list", "approve", "deny"])
ap.add_argument("id", nargs="?", type=int)
ap.add_argument("--db", default="data/approvals.db")
a = ap.parse_args()
os.makedirs(os.path.dirname(a.db), exist_ok=True)
s = ApprovalStore(a.db)
if a.action == "list":
    for i, tool, args, ts in s.pending():
        print(f"#{i}  {tool}  {args}  requested {time.strftime('%H:%M:%S', time.localtime(ts))}")
    print("(no pending requests)" if not s.pending() else "")
else:
    print("ok" if a.id and s.decide(a.id, a.action == "approve", getpass.getuser()) else "no such pending request")
