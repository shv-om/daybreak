"""python scripts/show_actions.py --scope config/scope.lab.intrusive.json

Read-only inspection of exactly what pagent.actions.build_actions would hand a model for this
scope (Phase 3, not yet built) - lets you see today whether the registry matches what you'd
expect before anything consumes it. Makes no tool call and sends nothing to any target; only
reads the scope file.
"""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.actions import actions_as_text, build_actions
from pagent.scope import Scope

ap = argparse.ArgumentParser()
ap.add_argument("--scope", required=True)
a = ap.parse_args()

scope = Scope.load(a.scope)
actions = build_actions(scope)
if not actions:
    sys.exit("no actions available for this scope")

batch = [x for x in actions if x.kind == "batch"]
targeted = [x for x in actions if x.kind == "targeted"]
print(f"=== batch actions ({len(batch)}) ===")
print(actions_as_text(batch))
print(f"\n=== targeted actions ({len(targeted)}) ===")
print(actions_as_text(targeted) or "(none - scope.intrusive_allowed is false, or no allowed_probe_targets/allowed_tools match)")
print(f"\n{len(actions)} action(s) total")
