"""Generate contextual hypotheses and payload suggestions. PROPOSAL ONLY: this script never
executes a tool. Two-pass pipeline:
  1. REASONING (--reasoning-model, defaults to --model) - reviews current findings against real,
     recent evidence (pagent.evidence: actual sanitized response content, not just status/length)
     and decides which findings are worth a closer look.
  2. GENERATION (--model) - proposes hypotheses+payloads only for that reviewed subset, with the
     same evidence attached.
The two passes can be different models - Ollama loads/unloads whichever is requested per call.

Example:
  python scripts/propose_tests.py --scope config/scope.lab.intrusive.json \
      --model qwen2.5-coder:3b --reasoning-model qwen3:4b
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pagent.evidence import build_evidence, evidence_as_text
from pagent.llm import OllamaClient
from pagent.parse import model_view
from pagent.proposals import ContextProposalError, ContextualProposalEngine
from pagent.review import ReviewEngine, ReviewError
from pagent.scope import Scope
from pagent.store import Store
from pagent.suggestions.context import ContextBuilder
from pagent.suggestions.registry import SuggestionSourceRegistry

SUGGESTION_SOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "config", "suggestion_sources")

ap = argparse.ArgumentParser()
ap.add_argument("--scope", required=True)
ap.add_argument("--db", default="data/pentest.db")
ap.add_argument("--model", required=True, help="generation model (hypotheses + payloads)")
ap.add_argument("--reasoning-model", help="triage/review model; defaults to --model if omitted")
ap.add_argument("--ollama", default="http://127.0.0.1:11434")
ap.add_argument("--run-id", type=int)
ap.add_argument("--out", default="reports")
a = ap.parse_args()
reasoning_model = a.reasoning_model or a.model

scope = Scope.load(a.scope)
store = Store(a.db)
run_id = a.run_id
if run_id is None:
    row = store.db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    run_id = row[0] if row else None
if run_id is None:
    sys.exit("no runs found in this database yet - run discovery/crawl/probing first")

observations = model_view(store.observations(run_id))
findings = store.findings_for_run(run_id)
if not findings:
    sys.exit(f"no findings for run_id={run_id} - nothing to review")

registry = SuggestionSourceRegistry(SUGGESTION_SOURCES_DIR)
builder = ContextBuilder(store=store, scope=scope)

# Only compact, already-structured finding fields are sent to the model; raw tool output goes
# through evidence_text (below), kept separate and explicitly labeled untrusted.
finding_context = []
weakness_types_seen = set()
for f in findings:
    base = {k: f.get(k) for k in ("id", "rule_id", "asset", "title", "status", "applicability")}
    base.update(builder.build(f))
    if "weakness_type" in base.get("candidate", {}):
        weakness_types_seen.add(base["candidate"]["weakness_type"])
    finding_context.append(base)

evidence_text = evidence_as_text(build_evidence(store, run_id))

try:
    reasoning_client = OllamaClient(reasoning_model, host=a.ollama)
    print(f"[{reasoning_model}] reviewing {len(findings)} finding(s) against recent evidence ...")
    review_rows, review_stats = ReviewEngine(reasoning_client).review_detailed(findings, evidence_text)
    worth_ids = [row["finding_id"] for row in review_rows if row["worth_investigating"]]
except (OSError, json.JSONDecodeError, ReviewError) as e:
    sys.exit(f"review pass failed: {e}")

if not worth_ids:
    sys.exit("review pass: nothing flagged as worth a closer look right now - no proposals generated")
print(f"review pass: {len(worth_ids)}/{len(findings)} finding(s) worth investigating")

filtered_context = [c for c in finding_context if c["id"] in worth_ids]
valid_refs = {c["id"] for c in filtered_context}
suggestion_source_guidance = {wt: registry.guidance_for(wt) for wt in sorted(weakness_types_seen)}
context = {"run_id": run_id, "observations": observations, "findings": filtered_context,
          "suggestion_sources": suggestion_source_guidance}

try:
    generation_client = OllamaClient(a.model, host=a.ollama)
    print(f"[{a.model}] generating hypotheses + payload proposals ...")
    hypotheses, gen_stats = ContextualProposalEngine(generation_client).generate(
        scope, context, valid_refs, evidence_text=evidence_text)
except (OSError, json.JSONDecodeError, ContextProposalError) as e:
    sys.exit(f"generation pass failed: {e}")

result = {
    "proposal_only": True,
    "run_id": run_id,
    "reasoning_model": reasoning_model,
    "generation_model": a.model,
    "review": {"reviewed": review_rows, "worth_investigating": worth_ids, "stats": review_stats},
    "stats": gen_stats,
    "hypotheses": [h.to_dict() for h in hypotheses],
}

os.makedirs(a.out, exist_ok=True)
path = os.path.join(a.out, f"proposals-run{run_id}.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
print(json.dumps(result, indent=2))
print("wrote", path)
print("NOTE: proposals were not executed; execution_state remains suggested_only and requires human approval.")
