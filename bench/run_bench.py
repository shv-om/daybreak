"""python bench/run_bench.py --model qwen3:4b-instruct-2507-q4_K_M --repeats 3 --port 5000
Needs Ollama running. Scoring uses a fake HTTP transport: nothing touches the network except Ollama."""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.bench import load_cases, run_case, summarize
from pagent.llm import OllamaClient, constrained_schema
from pagent.scope import Scope

root = os.path.join(os.path.dirname(__file__), "..")
ap = argparse.ArgumentParser()
ap.add_argument("--model", default="qwen3:4b-instruct-2507-q4_K_M")
ap.add_argument("--repeats", type=int, default=3)
ap.add_argument("--port", type=int, default=5000)
ap.add_argument("--num-ctx", type=int, default=4096)
ap.add_argument("--constrain", action="store_true", help="experimental stricter output schema")
a = ap.parse_args()

with open(os.path.join(root, "config", "scope.lab.json"), encoding="utf-8") as f:
    d = json.load(f)
d["allowed_ports"] = [a.port]
scope = Scope.from_dict(d)
cases = load_cases(os.path.join(root, "bench", "cases.json"))
client = OllamaClient(a.model, num_ctx=a.num_ctx, schema=constrained_schema() if a.constrain else None)
results = []
for rep in range(a.repeats):
    for case in cases:
        r = run_case(client, case, scope, a.port)
        r["repeat"] = rep
        results.append(r)
        print(f"[{rep}] {r['id']:<18} {'PASS' if r['passed'] else 'FAIL'}  {r.get('tool', r.get('error'))} {r.get('args', '')}")
summary = summarize(results)
print("\n" + json.dumps(summary, indent=2))
out = os.path.join(root, "bench", "results", f"{a.model.replace(':', '_').replace('/', '_')}{'-constrained' if a.constrain else ''}-{time.strftime('%Y%m%d-%H%M%S')}.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump({"model": a.model, "num_ctx": a.num_ctx, "repeats": a.repeats, "constrained": a.constrain, "summary": summary, "results": results}, f, indent=1)
print("saved", out)
