"""python scripts/validate_mapping.py   - prints each mapped CWE with its name from YOUR snapshot, for human review."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.kb.mapping import check_against_kb, check_mapping, load_mapping
from pagent.kb.store import KBStore
m = load_mapping("config/cwe_mapping.json")
print("structural problems:", check_mapping(m) or "none")
for r in check_against_kb(m, KBStore("data/kb.db")):
    print(f"{r['rule']:<45} {r['cwe_id']:<9} [{r['review_status']}] {r['name']}  ({r['status']}) {r['problem']}")
