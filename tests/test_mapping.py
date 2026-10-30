import json, os, unittest
from pagent.kb.mapping import KNOWN_RULES, check_against_kb, check_mapping, enrich_findings, load_mapping
from pagent.kb.store import KBStore
from pagent.report import build_report, to_markdown
from pagent.rules import candidates_from_observations
from test_findings import pipeline, BASE

ROOT = os.path.join(os.path.dirname(__file__), "..")


def kb_with(*entries):    # SYNTHETIC CWE rows
    kb = KBStore(":memory:")
    sid = kb.add_snapshot("cwe", "synthetic", "x" * 64, "synthetic-9.9", None, len(entries), 0, "synthetic")
    kb.upsert_cwe([{"cwe_id": c, "name": n, "abstraction": "Base", "status": st, "description": "d"} for c, n, st in entries], sid)
    return kb


def mapping(status="reviewed", ids=("CWE-9001",)):
    return {r: {"cwe_ids": [], "rationale": "synthetic", "review_status": "reviewed"} for r in KNOWN_RULES} | {
        "missing-header:content-security-policy": {"cwe_ids": list(ids), "rationale": "synthetic", "review_status": status}}


class StructureTests(unittest.TestCase):
    def test_shipped_mapping_is_structurally_valid(self):
        self.assertEqual(check_mapping(load_mapping(os.path.join(ROOT, "config", "cwe_mapping.json"))), [])

    def test_flags_problems(self):
        m = mapping()
        m["made-up-rule"] = m["open-port"]
        del m["open-port"]
        m["missing-header:referrer-policy"] = {"cwe_ids": ["79"], "rationale": "", "review_status": "maybe"}
        p = " | ".join(check_mapping(m))
        for needle in ("unknown rule: made-up-rule", "missing entry for rule: open-port", "cwe_ids must be", "review_status must", "rationale required"):
            self.assertIn(needle, p)


class KBCheckTests(unittest.TestCase):
    def test_reports_missing_and_deprecated(self):
        kb = kb_with(("CWE-9001", "Synthetic A", "Stable"), ("CWE-9002", "Synthetic B", "Deprecated"))
        m = mapping(ids=("CWE-9001", "CWE-9002", "CWE-9003"))
        rows = {r["cwe_id"]: r["problem"] for r in check_against_kb(m, kb)}
        self.assertEqual(rows, {"CWE-9001": "", "CWE-9002": "deprecated in snapshot", "CWE-9003": "not in CWE snapshot"})


class EnrichTests(unittest.TestCase):
    def findings(self):
        return pipeline([BASE])[4]

    def test_reviewed_mapping_attaches_with_provenance(self):
        kb, fs = kb_with(("CWE-9001", "Synthetic A", "Stable")), self.findings()
        out = enrich_findings(fs, kb, mapping("reviewed"))
        f = [x for x in fs if x.rule_id == "missing-header:content-security-policy"][0]
        self.assertEqual(f.weakness_ids, ["CWE-9001"])
        self.assertIn("KB snapshot 1", f.references[0])
        self.assertIn("synthetic-9.9", f.references[0])
        self.assertEqual(list(out["attached"]), [f.id])

    def test_proposed_not_attached_unless_requested(self):
        kb = kb_with(("CWE-9001", "Synthetic A", "Stable"))
        fs = self.findings()
        out = enrich_findings(fs, kb, mapping("proposed"))
        self.assertTrue(all(not f.weakness_ids for f in fs)); self.assertTrue(out["skipped"])
        fs2 = self.findings()
        enrich_findings(fs2, kb, mapping("proposed"), include_proposed=True)
        self.assertTrue(any(f.weakness_ids for f in fs2))

    def test_unusable_cwe_is_noted_not_attached(self):
        fs = self.findings()
        enrich_findings(fs, kb_with(("CWE-9001", "Synthetic A", "Deprecated")), mapping("reviewed"))
        f = [x for x in fs if x.rule_id == "missing-header:content-security-policy"][0]
        self.assertEqual(f.weakness_ids, [])
        self.assertTrue(any("not attached" in l for l in f.limitations))

    def test_report_lists_references(self):
        sc, gw, store, summ, fs = pipeline([BASE])
        enrich_findings(fs, kb_with(("CWE-9001", "Synthetic A", "Stable")), mapping("reviewed"))
        md = to_markdown(build_report(summ["run_id"], sc, fs))
        self.assertIn("Weakness IDs: CWE-9001", md)
        self.assertIn("  - CWE-9001: Synthetic A", md)


if __name__ == "__main__":
    unittest.main()
