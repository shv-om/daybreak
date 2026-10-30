import os, tempfile, unittest

from pagent.store import Store
from pagent.suggestions.outcomes import (ProposalOutcomeError, build_outcome_record, find_payload,
                                         summarize)

PROPOSALS = {
    "proposal_only": True,
    "run_id": 5,
    "model": "qwen3:4b-instruct-2507-q4_K_M",
    "hypotheses": [{
        "id": "H-abc123",
        "weakness_type": "sql_injection",
        "path": "/rest/products/search",
        "parameter": "q",
        "rationale": "...",
        "confidence": "low",
        "evidence_refs": ["F-abc"],
        "payloads": [
            {"id": "P-one", "hypothesis_id": "H-abc123", "payload": "a'", "category": "quote_break",
             "expected_signal": "response shape changes", "rationale": "..."},
            {"id": "P-two", "hypothesis_id": "H-abc123", "payload": "1 AND 1=1", "category": "boolean_pair",
             "expected_signal": "matches baseline", "rationale": "..."},
        ],
    }],
}


class FindPayloadTests(unittest.TestCase):
    def test_finds_existing_payload(self):
        h, p = find_payload(PROPOSALS, "P-two")
        self.assertEqual(h["id"], "H-abc123")
        self.assertEqual(p["category"], "boolean_pair")

    def test_unknown_payload_id_raises(self):
        with self.assertRaises(ProposalOutcomeError):
            find_payload(PROPOSALS, "P-nonexistent")


class BuildOutcomeRecordTests(unittest.TestCase):
    def test_valid_record(self):
        rec = build_outcome_record(PROPOSALS, "P-one", "confirmed_signal", "alice",
                                   "Got a 500 with the quote payload vs 200 baseline, reproduced twice.")
        self.assertEqual(rec["run_id"], 5)
        self.assertEqual(rec["model"], "qwen3:4b-instruct-2507-q4_K_M")
        self.assertEqual(rec["hypothesis_id"], "H-abc123")
        self.assertEqual(rec["payload_id"], "P-one")
        self.assertEqual(rec["weakness_type"], "sql_injection")
        self.assertEqual(rec["category"], "quote_break")
        self.assertEqual(rec["payload_text"], "a'")       # copied verbatim from the proposal
        self.assertEqual(rec["tested_by"], "alice")

    def test_rejects_unknown_outcome(self):
        with self.assertRaises(ProposalOutcomeError):
            build_outcome_record(PROPOSALS, "P-one", "worked_great", "alice", "it worked")

    def test_rejects_empty_required_fields(self):
        with self.assertRaises(ProposalOutcomeError):
            build_outcome_record(PROPOSALS, "P-one", "no_signal", "", "nothing happened")
        with self.assertRaises(ProposalOutcomeError):
            build_outcome_record(PROPOSALS, "P-one", "no_signal", "alice", "   ")

    def test_rejects_unknown_payload(self):
        with self.assertRaises(ProposalOutcomeError):
            build_outcome_record(PROPOSALS, "P-nope", "no_signal", "alice", "nothing happened")


class SummarizeTests(unittest.TestCase):
    def test_counts_and_rate(self):
        rows = [{"outcome": "confirmed_signal"}, {"outcome": "no_signal"}, {"outcome": "no_signal"},
                {"outcome": "false_lead"}]
        s = summarize(rows)
        self.assertEqual(s["total_tested"], 4)
        self.assertEqual(s["counts"]["confirmed_signal"], 1)
        self.assertEqual(s["counts"]["no_signal"], 2)
        self.assertEqual(s["counts"]["false_lead"], 1)
        self.assertEqual(s["counts"]["inconclusive"], 0)
        self.assertEqual(s["confirmed_rate"], 0.25)

    def test_empty_rows_rate_is_none_not_zero_division(self):
        s = summarize([])
        self.assertEqual(s["total_tested"], 0)
        self.assertIsNone(s["confirmed_rate"])


class StoreRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)

    def tearDown(self):
        self.store.db.close()
        os.unlink(self.tmp.name)

    def test_record_and_fetch_by_run(self):
        rec = build_outcome_record(PROPOSALS, "P-one", "confirmed_signal", "alice", "signal reproduced")
        self.store.record_proposal_outcome(**rec)
        rows = self.store.proposal_outcomes_for_run(5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload_id"], "P-one")
        self.assertEqual(rows[0]["outcome"], "confirmed_signal")
        self.assertIn("row_sha256", rows[0])

    def test_fetch_by_payload_id(self):
        rec = build_outcome_record(PROPOSALS, "P-two", "no_signal", "bob", "matched baseline exactly")
        self.store.record_proposal_outcome(**rec)
        rows = self.store.proposal_outcomes_for_payload("P-two")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tested_by"], "bob")

    def test_run_with_no_outcomes_returns_empty(self):
        self.assertEqual(self.store.proposal_outcomes_for_run(999), [])


if __name__ == "__main__":
    unittest.main()
