import json, unittest
from pagent.evidence import evidence_as_text
from pagent.llm import OllamaClient
from pagent.review import ReviewEngine, ReviewError, parse_review, review_schema, validate_review

GOOD = {"reviewed": [{"finding_id": "F-abc", "worth_investigating": True, "note": "status differs from baseline"},
                     {"finding_id": "F-xyz", "worth_investigating": False, "note": "nothing unusual"}]}


class ParseReviewTests(unittest.TestCase):
    def test_valid_parses(self):
        self.assertEqual(len(parse_review(GOOD)["reviewed"]), 2)

    def test_valid_parses_from_json_string(self):
        self.assertEqual(len(parse_review(json.dumps(GOOD))["reviewed"]), 2)

    def test_wrong_root_keys_rejected(self):
        with self.assertRaises(ReviewError):
            parse_review({"results": []})

    def test_extra_field_rejected(self):
        bad = json.loads(json.dumps(GOOD))
        bad["reviewed"][0]["severity"] = "high"
        with self.assertRaises(ReviewError):
            parse_review(bad)

    def test_non_bool_worth_investigating_rejected(self):
        bad = json.loads(json.dumps(GOOD))
        bad["reviewed"][0]["worth_investigating"] = "yes"
        with self.assertRaises(ReviewError):
            parse_review(bad)

    def test_too_many_items_rejected(self):
        bad = {"reviewed": [{"finding_id": f"F-{i}", "worth_investigating": True, "note": ""} for i in range(20)]}
        with self.assertRaises(ReviewError):
            parse_review(bad)

    def test_malformed_json_rejected(self):
        with self.assertRaises(ReviewError):
            parse_review("{not json")


class ValidateReviewTests(unittest.TestCase):
    def test_returns_only_worth_investigating_ids_in_order(self):
        out = validate_review(GOOD, {"F-abc", "F-xyz"})
        self.assertEqual(out, ["F-abc"])

    def test_unknown_finding_id_rejected(self):
        with self.assertRaises(ReviewError):
            validate_review(GOOD, {"F-xyz"})   # F-abc not in the valid set

    def test_empty_valid_ids_rejects_everything_referenced(self):
        with self.assertRaises(ReviewError):
            validate_review(GOOD, set())


class ReviewEngineTests(unittest.TestCase):
    def test_engine_uses_structured_schema_and_untrusted_context_wrapping(self):
        seen = {}
        def fake(url, payload, timeout):
            seen["format"] = payload["format"]
            seen["messages"] = payload["messages"]
            return {"message": {"content": json.dumps(GOOD)}, "eval_count": 3}
        c = OllamaClient("reasoning-model", post=fake)
        findings = [{"id": "F-abc", "rule_id": "sqli-boolean-signal", "title": "t", "status": "candidate",
                    "confidence": {"level": "low"}},
                   {"id": "F-xyz", "rule_id": "missing-header:x", "title": "t2", "status": "candidate",
                    "confidence": {"level": "low"}}]
        ids, stats = ReviewEngine(c).review(findings, evidence_text="### tool_call #1\nresponse:\nhello")
        self.assertEqual(seen["format"], review_schema())
        self.assertIn("untrusted_tool_output", seen["messages"][1]["content"])
        self.assertIn("hello", seen["messages"][1]["content"])
        self.assertEqual(ids, ["F-abc"])
        self.assertEqual(stats["eval_count"], 3)

    def test_findings_without_id_are_excluded_from_valid_set(self):
        c = OllamaClient("m", post=lambda u, p, t: {"message": {"content": json.dumps(GOOD)}})
        findings = [{"rule_id": "x", "title": "t", "status": "candidate", "confidence": {}}]   # no "id"
        with self.assertRaises(ReviewError):
            ReviewEngine(c).review(findings)   # GOOD references F-abc, which isn't in the valid set


class EvidenceAsTextTests(unittest.TestCase):
    def test_renders_allowed_call_with_excerpt(self):
        entries = [{"tool_call_id": 1, "tool": "http_get", "args": {"host": "h", "port": 1, "path": "/"},
                   "allowed": True, "reason": None, "ts": 0.0, "source": "untrusted_target_response",
                   "output_excerpt": "status=200\n\nhi", "output_truncated": False}]
        text = evidence_as_text(entries)
        self.assertIn("tool_call #1", text)
        self.assertIn("http_get", text)
        self.assertIn("status=200", text)
        self.assertIn("hi", text)

    def test_renders_denied_call_with_reason_no_excerpt(self):
        entries = [{"tool_call_id": 2, "tool": "sqli_probe", "args": {}, "allowed": False,
                   "reason": "approval required", "ts": 0.0, "source": "untrusted_target_response",
                   "output_excerpt": None, "output_truncated": False}]
        text = evidence_as_text(entries)
        self.assertIn("denied_reason=approval required", text)
        self.assertNotIn("response", text)

    def test_truncated_marker_shown(self):
        entries = [{"tool_call_id": 3, "tool": "http_get", "args": {}, "allowed": True, "reason": None,
                   "ts": 0.0, "source": "untrusted_target_response", "output_excerpt": "abc",
                   "output_truncated": True}]
        self.assertIn("[TRUNCATED]", evidence_as_text(entries))

    def test_empty_list_renders_empty_string(self):
        self.assertEqual(evidence_as_text([]), "")


if __name__ == "__main__":
    unittest.main()
