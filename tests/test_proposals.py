import json, unittest
from pagent.llm import OllamaClient
from pagent.proposals import (ContextProposalError, ContextualProposalEngine,
                              contextual_proposal_schema, parse_contextual_output,
                              validate_contextual_output)
from pagent.scope import Scope


def scope_for():
    return Scope.from_dict({
        "engagement_id": "P", "authorized_by": "SYNTHETIC TEST",
        "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2030-01-01T00:00:00+00:00",
        "allowed_hosts": ["localhost"], "allowed_cidrs": [], "excluded_hosts": [], "allowed_ports": [5000],
        "allowed_tools": ["reflect_probe", "sqli_probe"], "intrusive_allowed": True,
        "allowed_probe_targets": [{"path": "/rest/products/search", "param": "q"}],
    })


GOOD = {
    "hypotheses": [{
        "weakness_type": "reflected_input",
        "path": "/rest/products/search",
        "parameter": "q",
        "rationale": "Search input is an explicitly authorized reflection-test target.",
        "confidence": "low",
        "evidence_refs": ["F-abc"],
        "payloads": [{
            "payload": "pagent-context-marker<probe>",
            "category": "html_context_marker",
            "expected_signal": "Marker is reflected without entity encoding.",
            "rationale": "A short marker can distinguish raw reflection from encoded reflection."
        }]
    }]
}


class ContextParseTests(unittest.TestCase):
    def test_valid_proposal_is_normalized_as_suggested_only(self):
        hs = validate_contextual_output(GOOD, scope_for(), {"F-abc"})
        self.assertEqual(len(hs), 1)
        self.assertTrue(hs[0].id.startswith("H-"))
        self.assertTrue(hs[0].payloads[0].id.startswith("P-"))
        self.assertTrue(hs[0].payloads[0].requires_approval)
        self.assertEqual(hs[0].payloads[0].execution_state, "suggested_only")

    def test_out_of_scope_target_is_rejected(self):
        bad = json.loads(json.dumps(GOOD))
        bad["hypotheses"][0]["path"] = "/admin"
        with self.assertRaises(ContextProposalError):
            validate_contextual_output(bad, scope_for(), {"F-abc"})

    def test_unknown_evidence_reference_is_rejected(self):
        with self.assertRaises(ContextProposalError):
            validate_contextual_output(GOOD, scope_for(), set())

    def test_category_must_match_weakness_type(self):
        bad = json.loads(json.dumps(GOOD))
        bad["hypotheses"][0]["payloads"][0]["category"] = "quote_break"
        with self.assertRaises(ContextProposalError):
            parse_contextual_output(bad)

    def test_payload_is_bounded_and_single_line(self):
        for payload in ["", "x" * 257, "a\nb", "a\rb", "a\x00b"]:
            bad = json.loads(json.dumps(GOOD)); bad["hypotheses"][0]["payloads"][0]["payload"] = payload
            with self.assertRaises(ContextProposalError):
                parse_contextual_output(bad)


class ContextEngineTests(unittest.TestCase):
    def test_engine_uses_structured_schema_and_scope_validation(self):
        seen = {}
        def fake(url, payload, timeout):
            seen["format"] = payload["format"]
            seen["messages"] = payload["messages"]
            return {"message": {"content": json.dumps(GOOD)}, "eval_count": 7}
        c = OllamaClient("m", post=fake)
        hs, stats = ContextualProposalEngine(c).generate(scope_for(), {"findings": []}, {"F-abc"})
        self.assertEqual(seen["format"], contextual_proposal_schema())
        self.assertIn("proposal-only", seen["messages"][0]["content"])
        self.assertEqual(hs[0].weakness_type, "reflected_input")
        self.assertEqual(stats["eval_count"], 7)

    def test_evidence_text_passed_through_as_untrusted_context(self):
        seen = {}
        def fake(url, payload, timeout):
            seen["messages"] = payload["messages"]
            return {"message": {"content": json.dumps(GOOD)}, "eval_count": 1}
        c = OllamaClient("m", post=fake)
        ContextualProposalEngine(c).generate(scope_for(), {"findings": []}, {"F-abc"},
                                             evidence_text="### tool_call #1\nresponse:\nraw body here")
        self.assertIn("untrusted_tool_output", seen["messages"][1]["content"])
        self.assertIn("raw body here", seen["messages"][1]["content"])

    def test_model_cannot_smuggle_tool_execution_fields(self):
        bad = json.loads(json.dumps(GOOD))
        bad["hypotheses"][0]["payloads"][0]["tool"] = "sqli_probe"
        c = OllamaClient("m", post=lambda u, p, t: {"message": {"content": json.dumps(bad)}})
        with self.assertRaises(ContextProposalError):
            ContextualProposalEngine(c).generate(scope_for(), {}, {"F-abc"})


if __name__ == "__main__":
    unittest.main()
