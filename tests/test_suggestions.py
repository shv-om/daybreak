import json
import os
import tempfile
import unittest

from pagent.scope import Scope
from pagent.store import Store
from pagent.suggestions.context import ContextBuilder, ContextBuilderError, build_context
from pagent.suggestions.registry import SuggestionSourceError, SuggestionSourceRegistry
from pagent.suggestions.strategy import (TestStrategyError, parse_test_strategy,
                                         test_strategy_schema, validate_test_strategy)

REPO_SOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "config", "suggestion_sources")


def scope_for(probe_targets=(("/rest/products/search", "q"), ("/rest/user/login", "email"))):
    return Scope.from_dict({
        "engagement_id": "T", "authorized_by": "SYNTHETIC TEST",
        "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2030-01-01T00:00:00+00:00",
        "allowed_hosts": ["localhost"], "allowed_cidrs": [], "excluded_hosts": [], "allowed_ports": [5000],
        "allowed_tools": ["reflect_probe", "sqli_probe", "login_sqli_probe"], "intrusive_allowed": True,
        "allowed_probe_targets": [{"path": p, "param": q} for p, q in probe_targets],
    })


def sqli_finding(evidence_observation_ids=()):
    return {
        "id": "F-sqli1", "rule_id": "sqli-boolean-signal", "asset": "localhost:5000/rest/products/search?q",
        "title": "Boolean-based SQL injection signal on /rest/products/search?q", "status": "candidate",
        "applicability": "Single parameter on one named path, GET only",
        "verification": {"method": "boolean pair", "result": "signal"},
        "evidence": [{"tool_call_id": 1, "observation_ids": list(evidence_observation_ids),
                      "output_sha256": "abc", "role": "initial"}],
        "confidence": {"level": "low", "why": "response-shape heuristic only"},
    }


def login_sqli_finding():
    return {
        "id": "F-login1", "rule_id": "login-sqli-boolean-signal", "asset": "localhost:5000/rest/user/login#email",
        "title": "Boolean-based SQL injection signal on login field 'email'", "status": "candidate",
        "applicability": "Single field on one named login endpoint, quote-breaking values only",
        "verification": {"method": "boolean pair", "result": "signal"},
        "evidence": [{"tool_call_id": 2, "observation_ids": [], "output_sha256": "def", "role": "initial"}],
        "confidence": {"level": "low", "why": "response-shape heuristic only"},
    }


def header_finding():
    return {
        "id": "F-hdr1", "rule_id": "missing-header:content-security-policy", "asset": "localhost:5000",
        "title": "Content-Security-Policy header not observed", "status": "candidate",
        "applicability": "HTML responses over HTTP(S)",
        "verification": {"method": "pending", "result": "pending"},
        "evidence": [{"tool_call_id": 3, "observation_ids": [], "output_sha256": "ghi", "role": "initial"}],
        "confidence": {"level": "low", "why": "single observation, not yet repeated"},
    }


class ContextBuilderWithoutStoreTests(unittest.TestCase):
    def test_minimal_finding_requires_id_and_asset(self):
        with self.assertRaises(ContextBuilderError):
            build_context({"id": "F-x"})

    def test_sqli_query_param_finding_populated_without_store(self):
        ctx = build_context(sqli_finding())
        self.assertEqual(ctx["endpoint"], {"method": "GET", "path": "/rest/products/search"})
        self.assertEqual(ctx["parameter"], {"name": "q", "location": "query", "observed_type": "string"})
        self.assertEqual(ctx["candidate"]["weakness_type"], "sql_injection")
        self.assertEqual(ctx["candidate"]["finding_id"], "F-sqli1")
        self.assertEqual(ctx["candidate"]["confidence"], "low")
        self.assertEqual(ctx["candidate"]["observed_result"], "signal")
        self.assertEqual(ctx["technology_context"], {"endpoint_role": "search"})
        self.assertNotIn("baseline", ctx)          # no store, no evidence -> never fabricated

    def test_login_json_body_field_finding(self):
        ctx = build_context(login_sqli_finding())
        self.assertEqual(ctx["endpoint"]["method"], "POST")
        self.assertEqual(ctx["parameter"], {"name": "email", "location": "json_body", "observed_type": "string"})
        self.assertEqual(ctx["technology_context"]["endpoint_role"], "authentication")

    def test_finding_with_no_known_rule_hint_has_no_endpoint_or_parameter(self):
        ctx = build_context(header_finding())
        self.assertNotIn("endpoint", ctx)
        self.assertNotIn("parameter", ctx)
        self.assertNotIn("technology_context", ctx)
        self.assertEqual(ctx["candidate"]["finding_id"], "F-hdr1")
        self.assertNotIn("weakness_type", ctx["candidate"])   # unknown rule -> not invented

    def test_no_observation_ids_means_no_candidate_observation_ids_key(self):
        ctx = build_context(login_sqli_finding())
        self.assertNotIn("observation_ids", ctx["candidate"])


class ContextBuilderWithStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.scope = scope_for()
        self.run_id = self.store.start_run(self.scope)

    def tearDown(self):
        self.store.db.close()
        os.unlink(self.tmp.name)

    def _tool_call(self):
        return self.store.record_tool_call(self.run_id, "http_head", {}, {"ok": True, "untrusted_output": "x"})

    def test_baseline_populated_only_from_referenced_observations(self):
        call_id = self._tool_call()
        status_obs = self.store.add_observation(self.run_id, call_id, "localhost:5000/rest/products/search?q",
                                                 "http_status", "status", "401")
        ct_obs = self.store.add_observation(self.run_id, call_id, "localhost:5000/rest/products/search?q",
                                            "http_header", "content-type", "application/json; charset=utf-8")
        finding = sqli_finding(evidence_observation_ids=[status_obs, ct_obs])
        ctx = ContextBuilder(store=self.store).build(finding)
        self.assertEqual(ctx["baseline"]["status_code"], 401)
        self.assertEqual(ctx["baseline"]["response_content_type"], "application/json; charset=utf-8")
        self.assertNotIn("response_length", ctx["baseline"])       # never observed -> never invented

    def test_unreferenced_observations_are_not_pulled_in(self):
        call_id = self._tool_call()
        self.store.add_observation(self.run_id, call_id, "localhost:5000/rest/products/search?q",
                                   "http_status", "status", "200")
        finding = sqli_finding(evidence_observation_ids=[])  # evidence references nothing
        ctx = ContextBuilder(store=self.store).build(finding)
        self.assertNotIn("baseline", ctx)

    def test_content_type_lookup_feeds_interface_type(self):
        call_id = self._tool_call()
        self.store.add_observation(self.run_id, call_id, "localhost:5000", "http_header",
                                   "content-type", "application/json; charset=utf-8")
        ctx = ContextBuilder(store=self.store).build(login_sqli_finding())
        self.assertEqual(ctx["endpoint"]["content_type"], "application/json; charset=utf-8")
        self.assertEqual(ctx["technology_context"]["interface_type"], "JSON API")


class RegistryTests(unittest.TestCase):
    def test_shipped_sources_load_and_are_minimal(self):
        reg = SuggestionSourceRegistry(REPO_SOURCES_DIR)
        self.assertIn("sql_injection", reg.categories())
        self.assertIn("reflected_input", reg.categories())
        for cat in reg.categories():
            self.assertLessEqual(len(reg.get(cat)["example_patterns"]), 3)

    def test_unknown_category_returns_none_not_error(self):
        reg = SuggestionSourceRegistry(REPO_SOURCES_DIR)
        self.assertIsNone(reg.get("path_traversal"))

    def test_guidance_for_unknown_category_is_explicit_about_unavailability(self):
        reg = SuggestionSourceRegistry(REPO_SOURCES_DIR)
        g = reg.guidance_for("path_traversal")
        self.assertEqual(g, {"category": "path_traversal", "available": False})

    def test_guidance_for_known_category_includes_description_and_examples(self):
        reg = SuggestionSourceRegistry(REPO_SOURCES_DIR)
        g = reg.guidance_for("sql_injection")
        self.assertTrue(g["available"])
        self.assertIn("description", g)
        self.assertIn("example_patterns", g)

    def test_missing_directory_yields_empty_registry(self):
        reg = SuggestionSourceRegistry("/nonexistent/path/for/sure")
        self.assertEqual(reg.categories(), [])

    def test_rejects_file_with_unexpected_keys(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bad.json"), "w") as f:
                json.dump({"category": "x", "description": "d", "consider": [], "references": [],
                          "example_patterns": [], "extra_field": "nope"}, f)
            with self.assertRaises(SuggestionSourceError):
                SuggestionSourceRegistry(d)

    def test_rejects_oversized_payload_library(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bad.json"), "w") as f:
                json.dump({"category": "x", "description": "d", "consider": [], "references": [],
                          "example_patterns": ["a", "b", "c", "d"]}, f)   # one over the limit
            with self.assertRaises(SuggestionSourceError):
                SuggestionSourceRegistry(d)

    def test_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bad.json"), "w") as f:
                f.write("{not json")
            with self.assertRaises(SuggestionSourceError):
                SuggestionSourceRegistry(d)


GOOD_STRATEGY = {
    "strategies": [{
        "hypothesis_id": "H-abc123",
        "objective": "Determine whether the search parameter influences SQL query logic.",
        "test_category": "sql_injection",
        "target_parameter": "/rest/products/search#q",
        "parameter_context": "GET query string parameter, observed as a string.",
        "baseline_requirement": "Record status code and response length for the unmodified query first.",
        "comparison_method": "Compare a quote-breaking value and a true/false boolean pair against the baseline.",
        "expected_signal": "A response-shape difference between the true-like and false-like cases.",
        "negative_control": "A syntactically valid value that should behave like the baseline.",
        "interpretation_notes": "A shape difference is a candidate signal, not confirmed exploitation.",
        "confidence": "low",
        "suggestion_sources": ["sql_injection"],
    }]
}


class StrategyParseTests(unittest.TestCase):
    def test_valid_strategy_parses(self):
        parsed = parse_test_strategy(GOOD_STRATEGY)
        self.assertEqual(len(parsed["strategies"]), 1)

    def test_valid_strategy_parses_from_json_string(self):
        parsed = parse_test_strategy(json.dumps(GOOD_STRATEGY))
        self.assertEqual(len(parsed["strategies"]), 1)

    def test_wrong_root_keys_rejected(self):
        with self.assertRaises(TestStrategyError):
            parse_test_strategy({"hypotheses": []})

    def test_extra_field_rejected(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["tool"] = "sqli_probe"
        with self.assertRaises(TestStrategyError):
            parse_test_strategy(bad)

    def test_bad_test_category_rejected(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["test_category"] = "rce"
        with self.assertRaises(TestStrategyError):
            parse_test_strategy(bad)

    def test_bad_confidence_rejected(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["confidence"] = "certain"
        with self.assertRaises(TestStrategyError):
            parse_test_strategy(bad)

    def test_empty_target_parameter_rejected(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["target_parameter"] = ""
        with self.assertRaises(TestStrategyError):
            parse_test_strategy(bad)


class StrategyValidateTests(unittest.TestCase):
    def test_valid_strategy_is_accepted_and_normalized(self):
        strategies = validate_test_strategy(GOOD_STRATEGY, scope_for(), {"H-abc123"},
                                            SuggestionSourceRegistry(REPO_SOURCES_DIR))
        self.assertEqual(len(strategies), 1)
        self.assertTrue(strategies[0].id.startswith("TS-"))
        self.assertEqual(strategies[0].target_parameter, "/rest/products/search#q")

    def test_out_of_scope_target_rejected(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["target_parameter"] = "/admin#x"
        with self.assertRaises(TestStrategyError):
            validate_test_strategy(bad, scope_for(), {"H-abc123"})

    def test_unknown_hypothesis_id_rejected_when_refs_supplied(self):
        with self.assertRaises(TestStrategyError):
            validate_test_strategy(GOOD_STRATEGY, scope_for(), {"H-different"})

    def test_missing_hash_separator_rejected(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["target_parameter"] = "/rest/products/search"
        with self.assertRaises(TestStrategyError):
            validate_test_strategy(bad, scope_for(), {"H-abc123"})

    def test_unknown_suggestion_source_rejected_when_registry_supplied(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["suggestion_sources"] = ["path_traversal"]
        with self.assertRaises(TestStrategyError):
            validate_test_strategy(bad, scope_for(), {"H-abc123"}, SuggestionSourceRegistry(REPO_SOURCES_DIR))

    def test_no_registry_supplied_skips_suggestion_source_check(self):
        bad = json.loads(json.dumps(GOOD_STRATEGY))
        bad["strategies"][0]["suggestion_sources"] = ["path_traversal"]
        strategies = validate_test_strategy(bad, scope_for(), {"H-abc123"})   # registry=None
        self.assertEqual(strategies[0].suggestion_sources, ["path_traversal"])

    def test_empty_evidence_refs_allows_any_hypothesis_id(self):
        strategies = validate_test_strategy(GOOD_STRATEGY, scope_for(), ())
        self.assertEqual(len(strategies), 1)

    def test_schema_matches_required_fields(self):
        schema = test_strategy_schema()
        required = schema["properties"]["strategies"]["items"]["required"]
        self.assertIn("target_parameter", required)
        self.assertIn("confidence", required)
        self.assertEqual(schema["properties"]["strategies"]["items"]["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
