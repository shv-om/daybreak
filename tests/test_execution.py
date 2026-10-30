import copy, json, os, tempfile, unittest

from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.execution import ProposalExecutionError, resolve_from_file, resolve_tool_call
from pagent.policy import PolicyGateway
from pagent.proposals import validate_contextual_output
from pagent.scope import Scope
from pagent.tools.login_sqli_probe import make_login_sqli_probe
from pagent.tools.reflect_probe import make_reflect_probe
from pagent.tools.sqli_probe import make_sqli_probe

SEARCH_TARGET = {"path": "/rest/products/search", "param": "q"}
LOGIN_TARGET = {"path": "/rest/user/login", "param": "email"}


def scope_for(targets=(SEARCH_TARGET,), tools=("reflect_probe", "sqli_probe", "login_sqli_probe")):
    return Scope.from_dict({
        "engagement_id": "X", "authorized_by": "SYNTHETIC TEST",
        "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2030-01-01T00:00:00+00:00",
        "allowed_hosts": ["localhost"], "allowed_cidrs": [], "excluded_hosts": [], "allowed_ports": [5000],
        "allowed_tools": list(tools), "intrusive_allowed": True, "allowed_probe_targets": list(targets),
    })


def hypothesis_doc(weakness_type, target, category, payload="pagent-test-value"):
    """Builds one proposals-run-shaped {"hypotheses": [...]} dict with real, correctly-derived
    ids, by running it through the same validator a real model's output goes through - so these
    fixtures can never silently drift from what pagent.proposals actually produces."""
    raw = {"hypotheses": [{
        "weakness_type": weakness_type, "path": target["path"], "parameter": target["param"],
        "rationale": "synthetic fixture", "confidence": "low", "evidence_refs": [],
        "payloads": [{"payload": payload, "category": category,
                      "expected_signal": "synthetic", "rationale": "synthetic"}],
    }]}
    hs = validate_contextual_output(raw, scope_for(targets=(target,)), set())
    return {"hypotheses": [h.to_dict() for h in hs]}, hs[0].payloads[0].id


class ResolveTests(unittest.TestCase):
    def test_quote_break_on_query_target_maps_to_sqli_probe(self):
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        resolved = resolve_from_file(doc, pid, scope_for())
        self.assertEqual(resolved.tool, "sqli_probe")
        self.assertEqual(resolved.args, {"host": "localhost", "port": 5000, "path": "/rest/products/search", "param": "q"})

    def test_reflection_categories_map_to_reflect_probe(self):
        for category in ("reflection_marker", "html_context_marker"):
            doc, pid = hypothesis_doc("reflected_input", SEARCH_TARGET, category)
            resolved = resolve_from_file(doc, pid, scope_for())
            self.assertEqual(resolved.tool, "reflect_probe")

    def test_quote_break_on_login_target_maps_to_login_sqli_probe(self):
        doc, pid = hypothesis_doc("sql_injection", LOGIN_TARGET, "quote_break")
        resolved = resolve_from_file(doc, pid, scope_for(targets=(LOGIN_TARGET,)))
        self.assertEqual(resolved.tool, "login_sqli_probe")
        self.assertEqual(resolved.args, {"host": "localhost", "port": 5000, "path": "/rest/user/login", "field": "email"})

    def test_boolean_pair_is_non_executable(self):
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "boolean_pair")
        with self.assertRaises(ProposalExecutionError) as cm:
            resolve_from_file(doc, pid, scope_for())
        self.assertIn("no restricted adapter", str(cm.exception))

    def test_tool_not_in_scope_is_rejected(self):
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        sc = scope_for(tools=("reflect_probe",))   # sqli_probe deliberately missing
        with self.assertRaises(ProposalExecutionError):
            resolve_from_file(doc, pid, sc)

    def test_unknown_payload_id_raises(self):
        doc, _ = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        with self.assertRaises(ProposalExecutionError):
            resolve_from_file(doc, "P-doesnotexist", scope_for())

    def test_out_of_scope_target_at_execution_time_is_rejected(self):
        """Even though hypothesis_doc() only generates a doc against a scope that already allowed
        the target, a second, narrower scope passed at execution time must still be re-checked -
        the scope used to approve generation and the scope used to approve execution are not
        guaranteed to be the same scope file."""
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        narrow = scope_for(targets=())
        with self.assertRaises(ProposalExecutionError):
            resolve_from_file(doc, pid, narrow)


class TamperingTests(unittest.TestCase):
    def test_edited_payload_text_is_rejected(self):
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        doc = copy.deepcopy(doc)
        doc["hypotheses"][0]["payloads"][0]["payload"] = "something else entirely"   # id now stale
        with self.assertRaises(ProposalExecutionError) as cm:
            resolve_from_file(doc, pid, scope_for())
        self.assertIn("does not match its id", str(cm.exception))

    def test_edited_path_is_rejected(self):
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        doc = copy.deepcopy(doc)
        doc["hypotheses"][0]["path"] = "/admin"   # hypothesis id now stale
        with self.assertRaises(ProposalExecutionError) as cm:
            resolve_from_file(doc, pid, scope_for())
        self.assertIn("does not match its id", str(cm.exception))

    def test_execution_state_tampered_to_bypass_approval_is_rejected(self):
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        doc = copy.deepcopy(doc)
        doc["hypotheses"][0]["payloads"][0]["execution_state"] = "executed"
        with self.assertRaises(ProposalExecutionError):
            resolve_tool_call(doc["hypotheses"][0], doc["hypotheses"][0]["payloads"][0], scope_for())


class EndToEndApprovalTests(unittest.TestCase):
    """Confirms a resolved call still has to go through the exact same request -> human approval ->
    single-use-reservation -> execute lifecycle as any other intrusive tool call; this module does
    not grant itself a shortcut around PolicyGateway/ApprovalStore."""

    def _gateway(self):
        tmp = tempfile.mkdtemp()
        sc = scope_for()
        tools = {"sqli_probe": make_sqli_probe(sc, lambda h, p, path, param, v, t: (200, 10)),
                 "reflect_probe": make_reflect_probe(sc, lambda h, p, path, param, v, t: (200, "x")),
                 "login_sqli_probe": make_login_sqli_probe(sc, lambda h, p, path, field, v, t: (200, 10))}
        ap = ApprovalStore(os.path.join(tmp, "ap.db"))
        gw = PolicyGateway(sc, tools, AuditLog(os.path.join(tmp, "a.jsonl")), approvals=ap)
        return sc, gw, ap

    def test_first_call_requests_approval_second_executes(self):
        sc, gw, ap = self._gateway()
        doc, pid = hypothesis_doc("sql_injection", SEARCH_TARGET, "quote_break")
        resolved = resolve_from_file(doc, pid, sc)

        first = gw.execute(resolved.tool, resolved.args)
        self.assertFalse(first["ok"])
        self.assertEqual(first["error"], "approval required")

        ap.decide(first["approval_request_id"], approve=True, who="tester")
        second = gw.execute(resolved.tool, resolved.args)
        self.assertTrue(second["ok"])
        self.assertIn("signal=", second["untrusted_output"])


if __name__ == "__main__":
    unittest.main()
