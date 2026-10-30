import os, tempfile, unittest
from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.parse import parse_fuzz_probe
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.tools.fuzz_probe import SQLI_VARIANTS, XSS_VARIANTS, make_fuzz_probe

TARGET = {"path": "/rest/products/search", "param": "q"}


def scope_for(port, probe_targets=(TARGET,), intrusive=True):
    d = {"engagement_id": "T", "authorized_by": "SYNTHETIC TEST", "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"], "allowed_cidrs": [],
         "excluded_hosts": [], "allowed_ports": [port], "allowed_tools": ["fuzz_probe"],
         "intrusive_allowed": intrusive, "allowed_probe_targets": list(probe_targets)}
    return Scope.from_dict(d)


class ParseFuzzProbeTests(unittest.TestCase):
    def test_sqli_output_parses_into_variants(self):
        out = "baseline_status=200 baseline_len=10\nsingle_quote_status=500 single_quote_len=3 single_quote_differs=yes"
        parsed = parse_fuzz_probe(out)
        self.assertIsNone(parsed["token"])
        self.assertEqual(parsed["variants"]["baseline"], {"status": "200", "len": "10"})
        self.assertEqual(parsed["variants"]["single_quote"]["differs"], "yes")

    def test_reflect_output_parses_token_and_signals(self):
        out = "token=abc123\nangle_bracket_status=200 angle_bracket_signal=raw\ndouble_quote_status=200 double_quote_signal=escaped"
        parsed = parse_fuzz_probe(out)
        self.assertEqual(parsed["token"], "abc123")
        self.assertEqual(parsed["variants"]["angle_bracket"]["signal"], "raw")
        self.assertEqual(parsed["variants"]["double_quote"]["signal"], "escaped")


class ToolGatingTests(unittest.TestCase):
    def test_not_in_allowed_probe_targets_fails_closed(self):
        sc = scope_for(8123, probe_targets=())
        spec = make_fuzz_probe(sc, sqli_transport=lambda h, p, path, param, v, t: (200, 10))
        with self.assertRaises(PermissionError):
            spec.handler(host="localhost", port=8123, path="/rest/products/search", param="q",
                        category="sql_injection", timeout=5)

    def test_wrong_param_on_right_path_still_denied(self):
        sc = scope_for(8123)
        spec = make_fuzz_probe(sc, reflect_transport=lambda h, p, path, param, v, t: (200, f"echo:{v}"))
        with self.assertRaises(PermissionError):
            spec.handler(host="localhost", port=8123, path="/rest/products/search", param="other",
                        category="reflected_input", timeout=5)

    def test_bad_category_rejected_by_arg_schema(self):
        sc = scope_for(8123)
        spec = make_fuzz_probe(sc)
        self.assertFalse(spec.arg_schema["category"][1]("path_traversal"))


class SqliFuzzHandlerTests(unittest.TestCase):
    def test_every_variant_sent_and_baseline_control_included(self):
        sc = scope_for(8123)
        sent = []

        def transport(h, p, path, param, value, t):
            sent.append(value)
            return (500, 3) if value.endswith("'") and not value.endswith("''") else (200, 10)

        spec = make_fuzz_probe(sc, sqli_transport=transport)
        out = spec.handler(host="localhost", port=8123, path="/rest/products/search", param="q",
                           category="sql_injection", timeout=5)
        self.assertEqual(sorted(sent), sorted(v for _, v in SQLI_VARIANTS))
        parsed = parse_fuzz_probe(out)
        self.assertEqual(parsed["variants"]["single_quote"]["differs"], "yes")
        self.assertEqual(parsed["variants"]["double_quote"]["differs"], "no")

    def test_no_actual_tautology_or_destructive_syntax_ever_sent(self):
        sent = []
        sc = scope_for(8123)
        spec = make_fuzz_probe(sc, sqli_transport=lambda h, p, path, param, v, t: (sent.append(v), (200, 1))[1])
        spec.handler(host="localhost", port=8123, path="/rest/products/search", param="q",
                    category="sql_injection", timeout=5)
        for v in sent:
            self.assertNotIn("or 1=1", v.lower())
            self.assertNotIn("drop ", v.lower())
            self.assertNotIn(";", v)


class ReflectFuzzHandlerTests(unittest.TestCase):
    def test_raw_vs_escaped_per_variant(self):
        sc = scope_for(8123)

        def transport(h, p, path, param, value, t):
            # angle-bracket marker reflected raw, quote markers escaped
            if "<>" in value or ("<" in value and ">" in value):
                return 200, f"echo:{value}"
            escaped = value.replace('"', "&quot;").replace("'", "&#x27;")
            return 200, f"echo:{escaped}"

        spec = make_fuzz_probe(sc, reflect_transport=transport)
        out = spec.handler(host="localhost", port=8123, path="/rest/products/search", param="q",
                           category="reflected_input", timeout=5)
        parsed = parse_fuzz_probe(out)
        self.assertEqual(parsed["variants"]["angle_bracket"]["signal"], "raw")
        self.assertEqual(parsed["variants"]["double_quote"]["signal"], "escaped")
        self.assertEqual(parsed["variants"]["single_quote"]["signal"], "escaped")
        self.assertEqual({name for name, _ in XSS_VARIANTS}, set(parsed["variants"]))


class GatewayRequiresApprovalTests(unittest.TestCase):
    def build(self):
        sc = scope_for(8123)
        tmp = tempfile.mkdtemp()
        ap = ApprovalStore(os.path.join(tmp, "a.db"))
        transport = lambda h, p, path, param, v, t: (200, 10)
        gw = PolicyGateway(sc, {"fuzz_probe": make_fuzz_probe(sc, sqli_transport=transport)},
                           AuditLog(os.path.join(tmp, "au.jsonl")), approvals=ap)
        return gw, ap

    def test_blocked_without_approval_then_runs_after(self):
        gw, ap = self.build()
        args = {"host": "localhost", "port": 8123, "path": "/rest/products/search", "param": "q",
               "category": "sql_injection"}
        r1 = gw.execute("fuzz_probe", args)
        self.assertFalse(r1["ok"])
        ap.decide(r1["approval_request_id"], True, "alice")
        r2 = gw.execute("fuzz_probe", args)
        self.assertTrue(r2["ok"])
        self.assertIn("baseline_status=200", r2["untrusted_output"])

    def test_out_of_target_requests_never_prompt_for_approval(self):
        gw, ap = self.build()
        r = gw.execute("fuzz_probe", {"host": "localhost", "port": 8123, "path": "/other", "param": "q",
                                      "category": "sql_injection"})
        self.assertFalse(r["ok"]); self.assertNotIn("approval_request_id", r)
        self.assertEqual(ap.pending(), [])


if __name__ == "__main__":
    unittest.main()
