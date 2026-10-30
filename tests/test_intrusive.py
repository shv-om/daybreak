import os, tempfile, unittest
from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.intrusive import reflect_finding, sqli_finding
from pagent.parse import make_xss_marker, parse_reflect_probe, parse_sqli_probe, reflection_signal
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.tools.reflect_probe import make_reflect_probe
from pagent.tools.sqli_probe import BASELINE, BREAK, ESCAPE, classify, make_sqli_probe

TARGET = {"path": "/rest/products/search", "param": "q"}


def scope_for(port, probe_targets=(TARGET,), intrusive=True):
    d = {"engagement_id": "T", "authorized_by": "SYNTHETIC TEST", "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"], "allowed_cidrs": [],
         "excluded_hosts": [], "allowed_ports": [port], "allowed_tools": ["reflect_probe", "sqli_probe"],
         "intrusive_allowed": intrusive, "allowed_probe_targets": list(probe_targets)}
    return Scope.from_dict(d)


class ReflectionSignalTests(unittest.TestCase):
    def test_raw_escaped_absent(self):
        value, needle = make_xss_marker("tok1")
        self.assertEqual(reflection_signal(f"echo: {value}", "tok1"), "raw")
        self.assertEqual(reflection_signal(f"echo: pagentmktok1&lt;pagentmk&gt;", "tok1"), "escaped")
        self.assertEqual(reflection_signal("nothing", "tok1"), "absent")


class SqliClassifyTests(unittest.TestCase):
    def test_classic_boolean_pattern(self):
        self.assertEqual(classify((200, 500), (500, 50), (200, 500)), "signal")

    def test_no_signal_cases(self):
        self.assertEqual(classify((200, 500), (200, 500), (200, 500)), "no_signal")        # nothing differs
        self.assertEqual(classify((200, 500), (500, 10), (500, 10)), "no_signal")          # escape also broke


class ToolGatingTests(unittest.TestCase):
    def test_not_in_allowed_probe_targets_fails_closed(self):
        sc = scope_for(8123, probe_targets=())
        spec = make_reflect_probe(sc, lambda h, p, path, param, v, t: (200, "x"))
        with self.assertRaises(PermissionError):
            spec.handler(host="localhost", port=8123, path="/rest/products/search", param="q", timeout=5)

    def test_wrong_param_on_right_path_still_denied(self):
        sc = scope_for(8123)
        spec = make_sqli_probe(sc, lambda h, p, path, param, v, t: (200, 10))
        with self.assertRaises(PermissionError):
            spec.handler(host="localhost", port=8123, path="/rest/products/search", param="other", timeout=5)


class GatewayRequiresApprovalTests(unittest.TestCase):
    def build(self):
        sc = scope_for(8123)
        tmp = tempfile.mkdtemp()
        ap = ApprovalStore(os.path.join(tmp, "a.db"))
        transport = lambda h, p, path, param, v, t: (200, f"echo:{v}")
        gw = PolicyGateway(sc, {"reflect_probe": make_reflect_probe(sc, transport)},
                           AuditLog(os.path.join(tmp, "au.jsonl")), approvals=ap)
        return gw, ap

    def test_blocked_without_approval_then_runs_after(self):
        gw, ap = self.build()
        args = {"host": "localhost", "port": 8123, "path": "/rest/products/search", "param": "q"}
        r1 = gw.execute("reflect_probe", args)
        self.assertFalse(r1["ok"])
        ap.decide(r1["approval_request_id"], True, "alice")
        r2 = gw.execute("reflect_probe", args)
        self.assertTrue(r2["ok"])
        self.assertIn("signal=raw", r2["untrusted_output"])

    def test_out_of_target_requests_never_prompt_for_approval(self):
        gw, ap = self.build()
        r = gw.execute("reflect_probe", {"host": "localhost", "port": 8123, "path": "/other", "param": "q"})
        self.assertFalse(r["ok"]); self.assertNotIn("approval_request_id", r)
        self.assertEqual(ap.pending(), [])


class FindingShapeTests(unittest.TestCase):
    def test_reflect_finding_status_follows_signal(self):
        f_raw = reflect_finding(1, "h", "localhost:5000", "/rest/products/search", "q",
                                "status=200\ntoken=abc\nsignal=raw")
        f_none = reflect_finding(1, "h", "localhost:5000", "/rest/products/search", "q",
                                 "status=200\ntoken=abc\nsignal=escaped")
        self.assertEqual(f_raw.status, "candidate")
        self.assertEqual(f_none.status, "informational")
        self.assertTrue(any("not a browser" in l for l in f_raw.limitations))

    def test_sqli_finding_status_follows_signal(self):
        f_sig = sqli_finding(1, "h", "localhost:5000", "/rest/products/search", "q",
                             "base_status=200 base_len=10\nbreak_status=500 break_len=3\nescape_status=200 escape_len=10\nsignal=signal")
        f_none = sqli_finding(1, "h", "localhost:5000", "/rest/products/search", "q",
                              "base_status=200 base_len=10\nbreak_status=200 break_len=10\nescape_status=200 escape_len=10\nsignal=no_signal")
        self.assertEqual(f_sig.status, "candidate")
        self.assertEqual(f_none.status, "informational")
        self.assertIn("No login was attempted", " ".join(f_sig.limitations))


if __name__ == "__main__":
    unittest.main()
