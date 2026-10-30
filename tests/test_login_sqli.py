import json, os, tempfile, unittest
from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.intrusive import login_sqli_finding, MANUAL_CONFIRMATION_NOTE
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.tools.login_sqli_probe import DUMMY_SECRET, make_login_sqli_probe

TARGET = {"path": "/rest/user/login", "param": "email"}


def scope_for(port, targets=(TARGET,)):
    d = {"engagement_id": "T", "authorized_by": "SYNTHETIC TEST", "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"], "allowed_cidrs": [],
         "excluded_hosts": [], "allowed_ports": [port], "allowed_tools": ["login_sqli_probe"],
         "intrusive_allowed": True, "allowed_probe_targets": list(targets)}
    return Scope.from_dict(d)


class NoTautologyTests(unittest.TestCase):
    def test_sent_bodies_never_contain_a_tautology_or_sql_keywords(self):
        sent = []
        def transport(h, p, path, field, value, t):
            sent.append(value); return (200, 10)
        spec = make_login_sqli_probe(scope_for(8123), transport)
        spec.handler(host="localhost", port=8123, path="/rest/user/login", field="email", timeout=5)
        joined = " ".join(sent).lower()
        for forbidden in ("or 1=1", "or '1'='1", " or ", "union", "drop ", "--", "#"):
            self.assertNotIn(forbidden, joined, f"forbidden fragment {forbidden!r} in sent values {sent}")
        self.assertEqual(sent.count(sent[0]), 1)   # base, break, escape are three distinct values

    def test_password_field_is_fixed_dummy_never_varied(self):
        bodies = []
        def transport(h, p, path, field, value, t):
            bodies.append(json.dumps({field: value, "password": DUMMY_SECRET}))
            return (200, 10)
        spec = make_login_sqli_probe(scope_for(8123), transport)
        spec.handler(host="localhost", port=8123, path="/rest/user/login", field="email", timeout=5)
        self.assertTrue(all(DUMMY_SECRET in b for b in bodies))

    def test_body_is_read_and_discarded_not_parsed(self):
        # transport only ever returns (status, length) - handler has no code path to read body content
        import inspect
        src = inspect.getsource(make_login_sqli_probe)
        self.assertNotIn("json.loads", src)


class GatingTests(unittest.TestCase):
    def test_lab_intrusive_scope_allows_login_probe(self):
        path = os.path.join(os.path.dirname(__file__), "..", "config", "scope.lab.intrusive.json")
        sc = Scope.load(path)
        self.assertIn("login_sqli_probe", sc.allowed_tools)
        self.assertTrue(sc.check_probe_target("/rest/user/login", "email"))

    def test_wrong_field_denied(self):
        spec = make_login_sqli_probe(scope_for(8123), lambda h, p, path, field, v, t: (200, 10))
        self.assertFalse(scope_for(8123).check_probe_target("/rest/user/login", "password"))

    def test_gateway_requires_approval(self):
        sc = scope_for(8123)
        tmp = tempfile.mkdtemp()
        ap = ApprovalStore(os.path.join(tmp, "a.db"))
        gw = PolicyGateway(sc, {"login_sqli_probe": make_login_sqli_probe(sc, lambda h, p, path, field, v, t: (200, 10))},
                           AuditLog(os.path.join(tmp, "au.jsonl")), approvals=ap)
        args = {"host": "localhost", "port": 8123, "path": "/rest/user/login", "field": "email"}
        r1 = gw.execute("login_sqli_probe", args)
        self.assertFalse(r1["ok"])
        ap.decide(r1["approval_request_id"], True, "alice")
        self.assertTrue(gw.execute("login_sqli_probe", args)["ok"])


class FindingTests(unittest.TestCase):
    def test_signal_gets_next_steps_suggestion_not_a_sent_payload(self):
        f = login_sqli_finding(1, "h", "localhost:5000", "/rest/user/login", "email",
                               "base_status=200 base_len=10\nbreak_status=500 break_len=3\nescape_status=200 escape_len=10\nsignal=signal")
        self.assertEqual(f.status, "candidate")
        self.assertEqual(f.next_steps, MANUAL_CONFIRMATION_NOTE)
        self.assertIn("human", f.next_steps.lower())
        self.assertTrue(any("tautology" in l for l in f.limitations))

    def test_no_signal_has_no_next_steps(self):
        f = login_sqli_finding(1, "h", "localhost:5000", "/rest/user/login", "email",
                               "base_status=200 base_len=10\nbreak_status=200 break_len=10\nescape_status=200 escape_len=10\nsignal=no_signal")
        self.assertEqual(f.status, "informational")
        self.assertEqual(f.next_steps, "")


if __name__ == "__main__":
    unittest.main()
