import json, os, tempfile, unittest

from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.tools.payload_fuzz import (CONTROL_VALUE, JSON_LOGIN, MAX_PAYLOADS, QUERY_GET,
                                       make_payload_fuzz, valid_payload_batch)

SEARCH = {"path": "/rest/products/search", "param": "q"}
LOGIN = {"path": "/rest/user/login", "param": "email"}


def scope_for(target=SEARCH):
    return Scope.from_dict({
        "engagement_id": "F", "authorized_by": "SYNTHETIC TEST",
        "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2030-01-01T00:00:00+00:00",
        "allowed_hosts": ["localhost"], "allowed_cidrs": [], "excluded_hosts": [], "allowed_ports": [5000],
        "allowed_tools": ["payload_fuzz"], "intrusive_allowed": True, "allowed_probe_targets": [target],
    })


class PayloadValidationTests(unittest.TestCase):
    def test_bounded_payload_batch(self):
        self.assertTrue(valid_payload_batch(["a", "'", "<tag>"]))
        self.assertFalse(valid_payload_batch([]))
        self.assertFalse(valid_payload_batch(["x"] * 2))
        self.assertFalse(valid_payload_batch(["a\r\nb"]))
        self.assertFalse(valid_payload_batch(["x"] * (MAX_PAYLOADS + 1)))
        self.assertFalse(valid_payload_batch(["x" * 257]))


class AdapterTests(unittest.TestCase):
    def test_query_mode_sends_control_then_exact_payloads(self):
        calls = []
        def transport(host, port, path, param, mode, value, timeout):
            calls.append((path, param, mode, value))
            return (200 if value != "boom" else 500, 10 + len(value), "application/json", False)
        spec = make_payload_fuzz(scope_for(), transport=transport, sleeper=lambda _: None)
        out = json.loads(spec.handler(host="localhost", port=5000, path=SEARCH["path"], param="q",
                                      mode=QUERY_GET, payloads=["alpha", "boom"], timeout=1.0))
        self.assertEqual([c[3] for c in calls], [CONTROL_VALUE, "alpha", "boom"])
        self.assertEqual(out["request_count"], 3)
        self.assertEqual(len(out["cases"]), 2)
        self.assertNotIn("alpha", json.dumps(out))
        self.assertTrue(out["cases"][1]["status_changed"])

    def test_login_target_requires_login_mode(self):
        sc = scope_for(LOGIN)
        spec = make_payload_fuzz(sc, transport=lambda *a: (401, 10, "application/json", False), sleeper=lambda _: None)
        ok, _ = spec.cross_check({"path": LOGIN["path"], "param": "email", "mode": JSON_LOGIN})
        bad, why = spec.cross_check({"path": LOGIN["path"], "param": "email", "mode": QUERY_GET})
        self.assertTrue(ok)
        self.assertFalse(bad)
        self.assertIn("request mode", why)

    def test_one_payload_transport_failure_is_recorded_and_batch_continues(self):
        calls = []
        def transport(host, port, path, param, mode, value, timeout):
            calls.append(value)
            if value == "bad":
                raise ConnectionResetError()
            return 200, 20, "text/plain", False
        spec = make_payload_fuzz(scope_for(), transport=transport, sleeper=lambda _: None)
        out = json.loads(spec.handler(host="localhost", port=5000, path=SEARCH["path"], param="q",
                                      mode=QUERY_GET, payloads=["bad", "good"], timeout=1.0))
        self.assertEqual(calls, [CONTROL_VALUE, "bad", "good"])
        self.assertEqual(out["cases"][0]["transport_error"], "ConnectionResetError")
        self.assertEqual(len(out["cases"]), 2)


class ApprovalTests(unittest.TestCase):
    def test_gateway_binds_approval_to_exact_payload_batch(self):
        tmp = tempfile.mkdtemp()
        sc = scope_for()
        spec = make_payload_fuzz(sc, transport=lambda *a: (200, 10, "text/plain", False), sleeper=lambda _: None)
        ap = ApprovalStore(os.path.join(tmp, "approvals.db"))
        gw = PolicyGateway(sc, {"payload_fuzz": spec}, AuditLog(os.path.join(tmp, "audit.jsonl")), approvals=ap)
        args = {"host": "localhost", "port": 5000, "path": SEARCH["path"], "param": "q",
                "mode": QUERY_GET, "payloads": ["one", "two"]}
        first = gw.execute("payload_fuzz", args)
        self.assertFalse(first["ok"])
        self.assertEqual(first["error"], "approval required")
        ap.decide(first["approval_request_id"], True, who="tester")

        changed = dict(args, payloads=["one", "THREE"])
        self.assertFalse(gw.execute("payload_fuzz", changed)["ok"])
        second = gw.execute("payload_fuzz", args)
        self.assertTrue(second["ok"])


if __name__ == "__main__":
    unittest.main()
