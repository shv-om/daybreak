import os, tempfile, threading, unittest
from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.policy import PolicyGateway, ToolSpec
from test_discovery import scope_for

PORT = 8123
ARGS = {"host": "127.0.0.1", "port": PORT}


class Clock:
    t = 1000.0
    def __call__(self): return self.t


def build(intrusive=True, ttl=900):
    runs = []
    probe = ToolSpec("probe", False, {"host": (str, None), "port": (int, None)}, 5, 5.0, 1000,
                     lambda timeout, host, port: runs.append((host, port)) or "synthetic probe result")
    sc = scope_for(PORT, allowed_tools=["probe"], intrusive_allowed=intrusive)
    clock, tmp = Clock(), tempfile.mkdtemp()
    ap = ApprovalStore(os.path.join(tmp, "ap.db"), ttl_s=ttl, clock=clock)
    gw = PolicyGateway(sc, {"probe": probe}, AuditLog(os.path.join(tmp, "a.jsonl")), approvals=ap)
    return gw, ap, runs, clock


class ApprovalTests(unittest.TestCase):
    def test_scope_flag_off_denies_and_creates_no_request(self):
        gw, ap, runs, _ = build(intrusive=False)
        r = gw.execute("probe", ARGS)
        self.assertEqual(r["error"], "intrusive tools disabled by scope")
        self.assertEqual((ap.pending(), runs), ([], []))

    def test_request_then_human_approval_then_single_use(self):
        gw, ap, runs, _ = build()
        r = gw.execute("probe", ARGS)
        self.assertEqual(r["error"], "approval required")
        rid = r["approval_request_id"]
        self.assertEqual(gw.execute("probe", ARGS)["approval_request_id"], rid)   # idempotent
        self.assertEqual(len(ap.pending()), 1)
        self.assertTrue(ap.decide(rid, True, "alice"))
        self.assertTrue(gw.execute("probe", ARGS)["ok"])
        self.assertEqual(runs, [("127.0.0.1", PORT)])
        again = gw.execute("probe", ARGS)                       # approval was consumed
        self.assertFalse(again["ok"]); self.assertIn("approval_request_id", again)

    def test_invalid_or_out_of_scope_actions_never_reach_a_human(self):
        gw, ap, runs, _ = build()
        for args in ({"host": "8.8.8.8", "port": PORT}, {"host": "127.0.0.1", "port": 22}, {"host": "127.0.0.1"}, {"host": 1, "port": PORT}):
            self.assertFalse(gw.execute("probe", args)["ok"])
        self.assertEqual((ap.pending(), runs), ([], []))

    def test_approval_is_bound_to_exact_args(self):
        gw, ap, runs, _ = build()
        rid = gw.execute("probe", ARGS)["approval_request_id"]
        ap.decide(rid, True, "alice")
        other = gw.execute("probe", {"host": "localhost", "port": PORT})
        self.assertFalse(other["ok"])
        self.assertEqual(runs, [])

    def test_expiry_and_denial(self):
        gw, ap, runs, clock = build(ttl=60)
        rid = gw.execute("probe", ARGS)["approval_request_id"]
        ap.decide(rid, True, "alice")
        clock.t += 61
        self.assertFalse(gw.execute("probe", ARGS)["ok"])
        rid2 = gw.execute("probe", ARGS)["approval_request_id"]
        ap.decide(rid2, False, "alice")
        self.assertFalse(gw.execute("probe", ARGS)["ok"])
        self.assertEqual(runs, [])

    def test_failed_handler_does_not_burn_the_approval(self):
        """Regression: found 2026-10-25 during an end-to-end run where the target was briefly down -
        the approval was previously consumed before the handler ran, so a transient failure silently
        burned a one-time human approval. The next attempt should still use the SAME approval id."""
        runs = []
        def flaky(timeout, host, port):
            runs.append(1)
            if len(runs) == 1:
                raise ConnectionRefusedError()
            return "synthetic probe result"
        probe = ToolSpec("probe", False, {"host": (str, None), "port": (int, None)}, 5, 5.0, 1000, flaky)
        sc = scope_for(PORT, allowed_tools=["probe"], intrusive_allowed=True)
        tmp = tempfile.mkdtemp()
        ap = ApprovalStore(os.path.join(tmp, "ap.db"))
        gw = PolicyGateway(sc, {"probe": probe}, AuditLog(os.path.join(tmp, "a.jsonl")), approvals=ap)
        rid = gw.execute("probe", ARGS)["approval_request_id"]
        ap.decide(rid, True, "alice")
        r1 = gw.execute("probe", ARGS)
        self.assertFalse(r1["ok"])
        self.assertEqual(r1.get("approval_id"), rid)              # handler failed, approval still intact
        r2 = gw.execute("probe", ARGS)                             # retry with NO new approval step
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["approval_id"], rid)
        r3 = gw.execute("probe", ARGS)                             # now it IS used up
        self.assertFalse(r3["ok"])
        self.assertNotEqual(r3.get("approval_request_id"), rid)

    def test_same_approval_cannot_execute_twice_concurrently(self):
        """Two gateway instances sharing one approval DB must not both execute one approval."""
        tmp = tempfile.mkdtemp()
        ap_path = os.path.join(tmp, "ap.db")
        ap1, ap2 = ApprovalStore(ap_path), ApprovalStore(ap_path)
        sc = scope_for(PORT, allowed_tools=["probe"], intrusive_allowed=True)
        started, release = threading.Event(), threading.Event()
        runs = []

        def slow(timeout, host, port):
            runs.append((host, port))
            started.set()
            release.wait(2)
            return "synthetic probe result"

        probe = ToolSpec("probe", False, {"host": (str, None), "port": (int, None)}, 5, 5.0, 1000, slow)
        gw1 = PolicyGateway(sc, {"probe": probe}, AuditLog(os.path.join(tmp, "a1.jsonl")), approvals=ap1)
        gw2 = PolicyGateway(sc, {"probe": probe}, AuditLog(os.path.join(tmp, "a2.jsonl")), approvals=ap2)

        rid = gw1.execute("probe", ARGS)["approval_request_id"]
        self.assertTrue(ap1.decide(rid, True, "alice"))
        first = {}

        def execute_first():
            first.update(gw1.execute("probe", ARGS))

        t = threading.Thread(target=execute_first)
        t.start()
        self.assertTrue(started.wait(1))
        second = gw2.execute("probe", ARGS)
        release.set()
        t.join(2)

        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertEqual(len(runs), 1)

    def test_decide_only_works_on_pending(self):
        gw, ap, _, _ = build()
        rid = gw.execute("probe", ARGS)["approval_request_id"]
        self.assertTrue(ap.decide(rid, False, "a"))
        self.assertFalse(ap.decide(rid, True, "a"))     # a denial cannot be flipped silently

    def test_emergency_stop_beats_approval_and_audit_records_it(self):
        gw, ap, runs, _ = build()
        rid = gw.execute("probe", ARGS)["approval_request_id"]
        ap.decide(rid, True, "alice")
        gw.emergency_stop()
        self.assertFalse(gw.execute("probe", ARGS)["ok"])
        self.assertEqual(runs, [])
        self.assertTrue(AuditLog.verify(gw.audit.path))

    def test_model_cannot_self_approve(self):
        gw, _, _, _ = build()
        with self.assertRaises(TypeError):
            gw.execute("probe", ARGS, approved=True)


if __name__ == "__main__":
    unittest.main()
