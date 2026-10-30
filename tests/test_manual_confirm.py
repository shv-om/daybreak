import json, os, tempfile, unittest
from pagent.manual_confirm import ManualConfirmError, apply_manual_action
from pagent.report import finding_markdown, to_markdown, build_report
from pagent.store import Store
from pagent.intrusive import login_sqli_finding
from pagent.scope import Scope


def sample_finding():
    f = login_sqli_finding(1, "deadbeef" * 8, "localhost:5000", "/rest/user/login", "email",
                           "base_status=200 base_len=10\nbreak_status=500 break_len=3\nescape_status=200 escape_len=10\nsignal=signal")
    return f.to_dict()


class ApplyTests(unittest.TestCase):
    def test_requires_all_fields(self):
        f = sample_finding()
        with self.assertRaises(ManualConfirmError):
            apply_manual_action(f, "", "did a thing", "payload", "result")
        with self.assertRaises(ManualConfirmError):
            apply_manual_action(f, "alice", "did a thing", "   ", "result")

    def test_sets_confirmed_and_records_verbatim_payload(self):
        f = sample_finding()
        out = apply_manual_action(f, "alice", "Tried login bypass manually in browser",
                                  "attacker@test.com' OR 1=1--", "Logged in as admin", notes="screenshot saved")
        self.assertEqual(out["status"], "confirmed")
        self.assertEqual(out["confidence"]["level"], "high")
        self.assertEqual(len(out["manual_actions"]), 1)
        a = out["manual_actions"][0]
        self.assertEqual(a["payload_sent"], "attacker@test.com' OR 1=1--")
        self.assertEqual(a["observed_result"], "Logged in as admin")
        self.assertEqual(a["performed_by"], "alice")
        self.assertIn("performed_at", a)
        self.assertNotIn("exploit", out["verification"]["method"])   # sanity: no implication the tool exploited anything
        self.assertIn("not executed, constructed, or sent by this tool", out["verification"]["method"])

    def test_original_finding_dict_not_mutated(self):
        f = sample_finding()
        orig_status = f["status"]
        apply_manual_action(f, "alice", "x", "y", "z")
        self.assertEqual(f["status"], orig_status)
        self.assertEqual(f.get("manual_actions", []), [])

    def test_multiple_manual_actions_accumulate(self):
        f = sample_finding()
        f = apply_manual_action(f, "alice", "first try", "p1", "r1")
        f = apply_manual_action(f, "bob", "second try, independent", "p2", "r2")
        self.assertEqual(len(f["manual_actions"]), 2)
        self.assertEqual(f["verification"]["repeats"], 2)

    def test_sanitizes_control_characters_in_free_text(self):
        f = sample_finding()
        out = apply_manual_action(f, "alice", "x\x00y", "p\x1bq", "r\x07s")
        a = out["manual_actions"][0]
        self.assertNotIn("\x00", a["action_description"])
        self.assertNotIn("\x1b", a["payload_sent"])


class RenderTests(unittest.TestCase):
    def test_finding_markdown_shows_manual_log_block(self):
        f = sample_finding()
        f = apply_manual_action(f, "alice", "Manual bypass attempt", "x' OR 1=1--", "Got admin session")
        md = finding_markdown(f)
        self.assertIn("Manual confirmation log (performed by a human operator, not this tool)", md)
        self.assertIn("x' OR 1=1--", md)
        self.assertIn("by alice", md)

    def test_no_manual_log_section_when_no_actions(self):
        f = sample_finding()
        self.assertNotIn("Manual confirmation log", finding_markdown(f))


class StorePersistenceTests(unittest.TestCase):
    def test_save_and_get_and_list(self):
        store = Store(":memory:")
        d = {"engagement_id": "T", "authorized_by": "SYNTHETIC TEST", "valid_from": "2026-01-01T00:00:00+00:00",
             "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"], "allowed_cidrs": [],
             "excluded_hosts": [], "allowed_ports": [5000], "allowed_tools": ["http_head"]}
        sc = Scope.from_dict(d)
        run_id = store.start_run(sc)
        f1, f2 = sample_finding(), sample_finding()
        f2["id"] = "F-other0000"
        store.save_finding(run_id, f1)
        store.save_finding(run_id, f2)
        got_run, got = store.get_finding(f1["id"])
        self.assertEqual((got_run, got["id"]), (run_id, f1["id"]))
        self.assertEqual(len(store.findings_for_run(run_id)), 2)
        self.assertEqual(store.get_finding("F-does-not-exist"), (None, None))

    def test_save_is_an_upsert(self):
        store = Store(":memory:")
        sc = Scope.from_dict({"engagement_id": "T", "authorized_by": "SYNTHETIC TEST", "valid_from": "2026-01-01T00:00:00+00:00",
                              "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"], "allowed_cidrs": [],
                              "excluded_hosts": [], "allowed_ports": [5000], "allowed_tools": ["http_head"]})
        run_id = store.start_run(sc)
        f = sample_finding()
        store.save_finding(run_id, f)
        f["status"] = "confirmed"
        store.save_finding(run_id, f)
        _, got = store.get_finding(f["id"])
        self.assertEqual(got["status"], "confirmed")
        self.assertEqual(len(store.findings_for_run(run_id)), 1)

    def test_manual_actions_log_roundtrip(self):
        store = Store(":memory:")
        store.add_manual_action("F-x", "alice", "did a thing", "payload!", "result!", "note")
        rows = store.manual_actions_for("F-x")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload_sent"], "payload!")
        self.assertTrue(rows[0]["row_sha256"])


if __name__ == "__main__":
    unittest.main()
