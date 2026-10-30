import os, tempfile, unittest
from pagent.evidence import build_evidence
from pagent.scope import Scope
from pagent.store import Store


def scope_for():
    return Scope.from_dict({"engagement_id": "T", "authorized_by": "x", "valid_from": "2026-01-01T00:00:00+00:00",
                            "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"],
                            "allowed_cidrs": [], "excluded_hosts": [], "allowed_ports": [5000],
                            "allowed_tools": [], "intrusive_allowed": False})


class StoreRawOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.run_id = self.store.start_run(scope_for())

    def tearDown(self):
        self.store.db.close()
        os.unlink(self.tmp.name)

    def test_raw_output_round_trips_exactly(self):
        body = "status=200\ncontent-type=text/html\n\n<html>hello \x00 world</html>"
        cid = self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/"},
                                          {"ok": True, "untrusted_output": body})
        self.assertEqual(self.store.raw_output_for_call(cid), body)   # exact, unsanitized - sanitization is evidence.py's job

    def test_raw_output_none_for_denied_call(self):
        cid = self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/x"},
                                          {"ok": False, "error": "scope: nope"})
        self.assertIsNone(self.store.raw_output_for_call(cid))

    def test_raw_output_none_for_unknown_call_id(self):
        self.assertIsNone(self.store.raw_output_for_call(99999))

    def test_tool_call_rows_shape(self):
        cid = self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/"},
                                          {"ok": True, "untrusted_output": "status=200"})
        rows = self.store.tool_call_rows(self.run_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], cid)
        self.assertEqual(rows[0]["args"], {"host": "localhost", "port": 5000, "path": "/"})
        self.assertIs(rows[0]["allowed"], True)
        self.assertNotIn("args_json", rows[0])
        self.assertNotIn("raw_output_untrusted", rows[0])   # body is a separate, explicit fetch

    def test_tool_call_rows_asset_prefix_filters(self):
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/a"},
                                    {"ok": True, "untrusted_output": "x"})
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/b"},
                                    {"ok": True, "untrusted_output": "y"})
        rows = self.store.tool_call_rows(self.run_id, asset_prefix="localhost:5000/a")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["args"]["path"], "/a")

    def test_old_tuple_shaped_tool_calls_method_unaffected(self):
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/"},
                                    {"ok": True, "untrusted_output": "x"})
        row = self.store.tool_calls(self.run_id)[0]
        self.assertEqual(row[2], 1)   # allowed, by old tuple index - must not have shifted


class BuildEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.run_id = self.store.start_run(scope_for())

    def tearDown(self):
        self.store.db.close()
        os.unlink(self.tmp.name)

    def test_allowed_call_gets_sanitized_excerpt(self):
        body = "status=200\n\nhi \x01 there"
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/"},
                                    {"ok": True, "untrusted_output": body})
        entries = build_evidence(self.store, self.run_id)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["source"], "untrusted_target_response")
        self.assertTrue(e["allowed"])
        self.assertNotIn("\x01", e["output_excerpt"])
        self.assertIn("?", e["output_excerpt"])   # unsafe control chars replaced with '?'
        self.assertFalse(e["output_truncated"])

    def test_newlines_and_non_ascii_text_survive_sanitization(self):
        body = "status=200\ncontent-type=text/html\n\n<html>caf\u00e9 \u2014 line two</html>"
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/"},
                                    {"ok": True, "untrusted_output": body})
        entries = build_evidence(self.store, self.run_id)
        self.assertEqual(entries[0]["output_excerpt"], body)   # unchanged: no control chars present

    def test_denied_call_has_no_excerpt_but_is_included(self):
        self.store.record_tool_call(self.run_id, "sqli_probe", {"host": "localhost", "port": 5000, "path": "/x", "param": "q"},
                                    {"ok": False, "error": "approval required"})
        entries = build_evidence(self.store, self.run_id)
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["allowed"])
        self.assertIsNone(entries[0]["output_excerpt"])
        self.assertEqual(entries[0]["reason"], "approval required")

    def test_body_truncated_at_max_body_chars(self):
        body = "status=200\n\n" + ("A" * 5000)
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/"},
                                    {"ok": True, "untrusted_output": body})
        entries = build_evidence(self.store, self.run_id, max_body_chars=50)
        self.assertEqual(len(entries[0]["output_excerpt"]), 50)
        self.assertTrue(entries[0]["output_truncated"])

    def test_max_calls_caps_and_orders_most_recent_first(self):
        ids = []
        for i in range(5):
            cid = self.store.record_tool_call(self.run_id, "http_get",
                                              {"host": "localhost", "port": 5000, "path": f"/{i}"},
                                              {"ok": True, "untrusted_output": f"status=200 n={i}"})
            ids.append(cid)
        entries = build_evidence(self.store, self.run_id, max_calls=2)
        self.assertEqual(len(entries), 2)
        self.assertEqual([e["tool_call_id"] for e in entries], list(reversed(ids))[:2])

    def test_asset_prefix_passthrough(self):
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/a"},
                                    {"ok": True, "untrusted_output": "x"})
        self.store.record_tool_call(self.run_id, "http_get", {"host": "localhost", "port": 5000, "path": "/b"},
                                    {"ok": True, "untrusted_output": "y"})
        entries = build_evidence(self.store, self.run_id, asset_prefix="localhost:5000/a")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["args"]["path"], "/a")

    def test_empty_run_returns_empty_list(self):
        self.assertEqual(build_evidence(self.store, self.run_id), [])


if __name__ == "__main__":
    unittest.main()
