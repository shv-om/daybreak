import json, os, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from pagent.audit import AuditLog
from pagent.discover import run_content_discovery
from pagent.parse import parse_dir_probe
from pagent.policy import PolicyGateway
from pagent.rules import candidates_from_discovery
from pagent.scope import Scope, ScopeError
from pagent.store import Store
from pagent.tools.dir_probe import make_dir_probe
from pagent.wordlist import MAX_ENTRIES, WordlistError, load_wordlist

REPO_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "config", "content_discovery_wordlist.json")


def scope_for(port, **over):
    d = {"engagement_id": "T", "authorized_by": "SYNTHETIC TEST", "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": [], "allowed_cidrs": ["127.0.0.1/32"],
         "excluded_hosts": [], "allowed_ports": [port], "allowed_tools": ["dir_probe"], "intrusive_allowed": False,
         "discovery_prefixes": ["/"]}
    d.update(over)
    return Scope.from_dict(d)


def write_wordlist(d, entries):
    path = os.path.join(d, "wl.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f)
    return path


class WordlistTests(unittest.TestCase):
    def test_shipped_wordlist_loads_and_is_small(self):
        wl = load_wordlist(REPO_WORDLIST)
        self.assertGreater(len(wl), 0)
        self.assertLessEqual(len(wl), MAX_ENTRIES)
        self.assertIn(".git", wl)

    def test_rejects_non_list(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_wordlist(d, {"not": "a list"})
            with self.assertRaises(WordlistError):
                load_wordlist(path)

    def test_rejects_oversized_wordlist(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_wordlist(d, [f"seg{i}" for i in range(MAX_ENTRIES + 1)])
            with self.assertRaises(WordlistError):
                load_wordlist(path)

    def test_rejects_path_traversal_entry(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_wordlist(d, ["../../etc/passwd"])
            with self.assertRaises(WordlistError):
                load_wordlist(path)

    def test_rejects_entry_with_slash(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_wordlist(d, ["admin/backup"])
            with self.assertRaises(WordlistError):
                load_wordlist(path)

    def test_dotfile_entries_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_wordlist(d, [".env", ".git"])
            self.assertEqual(load_wordlist(path), (".env", ".git"))

    def test_duplicates_deduplicated_preserving_order(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_wordlist(d, ["admin", "backup", "admin"])
            self.assertEqual(load_wordlist(path), ("admin", "backup"))

    def test_malformed_json_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w") as f:
                f.write("{not json")
            with self.assertRaises(WordlistError):
                load_wordlist(path)


class ScopeTests(unittest.TestCase):
    def test_discovery_prefixes_must_start_and_end_with_slash(self):
        with self.assertRaises(ScopeError):
            scope_for(8000, discovery_prefixes=["rest"])
        with self.assertRaises(ScopeError):
            scope_for(8000, discovery_prefixes=["/rest"])

    def test_check_discovery_path_is_prefix_based(self):
        sc = scope_for(8000, discovery_prefixes=["/", "/rest/"])
        self.assertTrue(sc.check_discovery_path("/admin"))
        self.assertTrue(sc.check_discovery_path("/rest/admin"))

    def test_check_discovery_path_denies_outside_prefix(self):
        sc = scope_for(8000, discovery_prefixes=["/rest/"])
        self.assertFalse(sc.check_discovery_path("/admin"))
        self.assertFalse(sc.check_discovery_path("/"))


class ParseDirProbeTests(unittest.TestCase):
    def test_parses_status_content_type_length(self):
        p = parse_dir_probe("status=200\ncontent-type=text/html\ncontent-length=42")
        self.assertEqual(p, {"status": 200, "content_type": "text/html", "content_length": 42})

    def test_missing_fields_are_none_or_empty(self):
        p = parse_dir_probe("status=404")
        self.assertEqual(p["content_type"], "")
        self.assertIsNone(p["content_length"])


class ToolGatingTests(unittest.TestCase):
    def test_path_outside_discovery_prefixes_denied(self):
        sc = scope_for(8123, discovery_prefixes=["/rest/"])
        spec = make_dir_probe(sc, transport=lambda h, p, path, t: (200, "text/html", 10))
        with self.assertRaises(PermissionError):
            spec.handler(host="localhost", port=8123, path="/admin", timeout=5)

    def test_path_under_prefix_allowed(self):
        sc = scope_for(8123, discovery_prefixes=["/"])
        spec = make_dir_probe(sc, transport=lambda h, p, path, t: (200, "text/html", 10))
        out = spec.handler(host="localhost", port=8123, path="/admin", timeout=5)
        self.assertIn("status=200", out)

    def test_read_only_tier_no_approval_needed(self):
        sc = scope_for(8123)
        tmp = tempfile.mkdtemp()
        gw = PolicyGateway(sc, {"dir_probe": make_dir_probe(sc, transport=lambda h, p, path, t: (404, "", 0))},
                           AuditLog(os.path.join(tmp, "a.jsonl")))
        r = gw.execute("dir_probe", {"host": "127.0.0.1", "port": 8123, "path": "/admin"})
        self.assertTrue(r["ok"])   # no approval required, unlike intrusive tools

    def test_gateway_denies_path_outside_prefix_before_reaching_handler(self):
        sc = scope_for(8123, discovery_prefixes=["/rest/"])
        tmp = tempfile.mkdtemp()
        gw = PolicyGateway(sc, {"dir_probe": make_dir_probe(sc)}, AuditLog(os.path.join(tmp, "a.jsonl")))
        r = gw.execute("dir_probe", {"host": "localhost", "port": 8123, "path": "/admin"})
        self.assertFalse(r["ok"])
        self.assertIn("discovery_prefixes", r["error"])


class OrchestratorCapTests(unittest.TestCase):
    def test_refuses_to_start_over_the_hard_cap(self):
        sc = scope_for(8123, discovery_prefixes=["/", "/rest/", "/api/", "/admin/", "/old/"])
        with tempfile.TemporaryDirectory() as d:
            wl_path = write_wordlist(d, [f"seg{i}" for i in range(50)])   # 5 prefixes x 50 entries x 1 target = 250 > 200
            tmp = tempfile.mkdtemp()
            gw = PolicyGateway(sc, {"dir_probe": make_dir_probe(sc)}, AuditLog(os.path.join(tmp, "a.jsonl")))
            store = Store(":memory:")
            with self.assertRaises(ValueError):
                run_content_discovery(gw, store, sc, wordlist_path=wl_path)


class IntegrationTest(unittest.TestCase):
    def test_against_real_server_records_hits_and_skips_404s(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/admin":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html>admin</html>")
                elif self.path == "/.git":
                    self.send_response(403)
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            sc = scope_for(port, discovery_prefixes=["/"])
            tmp = tempfile.mkdtemp()
            audit = AuditLog(os.path.join(tmp, "a.jsonl"))
            gw = PolicyGateway(sc, {"dir_probe": make_dir_probe(sc)}, audit)
            store = Store(":memory:")

            with tempfile.TemporaryDirectory() as d:
                wl_path = write_wordlist(d, ["admin", ".git", "backup"])
                summary = run_content_discovery(gw, store, sc, wordlist_path=wl_path)
            self.assertEqual(summary["calls_allowed"], 3)
            self.assertEqual(summary["calls_denied"], 0)

            findings = candidates_from_discovery(store, summary["run_id"])
            by_asset = {f.asset: f for f in findings}
            self.assertIn(f"127.0.0.1:{port}/admin", by_asset)
            self.assertIn(f"127.0.0.1:{port}/.git", by_asset)
            self.assertNotIn(f"127.0.0.1:{port}/backup", by_asset)   # 404 -> no finding
            self.assertEqual(by_asset[f"127.0.0.1:{port}/admin"].status, "candidate")
            self.assertIn("200", by_asset[f"127.0.0.1:{port}/admin"].title)
            self.assertIn("403", by_asset[f"127.0.0.1:{port}/.git"].title)
            self.assertTrue(AuditLog.verify(audit.path))
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
