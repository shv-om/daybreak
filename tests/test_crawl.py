import json, os, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from pagent.audit import AuditLog
from pagent.discover import run_crawl
from pagent.parse import extract_js_signals, extract_links, parse_http_get
from pagent.policy import PolicyGateway
from pagent.rules import candidates_from_crawl
from pagent.scope import Scope, ScopeError
from pagent.store import Store
from pagent.tools.http_get import make_http_get

PAGE = """<html><body>
<a href="/rest/products/search?q=test">search</a>
<script src="/static/app.js"></script>
<a href="http://evil.example.com/steal">external, must not be followed</a>
<form action="/rest/user/login"></form>
</body></html>"""

APP_JS = """
fetch("/api/internal/users");
const apiKey = "AKIAABCDEFGHIJKLMNOP";
const token = "sk_live_abcdefghijklmnop1234";
"""


def scope_for(port, **over):
    d = {"engagement_id": "T", "authorized_by": "SYNTHETIC TEST",
         "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2030-01-01T00:00:00+00:00",
         "allowed_hosts": [], "allowed_cidrs": ["127.0.0.1/32"], "excluded_hosts": [],
         "allowed_ports": [port], "allowed_tools": ["http_get"], "intrusive_allowed": False,
         "crawl_seeds": ["/", "/static/app.js"]}
    d.update(over)
    return Scope.from_dict(d)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body, ct = PAGE, "text/html; charset=utf-8"
        elif self.path == "/static/app.js":
            body, ct = APP_JS, "application/javascript"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class ScopeTests(unittest.TestCase):
    def test_crawl_seeds_must_be_paths(self):
        with self.assertRaises(ScopeError):
            scope_for(8000, crawl_seeds=["not-a-path"])

    def test_check_crawl_seed_is_explicit_allowlist(self):
        sc = scope_for(8000)
        self.assertTrue(sc.check_crawl_seed("/"))
        self.assertFalse(sc.check_crawl_seed("/rest/products/search"))   # discovered, not seeded


class ParseUnitTests(unittest.TestCase):
    def test_parse_http_get_splits_head_and_body(self):
        p = parse_http_get("status=200\ncontent-type=text/html\n\n<html>hi</html>")
        self.assertEqual((p["status"], p["content_type"], p["body"]), (200, "text/html", "<html>hi</html>"))

    def test_extract_links_classifies_same_host_script_and_external(self):
        links = extract_links(PAGE, "127.0.0.1", 5000)
        by_path = {l["path"]: l for l in links}
        self.assertEqual(by_path["/rest/products/search"]["params"], ["q"])
        self.assertFalse(by_path["/rest/products/search"]["same_host"] and by_path["/rest/products/search"]["is_script"])
        self.assertTrue(by_path["/static/app.js"]["is_script"])
        self.assertTrue(by_path["/static/app.js"]["same_host"])
        self.assertFalse(by_path["/steal"]["same_host"])   # evil.example.com - must be classified, not dropped silently

    def test_extract_js_signals_finds_endpoint_and_redacts_secret(self):
        sig = extract_js_signals(APP_JS)
        kinds = {k: [v for kk, key, v in sig if kk == k] for k in ("js_endpoint_candidate", "js_secret_candidate")}
        self.assertIn("/api/internal/users", kinds["js_endpoint_candidate"])
        self.assertTrue(kinds["js_secret_candidate"])
        for redacted in kinds["js_secret_candidate"]:
            self.assertIn("...", redacted)
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", redacted)
            self.assertNotIn("sk_live_abcdefghijklmnop1234", redacted)


class CrossCheckTests(unittest.TestCase):
    def test_gateway_denies_a_path_not_in_crawl_seeds(self):
        sc = scope_for(8000)
        tmp = tempfile.mkdtemp()
        gw = PolicyGateway(sc, {"http_get": make_http_get(sc)}, AuditLog(os.path.join(tmp, "a.jsonl")))
        r = gw.execute("http_get", {"host": "127.0.0.1", "port": 8000, "path": "/rest/products/search"})
        self.assertFalse(r["ok"])
        self.assertIn("crawl_seeds", r["error"])


class IntegrationTest(unittest.TestCase):
    def test_crawl_against_real_server_does_not_follow_discovered_links(self):
        srv = HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            sc = scope_for(port)
            tmp = tempfile.mkdtemp()
            audit = AuditLog(os.path.join(tmp, "a.jsonl"))
            gw = PolicyGateway(sc, {"http_get": make_http_get(sc)}, audit)
            store = Store(":memory:")

            summary = run_crawl(gw, store, sc)
            self.assertEqual((summary["calls_allowed"], summary["calls_denied"]), (2, 0))   # exactly the 2 seeds, nothing discovered was fetched

            obs = store.observation_rows(summary["run_id"])
            root_asset = f"127.0.0.1:{port}/"
            self.assertTrue(any(o["kind"] == "discovered_link" and "/rest/products/search" in o["value"] for o in obs if o["asset"] == root_asset))
            self.assertTrue(any(o["kind"] == "discovered_script" and o["value"] == "/static/app.js" for o in obs if o["asset"] == root_asset))
            self.assertTrue(any(o["kind"] == "discovered_param" and o["key"] == "/rest/products/search" and o["value"] == "q" for o in obs))
            self.assertTrue(any(o["kind"] == "external_link" for o in obs if o["asset"] == root_asset))
            js_asset = f"127.0.0.1:{port}/static/app.js"
            self.assertTrue(any(o["kind"] == "js_endpoint_candidate" for o in obs if o["asset"] == js_asset))
            self.assertTrue(any(o["kind"] == "js_secret_candidate" for o in obs if o["asset"] == js_asset))

            findings = candidates_from_crawl(store, summary["run_id"])
            by_rule = {(f.rule_id, f.asset): f for f in findings}
            surface = by_rule[("crawl-discovered-surface", root_asset)]
            self.assertEqual(surface.status, "informational")
            self.assertIn("2 link(s), 1 script(s), 1 parameter(s)", surface.title)   # /rest/products/search and the login form action
            ep = by_rule[("js-endpoint-candidate", js_asset)]
            self.assertEqual(ep.status, "candidate")
            secret = by_rule[("js-secret-candidate", js_asset)]
            self.assertEqual(secret.status, "candidate")
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", json.dumps(secret.to_dict()))   # raw secret never persisted, even in the finding

            self.assertTrue(AuditLog.verify(audit.path))
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
