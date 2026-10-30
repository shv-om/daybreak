import json, os, re, tempfile, threading, unittest
from http.server import HTTPServer
from pagent.audit import AuditLog
from pagent.discover import run_discovery
from pagent.policy import PolicyGateway
from pagent.report import build_report, to_markdown
from pagent.rules import candidates_from_observations
from pagent.store import Store
from pagent.tools.http_head import make_http_head
from pagent.verify import verify_candidates
from test_discovery import scope_for, Handler

BASE = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}


def pipeline(responses, port=8123):
    """responses: list of header dicts (or Exception) returned on successive requests."""
    seq = list(responses)
    def transport(h, p, t):
        r = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(r, Exception):
            raise r
        return 200, dict(r)
    sc = scope_for(port)
    gw = PolicyGateway(sc, {"http_head": make_http_head(transport)}, AuditLog(os.path.join(tempfile.mkdtemp(), "a.jsonl")))
    store = Store(":memory:")
    summ = run_discovery(gw, store, sc)
    fs = candidates_from_observations(store, summ["run_id"])
    return sc, gw, store, summ, fs


class RuleTests(unittest.TestCase):
    def test_candidates_match_absent_headers_and_hsts_is_inconclusive(self):
        _, _, _, _, fs = pipeline([BASE])
        ids = {f.rule_id.split(":")[1] for f in fs}
        self.assertEqual(ids, {"content-security-policy", "referrer-policy", "permissions-policy", "strict-transport-security"})
        hsts = [f for f in fs if "strict-transport" in f.rule_id][0]
        self.assertEqual(hsts.status, "inconclusive")
        self.assertTrue(all(f.status == "candidate" for f in fs if f is not hsts))

    def test_no_invented_severity_and_stable_ids(self):
        _, _, _, _, a = pipeline([BASE]); _, _, _, _, b = pipeline([BASE])
        self.assertEqual([f.id for f in a], [f.id for f in b])
        self.assertTrue(all(f.severity["rating"] == "not_assessed" for f in a))
        self.assertTrue(all(f.evidence and f.evidence[0]["output_sha256"] for f in a))


class VerifyTests(unittest.TestCase):
    def run_verify(self, second):
        sc, gw, store, summ, fs = pipeline([BASE, second])
        verify_candidates(gw, store, summ["run_id"], fs)
        return fs

    def test_reproduced_becomes_confirmed(self):
        fs = self.run_verify(BASE)
        c = [f for f in fs if "content-security" in f.rule_id][0]
        self.assertEqual(c.status, "confirmed")
        self.assertEqual(c.confidence["level"], "medium")
        self.assertEqual(len(c.evidence), 2)

    def test_header_appearing_on_repeat_is_inconclusive(self):
        fs = self.run_verify({**BASE, "Content-Security-Policy": "default-src 'self'"})
        c = [f for f in fs if "content-security" in f.rule_id][0]
        r = [f for f in fs if "referrer" in f.rule_id][0]
        self.assertEqual(c.status, "inconclusive")
        self.assertEqual(r.status, "confirmed")

    def test_verification_failure_is_inconclusive(self):
        fs = self.run_verify(TimeoutError())
        self.assertTrue(all(f.status == "inconclusive" for f in fs))

    def test_verification_evidence_references_saved_observations(self):
        sc, gw, store, summ, fs = pipeline([BASE, BASE])
        verify_candidates(gw, store, summ["run_id"], fs)
        c = [f for f in fs if "content-security" in f.rule_id][0]
        ids = c.evidence[1]["observation_ids"]
        saved = {r["id"] for r in store.observation_rows(summ["run_id"])}
        self.assertTrue(ids)
        self.assertTrue(set(ids).issubset(saved))


class ReportTests(unittest.TestCase):
    def test_json_and_markdown_agree(self):
        sc, gw, store, summ, fs = pipeline([BASE, BASE])
        verify_candidates(gw, store, summ["run_id"], fs)
        rep = build_report(summ["run_id"], sc, fs)
        md = to_markdown(rep)
        self.assertEqual(set(re.findall(r"### (F-[0-9a-f]{10})", md)), {f["id"] for f in rep["findings"]})
        self.assertEqual(rep["summary"]["total"], len(rep["findings"]))
        self.assertEqual(sum(rep["summary"][s] for s in ("candidate", "confirmed", "informational", "inconclusive")), rep["summary"]["total"])
        for s in ("confirmed", "inconclusive"):
            self.assertIn(f"| {s} | {rep['summary'][s]} |", md)
        json.dumps(rep)   # serialisable


class LocalServerEndToEnd(unittest.TestCase):
    def test_real_server(self):
        srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            sc = scope_for(srv.server_address[1])
            gw = PolicyGateway(sc, {"http_head": make_http_head()}, AuditLog(os.path.join(tempfile.mkdtemp(), "a.jsonl")))
            store = Store(":memory:")
            summ = run_discovery(gw, store, sc)
            fs = candidates_from_observations(store, summ["run_id"])
            verify_candidates(gw, store, summ["run_id"], fs)
            confirmed = {f.rule_id.split(":")[1] for f in fs if f.status == "confirmed"}
            self.assertEqual(confirmed, {"content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy"})
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
