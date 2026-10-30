import copy, json, unittest

from pagent.fuzzing import PayloadFuzzError, payload_fuzz_finding, resolve_payload_batch
from pagent.proposals import validate_contextual_output
from pagent.scope import Scope

SEARCH = {"path": "/rest/products/search", "param": "q"}
LOGIN = {"path": "/rest/user/login", "param": "email"}


def scope_for(targets=(SEARCH,), tools=("payload_fuzz",)):
    return Scope.from_dict({
        "engagement_id": "F", "authorized_by": "SYNTHETIC TEST",
        "valid_from": "2026-01-01T00:00:00+00:00", "valid_until": "2030-01-01T00:00:00+00:00",
        "allowed_hosts": ["localhost"], "allowed_cidrs": [], "excluded_hosts": [], "allowed_ports": [5000],
        "allowed_tools": list(tools), "intrusive_allowed": True, "allowed_probe_targets": list(targets),
    })


def doc_for(target=SEARCH, payloads=None, weakness="sql_injection"):
    payloads = payloads or [
        {"payload": "'", "category": "quote_break", "expected_signal": "shape changes", "rationale": "quote"},
        {"payload": "1 OR 1=1", "category": "boolean_pair", "expected_signal": "true-like response", "rationale": "pair"},
    ]
    raw = {"hypotheses": [{
        "weakness_type": weakness, "path": target["path"], "parameter": target["param"],
        "rationale": "synthetic", "confidence": "low", "evidence_refs": [], "payloads": payloads,
    }]}
    hs = validate_contextual_output(raw, scope_for(targets=(target,)), set())
    doc = {"proposal_only": True, "hypotheses": [h.to_dict() for h in hs]}
    return doc, [p.id for p in hs[0].payloads]


class ResolveFuzzBatchTests(unittest.TestCase):
    def test_dynamic_model_payloads_are_preserved_verbatim(self):
        doc, ids = doc_for()
        resolved = resolve_payload_batch(doc, ids, scope_for())
        self.assertEqual(resolved.tool, "payload_fuzz")
        self.assertEqual(resolved.args["payloads"], ["'", "1 OR 1=1"])
        self.assertEqual(resolved.args["mode"], "query_get")

    def test_login_target_uses_fixed_json_login_shape(self):
        payloads = [{"payload": "'", "category": "quote_break", "expected_signal": "shape", "rationale": "q"}]
        doc, ids = doc_for(LOGIN, payloads)
        resolved = resolve_payload_batch(doc, ids, scope_for(targets=(LOGIN,)))
        self.assertEqual(resolved.args["mode"], "json_login")
        self.assertEqual(resolved.args["param"], "email")

    def test_tampered_payload_text_is_rejected(self):
        doc, ids = doc_for()
        edited = copy.deepcopy(doc)
        edited["hypotheses"][0]["payloads"][0]["payload"] = "changed"
        with self.assertRaises(PayloadFuzzError) as cm:
            resolve_payload_batch(edited, [ids[0]], scope_for())
        self.assertIn("does not match its id", str(cm.exception))

    def test_payload_fuzz_must_be_explicitly_in_scope(self):
        doc, ids = doc_for()
        with self.assertRaises(PayloadFuzzError):
            resolve_payload_batch(doc, ids, scope_for(tools=("sqli_probe",)))

    def test_active_scope_is_rechecked(self):
        doc, ids = doc_for()
        narrower = scope_for(targets=(LOGIN,))
        with self.assertRaises(PayloadFuzzError):
            resolve_payload_batch(doc, [ids[0]], narrower)


class FindingTests(unittest.TestCase):
    def test_changed_response_is_candidate_not_confirmation(self):
        out = json.dumps({"mode": "query_get", "response_changed_count": 1,
                          "cases": [{"response_changed": True}]})
        f = payload_fuzz_finding(7, "abc", "localhost:5000", SEARCH["path"], "q", out, ("P-1",))
        self.assertEqual(f.status, "candidate")
        self.assertEqual(f.severity["rating"], "not_assessed")
        self.assertIn("1/1", f.verification["result"])
        self.assertIn("P-1", f.verification["payload_ids"])


if __name__ == "__main__":
    unittest.main()
