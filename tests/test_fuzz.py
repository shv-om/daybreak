import unittest
from pagent.fuzz import reflect_fuzz_finding, sqli_fuzz_finding


class SqliFuzzFindingTests(unittest.TestCase):
    def test_differing_variant_yields_candidate(self):
        out = ("baseline_status=200 baseline_len=10\n"
              "single_quote_status=500 single_quote_len=3 single_quote_differs=yes\n"
              "double_quote_status=200 double_quote_len=10 double_quote_differs=no\n"
              "escaped_quote_status=200 escaped_quote_len=10 escaped_quote_differs=no\n"
              "backslash_status=200 backslash_len=10 backslash_differs=no\n"
              "sql_comment_status=200 sql_comment_len=10 sql_comment_differs=no")
        f = sqli_fuzz_finding(1, "h", "localhost:5000", "/rest/products/search", "q", out)
        self.assertEqual(f.status, "candidate")
        self.assertEqual(f.verification["differing_variants"], ["single_quote"])
        self.assertTrue(f.next_steps)
        self.assertIn("No tautology", " ".join(f.limitations))

    def test_no_differing_variant_yields_informational(self):
        names = ("baseline", "single_quote", "double_quote", "escaped_quote", "backslash", "sql_comment")
        out = "\n".join(f"{name}_status=200 {name}_len=10" + ("" if name == "baseline" else f" {name}_differs=no")
                        for name in names)
        f = sqli_fuzz_finding(1, "h", "localhost:5000", "/rest/products/search", "q", out)
        self.assertEqual(f.status, "informational")
        self.assertEqual(f.verification["differing_variants"], [])
        self.assertFalse(f.next_steps)

    def test_finding_id_stable_for_same_inputs(self):
        out = "baseline_status=200 baseline_len=10"
        f1 = sqli_fuzz_finding(1, "h", "localhost:5000", "/rest/products/search", "q", out)
        f2 = sqli_fuzz_finding(2, "h2", "localhost:5000", "/rest/products/search", "q", out)
        self.assertEqual(f1.id, f2.id)


class ReflectFuzzFindingTests(unittest.TestCase):
    def test_any_raw_variant_yields_candidate(self):
        out = ("token=abc123\n"
              "angle_bracket_status=200 angle_bracket_signal=raw\n"
              "double_quote_status=200 double_quote_signal=escaped\n"
              "single_quote_status=200 single_quote_signal=escaped")
        f = reflect_fuzz_finding(1, "h", "localhost:5000", "/rest/products/search", "q", out)
        self.assertEqual(f.status, "candidate")
        self.assertEqual(f.verification["raw_variants"], ["angle_bracket"])

    def test_all_escaped_yields_informational(self):
        out = ("token=abc123\n"
              "angle_bracket_status=200 angle_bracket_signal=escaped\n"
              "double_quote_status=200 double_quote_signal=escaped\n"
              "single_quote_status=200 single_quote_signal=escaped")
        f = reflect_fuzz_finding(1, "h", "localhost:5000", "/rest/products/search", "q", out)
        self.assertEqual(f.status, "informational")
        self.assertEqual(f.verification["raw_variants"], [])


if __name__ == "__main__":
    unittest.main()
