import os, tempfile, unittest
from pagent.actions import build_actions, actions_as_text
from pagent.approvals import ApprovalStore
from pagent.audit import AuditLog
from pagent.policy import PolicyGateway
from pagent.scope import Scope
from pagent.tools.dir_probe import make_dir_probe
from pagent.tools.fuzz_probe import make_fuzz_probe
from pagent.tools.login_sqli_probe import make_login_sqli_probe
from pagent.tools.reflect_probe import make_reflect_probe
from pagent.tools.sqli_probe import make_sqli_probe

SEARCH = {"path": "/rest/products/search", "param": "q"}
LOGIN = {"path": "/rest/user/login", "param": "email"}


def scope_for(**over):
    d = {"engagement_id": "T", "authorized_by": "x", "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2030-01-01T00:00:00+00:00", "allowed_hosts": ["localhost"], "allowed_cidrs": [],
         "excluded_hosts": [], "allowed_ports": [5000], "allowed_tools": [], "intrusive_allowed": False,
         "allowed_probe_targets": [], "crawl_seeds": [], "discovery_prefixes": []}
    d.update(over)
    return Scope.from_dict(d)


class BatchActionTests(unittest.TestCase):
    def test_run_assessment_and_generate_proposals_always_present(self):
        names = {a.name for a in build_actions(scope_for())}
        self.assertIn("run_assessment", names)
        self.assertIn("generate_proposals", names)

    def test_run_crawl_requires_crawl_seeds(self):
        self.assertNotIn("run_crawl", {a.name for a in build_actions(scope_for())})
        self.assertIn("run_crawl", {a.name for a in build_actions(scope_for(crawl_seeds=["/"]))})

    def test_content_discovery_requires_both_prefixes_and_tool(self):
        absent1 = build_actions(scope_for(discovery_prefixes=["/"]))   # no dir_probe in allowed_tools
        self.assertNotIn("run_content_discovery", {a.name for a in absent1})
        absent2 = build_actions(scope_for(allowed_tools=["dir_probe"]))   # no prefixes
        self.assertNotIn("run_content_discovery", {a.name for a in absent2})
        present = build_actions(scope_for(discovery_prefixes=["/"], allowed_tools=["dir_probe"]))
        self.assertIn("run_content_discovery", {a.name for a in present})

    def test_all_batch_actions_are_read_only(self):
        for a in build_actions(scope_for(crawl_seeds=["/"], discovery_prefixes=["/"], allowed_tools=["dir_probe"])):
            if a.kind == "batch":
                self.assertTrue(a.read_only, a.name)


class TargetedActionTests(unittest.TestCase):
    def test_nothing_targeted_when_intrusive_not_allowed(self):
        sc = scope_for(intrusive_allowed=False, allowed_probe_targets=[SEARCH],
                       allowed_tools=["sqli_probe", "reflect_probe"])
        self.assertEqual([a for a in build_actions(sc) if a.kind == "targeted"], [])

    def test_nothing_targeted_when_no_probe_targets(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[], allowed_tools=["sqli_probe"])
        self.assertEqual([a for a in build_actions(sc) if a.kind == "targeted"], [])

    def test_login_target_only_produces_login_sqli_probe(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[LOGIN],
                       allowed_tools=["sqli_probe", "reflect_probe", "login_sqli_probe", "fuzz_probe"])
        names = {a.name for a in build_actions(sc) if a.kind == "targeted"}
        self.assertEqual(names, {"login_sqli_probe:/rest/user/login#email"})

    def test_login_target_absent_if_login_tool_not_in_allowed_tools(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[LOGIN], allowed_tools=["sqli_probe"])
        self.assertEqual([a for a in build_actions(sc) if a.kind == "targeted"], [])   # no fallback to sqli_probe

    def test_non_login_target_produces_sqli_reflect_and_two_fuzz_categories(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH],
                       allowed_tools=["sqli_probe", "reflect_probe", "fuzz_probe"])
        names = {a.name for a in build_actions(sc) if a.kind == "targeted"}
        self.assertEqual(names, {
            "sqli_probe:/rest/products/search#q",
            "reflect_probe:/rest/products/search#q",
            "fuzz_probe:/rest/products/search#q:sql_injection",
            "fuzz_probe:/rest/products/search#q:reflected_input",
        })

    def test_omitting_one_tool_only_removes_its_own_entries(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH], allowed_tools=["reflect_probe"])
        names = {a.name for a in build_actions(sc) if a.kind == "targeted"}
        self.assertEqual(names, {"reflect_probe:/rest/products/search#q"})

    def test_args_shape_for_each_tool(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH, LOGIN],
                       allowed_tools=["sqli_probe", "reflect_probe", "login_sqli_probe", "fuzz_probe"],
                       allowed_hosts=["localhost"], allowed_ports=[5000])
        by_name = {a.name: a for a in build_actions(sc)}
        self.assertEqual(by_name["sqli_probe:/rest/products/search#q"].args,
                         {"host": "localhost", "port": 5000, "path": "/rest/products/search", "param": "q"})
        self.assertEqual(by_name["login_sqli_probe:/rest/user/login#email"].args,
                         {"host": "localhost", "port": 5000, "path": "/rest/user/login", "field": "email"})
        self.assertEqual(by_name["fuzz_probe:/rest/products/search#q:sql_injection"].args["category"], "sql_injection")

    def test_all_targeted_actions_require_approval(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH],
                       allowed_tools=["sqli_probe", "reflect_probe", "fuzz_probe"])
        for a in build_actions(sc):
            if a.kind == "targeted":
                self.assertFalse(a.read_only, a.name)

    def test_action_names_are_unique(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH, LOGIN], crawl_seeds=["/"],
                       discovery_prefixes=["/"],
                       allowed_tools=["sqli_probe", "reflect_probe", "login_sqli_probe", "fuzz_probe", "dir_probe"])
        names = [a.name for a in build_actions(sc)]
        self.assertEqual(len(names), len(set(names)))


class ActionsAsTextTests(unittest.TestCase):
    def test_renders_tier_and_description_and_args(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH], allowed_tools=["sqli_probe"])
        text = actions_as_text(build_actions(sc))
        self.assertIn("REQUIRES APPROVAL", text)
        self.assertIn("read-only, auto-runs", text)
        self.assertIn("sqli_probe:/rest/products/search#q", text)
        self.assertIn("args=", text)

    def test_empty_list_renders_empty_string(self):
        self.assertEqual(actions_as_text([]), "")


class GatewayCrossCheckTests(unittest.TestCase):
    """Proves the registry never advertises an action PolicyGateway would reject for being
    out-of-scope: every targeted action's args, run through the REAL ToolSpec + PolicyGateway for
    this scope, must fail (if it fails at all) with an approval requirement - never a scope/
    cross_check denial."""

    def test_every_targeted_action_is_scope_valid(self):
        sc = scope_for(intrusive_allowed=True, allowed_probe_targets=[SEARCH, LOGIN],
                       allowed_tools=["sqli_probe", "reflect_probe", "login_sqli_probe", "fuzz_probe"])
        tmp = tempfile.mkdtemp()
        tools = {
            "sqli_probe": make_sqli_probe(sc, transport=lambda h, p, path, param, v, t: (200, 10)),
            "reflect_probe": make_reflect_probe(sc, transport=lambda h, p, path, param, v, t: (200, "echo")),
            "login_sqli_probe": make_login_sqli_probe(sc, transport=lambda h, p, path, field, v, t: (200, 10)),
            "fuzz_probe": make_fuzz_probe(sc, sqli_transport=lambda h, p, path, param, v, t: (200, 10),
                                          reflect_transport=lambda h, p, path, param, v, t: (200, "echo")),
        }
        gw = PolicyGateway(sc, tools, AuditLog(os.path.join(tmp, "a.jsonl")), approvals=ApprovalStore(os.path.join(tmp, "ap.db")))
        for action in build_actions(sc):
            if action.kind != "targeted":
                continue
            r = gw.execute(action.tool, action.args, proposed_by="test")
            if not r["ok"]:
                self.assertIn("approval_request_id", r, f"{action.name} denied for a non-approval reason: {r.get('error')}")

    def test_dir_probe_targets_from_registry_would_not_be_scope_denied(self):
        # dir_probe isn't a targeted action in this registry (it's a batch action), but confirm
        # the registry correctly keeps it out of 'targeted' - no per-path entries to cross-check.
        sc = scope_for(discovery_prefixes=["/"], allowed_tools=["dir_probe"])
        self.assertEqual([a for a in build_actions(sc) if a.tool == "dir_probe"], [])


if __name__ == "__main__":
    unittest.main()
