"""One interactive session covering every capability this project has: passive discovery,
crawling, intrusive probing, AI proposals (generate/review/approve/execute/log outcome), manual
confirmation, and knowledge-base update/mapping validation - all on one scope, one run_id, one
menu, so flags are entered once up front and nothing has to be retyped between steps.

This is orchestration only: every action below calls the SAME pagent.* functions the standalone
scripts (run_assessment.py, run_crawl.py, run_intrusive.py, propose_tests.py, execute_proposal.py,
approve.py, log_proposal_outcome.py, log_manual_action.py, kb_update.py, validate_mapping.py) call.
Nothing here is a shortcut around the policy gateway or the approval lifecycle - an intrusive call
still goes through ApprovalStore.request() -> a human reviews the EXACT tool+args and types y ->
the gateway's normal atomic reserve/execute/consume, and every call is still audit-logged. Those
standalone scripts are untouched and still work for scripting/CI.

    python scripts/agent.py --scope config/scope.lab.intrusive.json
(--model can be given up front too; if it isn't, you're asked once, only when you choose to
generate proposals. Everything else - what to run, which payload to approve, which finding to
confirm - happens from the menu.)
"""
import argparse, getpass, json, os, re, sys, time
from dataclasses import replace
from urllib.parse import unquote
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pagent.approvals import ApprovalStore
from pagent.actions import build_actions
from pagent.audit import AuditLog
from pagent.discover import run_content_discovery, run_crawl, run_discovery, run_port_discovery
from pagent.evidence import build_evidence, evidence_as_text
from pagent.execution import NON_EXECUTABLE_CATEGORIES, ProposalExecutionError, resolve_from_file
from pagent.fuzz import reflect_fuzz_finding, sqli_fuzz_finding
from pagent.intrusive import LOGIN_TARGETS, login_sqli_finding, reflect_finding, sqli_finding
from pagent.kb.fetch import ALLOWED as KB_SOURCES, fetch_source
from pagent.kb.ingest import ingest as kb_ingest
from pagent.kb.mapping import check_against_kb, check_mapping, enrich_findings, load_mapping
from pagent.kb.store import KBStore
from pagent.llm import OllamaClient
from pagent.manual_confirm import ManualConfirmError, apply_manual_action
from pagent.orchestrator import (ActionPlanner, ActionPlanningError, RoutineScopeError,
                                 validate_local_lab_routine_scope)
from pagent.parse import model_view
from pagent.policy import PolicyGateway
from pagent.proposals import ContextProposalError, ContextualProposalEngine
from pagent.review import ReviewEngine, ReviewError
from pagent.report import build_report, finding_markdown, to_markdown
from pagent.rules import candidates_from_crawl, candidates_from_discovery, candidates_from_observations, open_port_findings
from pagent.scope import Scope, ScopeError
from pagent.store import Store
from pagent.suggestions.context import ContextBuilder
from pagent.suggestions.outcomes import OUTCOMES, ProposalOutcomeError, build_outcome_record, summarize
from pagent.suggestions.registry import SuggestionSourceRegistry
from pagent.tools.dir_probe import make_dir_probe
from pagent.tools.fuzz_probe import make_fuzz_probe
from pagent.tools.http_get import make_http_get
from pagent.tools.http_head import make_http_head
from pagent.tools.login_sqli_probe import make_login_sqli_probe
from pagent.tools.nmap_tcp import make_nmap_tcp
from pagent.tools.reflect_probe import make_reflect_probe
from pagent.tools.sqli_probe import make_sqli_probe
from pagent.verify import verify_candidates
from pagent.wordlist import WordlistError

FINDING_BUILDERS = {"reflect_probe": reflect_finding, "sqli_probe": sqli_finding, "login_sqli_probe": login_sqli_finding}
# fuzz_probe is one tool shared by two categories, so it needs category-aware dispatch (see run_fuzz_targets below)
FUZZ_FINDING_BUILDERS = {"sql_injection": sqli_fuzz_finding, "reflected_input": reflect_fuzz_finding}
SUGGESTION_SOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "config", "suggestion_sources")


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return "q"


class Session:
    def __init__(self, a):
        self.a = a
        self.store = Store(a.db)
        self.approvals = ApprovalStore(a.approvals)
        self.audit = AuditLog(a.audit)
        self.registry = SuggestionSourceRegistry(SUGGESTION_SOURCES_DIR)
        self.doc = None            # currently loaded/generated proposals-run-shaped dict
        self.doc_path = None
        self.handled = set()       # payload ids already reviewed this session
        self.findings = []         # every Finding produced this session, across all areas
        self.auto_review = not a.no_auto_review   # [7c] toggles this; see _run_ai_pipeline
        self._bind_scope(Scope.load(a.scope))

    def _bind_scope(self, scope: Scope):
        """(Re)build everything that is a function of the active scope. Called at startup and
        whenever [7b] switches scope files - each scope gets its OWN run_id, never shared."""
        self.scope = scope
        tools = {"http_head": make_http_head(), "http_get": make_http_get(scope), "nmap_tcp": make_nmap_tcp(),
                 "reflect_probe": make_reflect_probe(scope), "sqli_probe": make_sqli_probe(scope),
                 "login_sqli_probe": make_login_sqli_probe(scope)}
        if "fuzz_probe" in scope.allowed_tools:   # opt-in via scope, same discipline as every other tool here
            tools["fuzz_probe"] = make_fuzz_probe(scope)
        if "dir_probe" in scope.allowed_tools:
            tools["dir_probe"] = make_dir_probe(scope)
        self.gateway = PolicyGateway(scope, tools, self.audit, approvals=self.approvals)
        self.builder = ContextBuilder(store=self.store, scope=scope)
        row = self.store.db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        self.source_run_id = row[0] if row else None   # prior run's findings, used as proposal context
        self.run_id = self.store.start_run(scope)       # this session's own run, for new tool_calls/findings

    def _write_component_report(self, prefix, findings):
        action_ledger = self.store.action_ledger_for_run(self.run_id)
        if not findings and not action_ledger:
            return
        report = build_report(self.run_id, self.scope, findings, action_ledger=action_ledger)
        os.makedirs(self.a.out, exist_ok=True)
        base = os.path.join(self.a.out, f"{prefix}-run{self.run_id}")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        with open(base + ".md", "w", encoding="utf-8") as f:
            f.write(to_markdown(report))
        print("wrote", base + ".json", "and", base + ".md")

    # ================= 1. Discovery & Assessment (passive, read-only) =================
    def run_assessment(self):
        open_ports = run_port_discovery(self.gateway, self.store, self.scope, self.run_id) if "nmap_tcp" in self.scope.allowed_tools else None
        if open_ports is not None:
            print("open ports:", json.dumps(open_ports))
        summary = run_discovery(self.gateway, self.store, self.scope, run_id=self.run_id, open_ports=open_ports)
        findings = open_port_findings(self.store, self.run_id) + candidates_from_observations(self.store, self.run_id)
        verify_candidates(self.gateway, self.store, self.run_id, findings)
        if os.path.exists(self.a.kb):
            mapping = load_mapping(self.a.mapping)
            problems = check_mapping(mapping)
            if problems:
                print("mapping problems:", "; ".join(problems))
            else:
                print("cwe enrichment:", json.dumps(enrich_findings(findings, KBStore(self.a.kb), mapping, self.a.include_proposed)))
        else:
            print(f"no knowledge base at {self.a.kb} - run [6a] first for CWE enrichment")
        for f in findings:
            self.store.save_finding(self.run_id, f.to_dict())
        self.findings += findings
        self._write_component_report("assessment", findings)
        print(f"assessment: {summary['calls_allowed']} allowed / {summary['calls_denied']} denied, {len(findings)} finding(s)")
        self._maybe_auto_review(findings)

    # ================= 2. Crawl (passive, read-only) =================
    def run_crawl_action(self):
        if not self.scope.crawl_seeds:
            print("scope.crawl_seeds is empty - add at least one path (e.g. \"/\") to the scope file first")
            return
        summary = run_crawl(self.gateway, self.store, self.scope, run_id=self.run_id)
        findings = candidates_from_crawl(self.store, self.run_id)
        for f in findings:
            self.store.save_finding(self.run_id, f.to_dict())
        self.findings += findings
        self._write_component_report("crawl", findings)
        print(f"crawl: {summary['calls_allowed']} allowed / {summary['calls_denied']} denied, {len(findings)} finding(s)")
        self._maybe_auto_review(findings)

    # ================= 9. Content discovery (passive, read-only) =================
    def run_content_discovery_action(self):
        """GETs scope.discovery_prefixes x the small checked-in wordlist - NOT an external tool
        (no ffuf/wfuzz/gobuster), NOT a model- or user-controlled path list. See
        pagent.discover.run_content_discovery / pagent.tools.dir_probe for exactly what is sent."""
        if not self.scope.discovery_prefixes:
            print("scope.discovery_prefixes is empty - add at least one prefix (e.g. \"/\") to the scope file first")
            return
        if "dir_probe" not in self.scope.allowed_tools:
            print("'dir_probe' is not in scope.allowed_tools - add it to the scope file to enable content discovery")
            return
        try:
            summary = run_content_discovery(self.gateway, self.store, self.scope, run_id=self.run_id)
        except WordlistError as e:
            print(f"wordlist error: {e}")
            return
        except ValueError as e:
            print(str(e))
            return
        findings = candidates_from_discovery(self.store, self.run_id)
        for f in findings:
            self.store.save_finding(self.run_id, f.to_dict())
        self.findings += findings
        self._write_component_report("content-discovery", findings)
        print(f"content discovery: {summary['calls_allowed']} allowed / {summary['calls_denied']} denied, {len(findings)} finding(s)")
        self._maybe_auto_review(findings)

    # ================= 3. Intrusive probing (approval required) =================
    def run_intrusive_targets(self):
        if not self.scope.intrusive_allowed:
            print("scope.intrusive_allowed is false - this scope does not permit intrusive testing")
            return
        if not self.scope.allowed_probe_targets:
            print("scope.allowed_probe_targets is empty - nothing is authorized for active probing")
            return
        host = sorted(self.scope.allowed_hosts)[0] if self.scope.allowed_hosts else "localhost"
        port = min(self.scope.allowed_ports)
        new_findings = []
        for path, param in self.scope.allowed_probe_targets:
            if (path, param) in LOGIN_TARGETS:
                jobs = [("login_sqli_probe", {"host": host, "port": port, "path": path, "field": param})]
            else:
                jobs = [("reflect_probe", {"host": host, "port": port, "path": path, "param": param}),
                       ("sqli_probe", {"host": host, "port": port, "path": path, "param": param})]
            for tool, args in jobs:
                r = self.gateway.execute(tool, args, proposed_by="deterministic")
                call_id = self.store.record_tool_call(self.run_id, tool, args, r)
                if not r["ok"]:
                    msg = f"{tool} {path}?{param}: NOT RUN - {r['error']}"
                    if "approval_request_id" in r:
                        msg += f" (approval id {r['approval_request_id']} - approve it via [3b], then run [3a] again)"
                    print(msg)
                    continue
                sha = self.store.tool_call_row(call_id)["output_sha256"]
                f = FINDING_BUILDERS[tool](call_id, sha, f"{host}:{port}", path, param, r["untrusted_output"])
                self.store.save_finding(self.run_id, f.to_dict())
                new_findings.append(f)
                print(f"{tool} {path}?{param}: ran (approval id {r.get('approval_id')})")
        self.findings += new_findings
        self._write_component_report("intrusive", new_findings)
        self._maybe_auto_review(new_findings)

    # ================= 3c. Payload fuzzing (approval required) =================
    def run_fuzz_targets(self):
        """Runs fuzz_probe (an expanded, still fully fixed-in-code diagnostic battery - see
        pagent.tools.fuzz_probe) for both categories against every non-login allowed_probe_targets
        entry. Login targets are skipped: fuzz_probe only has a GET query-string shape, same as
        reflect_probe/sqli_probe - login_sqli_probe already covers that target."""
        if not self.scope.intrusive_allowed:
            print("scope.intrusive_allowed is false - this scope does not permit intrusive testing")
            return
        if "fuzz_probe" not in self.scope.allowed_tools:
            print("fuzz_probe is not in scope.allowed_tools - add it to the scope file to enable payload fuzzing")
            return
        if not self.scope.allowed_probe_targets:
            print("scope.allowed_probe_targets is empty - nothing is authorized for active probing")
            return
        host = sorted(self.scope.allowed_hosts)[0] if self.scope.allowed_hosts else "localhost"
        port = min(self.scope.allowed_ports)
        new_findings = []
        for path, param in self.scope.allowed_probe_targets:
            if (path, param) in LOGIN_TARGETS:
                continue
            for category, builder in FUZZ_FINDING_BUILDERS.items():
                args = {"host": host, "port": port, "path": path, "param": param, "category": category}
                r = self.gateway.execute("fuzz_probe", args, proposed_by="deterministic")
                call_id = self.store.record_tool_call(self.run_id, "fuzz_probe", args, r)
                if not r["ok"]:
                    msg = f"fuzz_probe[{category}] {path}?{param}: NOT RUN - {r['error']}"
                    if "approval_request_id" in r:
                        msg += f" (approval id {r['approval_request_id']} - approve it via [3b], then run [3c] again)"
                    print(msg)
                    continue
                sha = self.store.tool_call_row(call_id)["output_sha256"]
                f = builder(call_id, sha, f"{host}:{port}", path, param, r["untrusted_output"])
                self.store.save_finding(self.run_id, f.to_dict())
                new_findings.append(f)
                print(f"fuzz_probe[{category}] {path}?{param}: ran (approval id {r.get('approval_id')})")
        self.findings += new_findings
        self._write_component_report("fuzz", new_findings)
        self._maybe_auto_review(new_findings)

    def review_approvals(self):
        pending = self.approvals.pending()
        if not pending:
            print("(no pending approval requests)")
            return
        for i, tool, args, ts in pending:
            print(f"#{i}  {tool}  {args}  requested {time.strftime('%H:%M:%S', time.localtime(ts))}")
            choice = ask("  approve? [y/N/s=stop]: ").lower()
            if choice == "s":
                return
            if choice == "y":
                self.approvals.decide(i, True, who=getpass.getuser())
                print("  approved - rerun [3a] (or [4c]) to execute")
            else:
                print("  left pending")

    # ================= 4. AI proposals =================
    def _run_ai_pipeline(self, auto: bool = False):
        """Two-pass, proposal-only AI pipeline:
          1. REASONING (self.a.reasoning_model, defaults to self.a.model) - ReviewEngine decides,
             from real evidence (pagent.evidence), which findings are worth a closer look.
          2. GENERATION (self.a.model) - ContextualProposalEngine proposes hypotheses+payloads
             only for that reviewed subset, with the same evidence attached.
        Both passes stay strictly proposal_only/suggested_only - neither ever executes anything.
        Returns the saved doc, or None if nothing ran. In every "nothing ran" case (no model
        configured, no candidate findings, review found nothing worth investigating, or a model/
        network error) this prints one line instead of raising - `auto=True` callers (every
        data-gathering action, when self.auto_review is set) must never have this crash the
        session over a transient Ollama hiccup."""
        model = self.a.model
        if not model:
            if auto:
                return None   # stay quiet in auto mode rather than prompting mid other-action
            model = ask("Ollama model name (generation pass): ")
            if not model:
                print("no model given, cancelled")
                return None
            self.a.model = model
        reasoning_model = self.a.reasoning_model or model

        run_ids = [r for r in (self.source_run_id, self.run_id) if r is not None]
        findings, observations = [], []
        for rid in dict.fromkeys(run_ids):
            findings += self.store.findings_for_run(rid)
            observations += self.store.observations(rid)
        findings = list({f["id"]: f for f in findings if f.get("id")}.values())
        if not findings:
            if not auto:
                print("no findings yet to review")
            return None
        observations = model_view(observations)
        finding_context, weakness_types_seen = [], set()
        for f in findings:
            base = {k: f.get(k) for k in ("id", "rule_id", "asset", "title", "status", "applicability")}
            base.update(self.builder.build(f))
            if "weakness_type" in base.get("candidate", {}):
                weakness_types_seen.add(base["candidate"]["weakness_type"])
            finding_context.append(base)

        evidence_text = evidence_as_text(build_evidence(self.store, self.run_id))

        try:
            reasoning_client = OllamaClient(reasoning_model, host=self.a.ollama)
            print(f"[{reasoning_model}] reviewing {len(findings)} finding(s) against recent evidence ...")
            review_rows, review_stats = ReviewEngine(reasoning_client).review_detailed(findings, evidence_text)
            worth_ids = [row["finding_id"] for row in review_rows if row["worth_investigating"]]
        except (OSError, json.JSONDecodeError, ReviewError) as e:
            self.store.record_action_event(
                self.run_id, "ai_triage_review", action_name="triage_findings",
                tool="ReviewEngine", decision="failed", outcome="AI review did not complete",
                details={"model": reasoning_model, "error_type": type(e).__name__,
                         "error": str(e)[:500], "finding_ids": [f["id"] for f in findings if f.get("id")]})
            print(f"review pass failed ({e}) - skipping AI proposals for now")
            return None
        self.store.record_action_event(
            self.run_id, "ai_triage_review", action_name="triage_findings",
            tool="ReviewEngine", decision="triaged",
            outcome=f"{len(worth_ids)} finding(s) recommended for closer review",
            rationale="Model triage is prioritization only; deterministic checks and evidence remain authoritative.",
            details={"model": reasoning_model,
                     "finding_ids": [f["id"] for f in findings if f.get("id")],
                     "worth_investigating_ids": worth_ids,
                     "reviewed": review_rows,
                     "review_stats": review_stats})
        if not worth_ids:
            print("review pass: nothing flagged as worth a closer look right now")
            return None
        print(f"review pass: {len(worth_ids)}/{len(findings)} finding(s) worth investigating")

        filtered_context = [c for c in finding_context if c["id"] in worth_ids]
        valid_refs = {c["id"] for c in filtered_context}
        guidance = {wt: self.registry.guidance_for(wt) for wt in sorted(weakness_types_seen)}
        context = {"run_id": self.run_id, "observations": observations, "findings": filtered_context,
                  "suggestion_sources": guidance}

        try:
            generation_client = OllamaClient(model, host=self.a.ollama)
            print(f"[{model}] generating hypotheses + payload proposals ...")
            hypotheses, gen_stats = ContextualProposalEngine(generation_client).generate(
                self.scope, context, valid_refs, evidence_text=evidence_text)
        except (OSError, json.JSONDecodeError, ContextProposalError) as e:
            print(f"generation pass failed ({e})")
            return None

        self.doc = {"proposal_only": True, "run_id": self.run_id, "reasoning_model": reasoning_model,
                    "generation_model": model,
                    "review": {"reviewed": review_rows, "worth_investigating": worth_ids,
                               "stats": review_stats},
                    "stats": gen_stats, "hypotheses": [h.to_dict() for h in hypotheses]}
        os.makedirs(self.a.out, exist_ok=True)
        self.doc_path = os.path.join(self.a.out, f"proposals-run{self.run_id}.json")
        with open(self.doc_path, "w", encoding="utf-8") as f:
            json.dump(self.doc, f, indent=2)
        self.handled = set()
        n_payloads = sum(len(h["payloads"]) for h in self.doc["hypotheses"])
        print(f"{len(self.doc['hypotheses'])} hypothesis(es), {n_payloads} payload(s) - wrote {self.doc_path}")
        print("NOTE: proposal_only - nothing above was executed. Use [4c] to review.")
        return self.doc

    def generate_proposals(self):
        self._run_ai_pipeline(auto=False)

    # ================= 10. Orchestrator =================
    def recommend_next_action(self):
        """Recommend one registered action; execute supported batch actions only after confirmation."""
        model = self.a.reasoning_model or self.a.model
        if not model:
            model = ask("Ollama model name (action planning): ")
            if not model:
                print("no model given, cancelled")
                return
            self.a.reasoning_model = model

        actions = build_actions(self.scope)
        findings = self.store.findings_for_run(self.run_id)
        context = {
            "engagement_id": self.scope.engagement_id,
            "run_id": self.run_id,
            "findings": [{k: f.get(k) for k in ("id", "title", "status", "confidence", "asset")}
                         for f in findings[-20:]],
            "recent_tool_calls": self.store.tool_calls(self.run_id)[-20:],
        }
        evidence_text = evidence_as_text(build_evidence(self.store, self.run_id))
        try:
            print(f"[{model}] choosing from {len(actions)} registered action(s) ...")
            recommendation, _stats = ActionPlanner(OllamaClient(model, host=self.a.ollama)).recommend(
                actions, context, evidence_text=evidence_text)
        except (OSError, ActionPlanningError) as e:
            print(f"action planning failed ({e})")
            return

        if recommendation["action"] == "stop":
            self.store.record_action_event(self.run_id, "planner_control", action_name="stop",
                                           rationale=recommendation["rationale"], decision="stop",
                                           outcome="no action dispatched")
            print("planner recommends stopping: " + recommendation["rationale"])
            return
        if recommendation["action"] == "ask_human":
            self.store.record_action_event(self.run_id, "planner_control", action_name="ask_human",
                                           rationale=recommendation["rationale"], decision="ask_human",
                                           outcome="no action dispatched")
            print("planner needs human input: " + recommendation["rationale"])
            return
        spec = recommendation["spec"]
        self.store.record_action_event(
            self.run_id, "recommendation", action_name=spec.name, tool=spec.tool, args=spec.args,
            rationale=recommendation["rationale"], decision="recommended",
            outcome="awaiting operator decision")
        tier = "read-only" if spec.read_only else "approval required"
        print("recommended next action:")
        print(f"  {spec.name} [{tier}]")
        if spec.args:
            print("  registered arguments: " + json.dumps(spec.args, sort_keys=True))
        print("  rationale: " + recommendation["rationale"])
        if spec.kind != "batch" or not spec.read_only:
            self.store.record_action_event(
                self.run_id, "handoff", action_name=spec.name, tool=spec.tool, args=spec.args,
                rationale=recommendation["rationale"], decision="human approval required",
                outcome="not dispatched by planner")
            self._write_component_report("agent", self.findings)
            print("This targeted action is not run from the planner. Use the existing intrusive menu and approval flow.")
            return

        runners = {
            "run_assessment": self.run_assessment,
            "run_crawl": self.run_crawl_action,
            "run_content_discovery": self.run_content_discovery_action,
            "generate_proposals": self.generate_proposals,
        }
        runner = runners.get(spec.tool)
        if runner is None:
            self.store.record_action_event(
                self.run_id, "dispatch", action_name=spec.name, tool=spec.tool,
                decision="unavailable", outcome="no session handler registered")
            self._write_component_report("agent", self.findings)
            print("No session handler is registered for this batch action; nothing was run.")
            return
        answer = ask("Run this one registered batch action now? [y/N]: ").lower()
        if answer != "y":
            self.store.record_action_event(
                self.run_id, "operator_decision", action_name=spec.name, tool=spec.tool,
                args=spec.args, decision="declined", outcome="action not run")
            self._write_component_report("agent", self.findings)
            print("recommendation not run")
            return
        self.store.record_action_event(
            self.run_id, "operator_decision", action_name=spec.name, tool=spec.tool,
            args=spec.args, decision="confirmed", outcome="dispatch authorized by operator")
        before_calls = {row["id"] for row in self.store.tool_call_rows(self.run_id)}
        before_findings = {f.get("id") for f in self.store.findings_for_run(self.run_id)}
        self.store.record_action_event(
            self.run_id, "dispatch_started", action_name=spec.name, tool=spec.tool,
            args=spec.args, decision="confirmed", outcome="calling existing session handler")
        print(f"running {spec.name} ...")
        try:
            runner()
        except Exception as e:
            self.store.record_action_event(
                self.run_id, "dispatch_finished", action_name=spec.name, tool=spec.tool,
                args=spec.args, decision="confirmed", outcome="handler raised an exception",
                details={"error_type": type(e).__name__, "error": str(e)[:500]})
            self._write_component_report("agent", self.findings)
            print(f"action handler failed ({type(e).__name__}: {e})")
            return
        after_calls = self.store.tool_call_rows(self.run_id)
        after_findings = {f.get("id") for f in self.store.findings_for_run(self.run_id)}
        new_call_ids = [row["id"] for row in after_calls if row["id"] not in before_calls]
        new_finding_ids = sorted(x for x in after_findings - before_findings if x)
        self.store.record_action_event(
            self.run_id, "dispatch_finished", action_name=spec.name, tool=spec.tool,
            args=spec.args, decision="confirmed", outcome="handler completed",
            details={"tool_call_ids": new_call_ids, "finding_ids": new_finding_ids})
        self._write_component_report("agent", self.findings)

    # ================= Local Juice Shop routine =================
    def scan_local_js_assets(self):
        """Fetch a bounded set of same-host script references for the loopback lab only."""
        host = next(iter(self.scope.allowed_hosts))
        port = next(iter(self.scope.allowed_ports))
        asset_prefix = f"{host}:{port}/"
        discovered = {
            value.split("?", 1)[0]
            for asset, kind, key, value in self.store.observations(self.run_id)
            if kind == "discovered_script" and asset.startswith(asset_prefix)
        }
        safe_paths = []
        for path in sorted(discovered):
            if not path.lower().endswith(".js") or not re.fullmatch(r"/[A-Za-z0-9/_.~%-]{1,255}", path):
                continue
            decoded = unquote(path)
            if any(segment in (".", "..") for segment in decoded.split("/")):
                continue
            if path not in self.scope.crawl_seeds:
                safe_paths.append(path)
        max_script_fetches = 10
        selected_paths = safe_paths[:max_script_fetches]
        if not selected_paths:
            print("JS scan: no eligible same-host .js references were found in the scoped seed page")
            return

        # This derived Scope exists only for this local-only action. It does not modify the scope
        # file, add paths to the run's authorization record, or permit any host outside loopback.
        script_scope = replace(self.scope, crawl_seeds=tuple(selected_paths))
        script_gateway = PolicyGateway(
            script_scope, {"http_get": make_http_get(script_scope)}, self.audit,
            approvals=self.approvals)
        summary = run_crawl(script_gateway, self.store, script_scope, run_id=self.run_id)
        existing_ids = {f.get("id") for f in self.store.findings_for_run(self.run_id)}
        findings = candidates_from_crawl(self.store, self.run_id)
        for finding in findings:
            self.store.save_finding(self.run_id, finding.to_dict())
            if finding.id not in existing_ids:
                self.findings.append(finding)
        print(f"JS scan: fetched {summary['calls_allowed']} script(s), {summary['calls_denied']} failed")
        if len(safe_paths) > max_script_fetches:
            print(f"JS scan: capped at {max_script_fetches} same-host scripts")
        self._write_component_report("js-assets", self.findings)
        self._maybe_auto_review([f for f in findings if f.id not in existing_ids])

    def run_local_lab_brain(self):
        """Run an evidence-driven loop over registered read-only actions for the loopback lab."""
        try:
            validate_local_lab_routine_scope(self.scope)
        except RoutineScopeError as e:
            print(f"local lab routine refused: {e}")
            return

        host = next(iter(self.scope.allowed_hosts))
        port = next(iter(self.scope.allowed_ports))
        runners = {
            "run_assessment": self.run_assessment,
            "run_content_discovery": self.run_content_discovery_action,
            "run_crawl": self.run_crawl_action,
            "generate_proposals": self.generate_proposals,
        }
        remaining = [a for a in build_actions(self.scope) if a.kind == "batch" and a.read_only
                     and (a.tool != "generate_proposals" or not self.auto_review)]
        completed = set()
        core_actions = {"run_assessment", "run_content_discovery", "run_crawl"}
        max_steps = len(remaining)
        planner_model = self.a.reasoning_model or self.a.model

        for step in range(1, max_steps + 1):
            findings = self.store.findings_for_run(self.run_id)
            core_remaining = core_actions - completed
            available_now = [a for a in remaining if not core_remaining or a.name in core_remaining]
            context = {
                "objective": "Complete each available core read-only action once for this local lab, "
                             "choosing the order based on current findings and evidence. Then stop. "
                             "Ask a human if the scope or next step is unclear.",
                "engagement_id": self.scope.engagement_id,
                "run_id": self.run_id,
                "step": step,
                "completed_actions": sorted(completed),
                "core_actions_remaining": sorted(core_actions - completed),
                "findings": [{k: f.get(k) for k in ("id", "title", "status", "confidence", "asset")}
                             for f in findings[-20:]],
                "recent_tool_calls": self.store.tool_calls(self.run_id)[-20:],
            }
            evidence_text = evidence_as_text(build_evidence(self.store, self.run_id))
            try:
                recommendation, _stats = ActionPlanner(
                    OllamaClient(planner_model, host=self.a.ollama)
                ).recommend(available_now, context, evidence_text=evidence_text)
            except (OSError, ActionPlanningError) as e:
                self.store.record_action_event(
                    self.run_id, "brain_error", tool="action_planner", decision="stopped",
                    outcome=type(e).__name__, details={"error": str(e)[:500], "step": step,
                                                       "model": planner_model})
                print(f"[brain] stopped; planning failed ({type(e).__name__}: {e})")
                break

            choice = recommendation["action"]
            if choice in ("stop", "ask_human"):
                self.store.record_action_event(
                    self.run_id, "planner_control", action_name=choice,
                    rationale=recommendation["rationale"], decision=choice,
                    outcome="no action dispatched", details={"step": step, "model": planner_model})
                print(f"[brain] {choice}: {recommendation['rationale']}")
                break

            spec = recommendation["spec"]
            self.store.record_action_event(
                self.run_id, "brain_decision", action_name=spec.name, tool=spec.tool,
                args={"host": host, "port": port}, rationale=recommendation["rationale"],
                decision="selected", outcome="local read-only action",
                details={"step": step, "model": planner_model})
            runner = runners.get(spec.tool)
            if runner is None:
                self.store.record_action_event(
                    self.run_id, "brain_error", action_name=spec.name, decision="stopped",
                    outcome="no local session handler registered", details={"step": step})
                print(f"[brain] stopped; no handler for {spec.name}")
                break

            before_calls = {row["id"] for row in self.store.tool_call_rows(self.run_id)}
            before_findings = {f.get("id") for f in self.store.findings_for_run(self.run_id)}
            self.store.record_action_event(
                self.run_id, "routine_step_started", action_name=spec.name, tool=spec.tool,
                args={"host": host, "port": port},
                decision="operator-started loopback routine", outcome=f"step {step}")
            print(f"[brain {step}/{max_steps}] selected {spec.name}: {recommendation['rationale']}")
            try:
                runner()
                if spec.tool == "run_crawl":
                    self.scan_local_js_assets()
            except Exception as e:
                self.store.record_action_event(
                    self.run_id, "routine_step_finished", action_name=spec.name, tool=spec.tool,
                    args={"host": host, "port": port},
                    decision="stopped", outcome="handler raised an exception",
                    details={"error_type": type(e).__name__, "error": str(e)[:500], "step": step})
                print(f"[brain {step}/{max_steps}] stopped ({type(e).__name__}: {e})")
                break

            after_calls = self.store.tool_call_rows(self.run_id)
            after_findings = {f.get("id") for f in self.store.findings_for_run(self.run_id)}
            new_calls = [row for row in after_calls if row["id"] not in before_calls]
            new_finding_ids = sorted(x for x in after_findings - before_findings if x)
            failed_calls = [row for row in new_calls if not row["allowed"]]
            outcome = "completed"
            if new_calls and len(failed_calls) == len(new_calls):
                outcome = "all tool calls failed; remaining routine stages skipped"
            self.store.record_action_event(
                self.run_id, "routine_step_finished", action_name=spec.name, tool=spec.tool,
                args={"host": host, "port": port},
                decision="completed" if outcome == "completed" else "stopped",
                outcome=outcome,
                details={"tool_call_ids": [row["id"] for row in new_calls],
                         "successful_calls": len(new_calls) - len(failed_calls),
                         "failed_calls": len(failed_calls), "finding_ids": new_finding_ids,
                         "step": step})
            print(f"[brain {step}/{max_steps}] {outcome}; {len(new_calls) - len(failed_calls)} successful tool call(s), "
                  f"{len(failed_calls)} failed, {len(new_finding_ids)} new finding(s)")
            completed.add(spec.name)
            remaining = [a for a in remaining if a.name != spec.name]
            self._write_component_report("agent", self.findings)
            if outcome != "completed":
                break

    def _maybe_auto_review(self, new_findings):
        """Called after every data-gathering action. Only fires when self.auto_review is on AND
        this action actually produced something candidate-status (no point spending a model call
        reviewing an all-clear/informational batch)."""
        if self.auto_review and any(f.status == "candidate" for f in new_findings):
            self._run_ai_pipeline(auto=True)

    def open_proposals(self):
        path = ask(f"path to proposals-run<id>.json [{self.doc_path or 'reports/proposals-run<id>.json'}]: ") or self.doc_path
        if not path:
            print("no path given")
            return
        try:
            with open(path, encoding="utf-8") as f:
                self.doc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"could not load {path}: {e}")
            return
        self.doc_path = path
        self.handled = set()
        print(f"loaded {path} (model={self.doc.get('model')}, generated for run_id={self.doc.get('run_id')})")

    def review(self):
        if self.doc is None:
            print("no proposals loaded - use [4a] to generate or [4b] to open an existing file first")
            return
        pending = [(h, p) for h in self.doc["hypotheses"] for p in h["payloads"] if p["id"] not in self.handled]
        if not pending:
            print("nothing left to review in the loaded file (use [4a]/[4b] to load another)")
            return
        for h, p in pending:
            print(f"\n--- {p['id']} (hypothesis {h['id']}) ---")
            print(f"  target:       {h['path']}?{h['parameter']}  (weakness_type={h['weakness_type']}, confidence={h['confidence']})")
            print(f"  rationale:    {h['rationale']}")
            print(f"  category:     {p['category']}")
            print(f"  payload:      {p['payload']!r}")
            print(f"  expected:     {p['expected_signal']}")
            print(f"  why:          {p['rationale']}")
            try:
                resolved = resolve_from_file(self.doc, p["id"], self.scope)
            except ProposalExecutionError as e:
                if p["category"] in NON_EXECUTABLE_CATEGORIES:
                    print(f"  [no restricted adapter for {p['category']!r} - this stays suggested_only]")
                    self._maybe_log_manual_outcome(h, p)
                else:
                    print(f"  [skipped: {e}]")
                    self.handled.add(p["id"])
                continue
            print(f"  resolved call: {resolved.tool} {resolved.args}")
            choice = ask("  approve and execute this EXACT call? [y/N/s=stop reviewing]: ").lower()
            if choice == "s":
                return
            self.handled.add(p["id"])
            if choice != "y":
                print("  skipped")
                continue
            r = self.gateway.execute(resolved.tool, resolved.args, proposed_by=f"proposal:{resolved.hypothesis_id}")
            if not r["ok"] and r.get("error") == "approval required":
                self.approvals.decide(r["approval_request_id"], approve=True, who=getpass.getuser())
                r = self.gateway.execute(resolved.tool, resolved.args, proposed_by=f"proposal:{resolved.hypothesis_id}")
            call_id = self.store.record_tool_call(self.run_id, resolved.tool, resolved.args, r)
            if not r["ok"]:
                print(f"  NOT RUN - {r['error']}")
                continue
            sha = self.store.tool_call_row(call_id)["output_sha256"]
            host, port = resolved.args["host"], resolved.args["port"]
            param_or_field = resolved.args.get("param") or resolved.args.get("field")
            finding = FINDING_BUILDERS[resolved.tool](call_id, sha, f"{host}:{port}", resolved.args["path"], param_or_field, r["untrusted_output"])
            self.store.save_finding(self.run_id, finding.to_dict())
            self.findings.append(finding)
            print(f"  ran. finding: {finding.id} - {finding.title} (status={finding.status})")
            receipt = {"run_id": self.run_id, "tool_call_id": call_id,
                      "proposal": {"hypothesis_id": resolved.hypothesis_id, "payload_id": resolved.payload_id, "category": resolved.category},
                      "tool": resolved.tool, "args": resolved.args, "finding": finding.to_dict()}
            os.makedirs(self.a.out, exist_ok=True)
            with open(os.path.join(self.a.out, f"proposal-execution-{resolved.payload_id}.json"), "w", encoding="utf-8") as f:
                json.dump(receipt, f, indent=2)

    def _maybe_log_manual_outcome(self, h, p):
        if ask("  log what you observed after testing this yourself? [y/N]: ").lower() != "y":
            self.handled.add(p["id"])
            return
        self._log_outcome(p["id"])

    def log_outcome_action(self):
        """[4d] Log an outcome for a payload id, independent of the review loop above (e.g. for a
        payload you tested outside this session). Same effect as scripts/log_proposal_outcome.py."""
        if self.doc is None:
            self.open_proposals()
            if self.doc is None:
                return
        payload_id = ask("payload id (P-...): ")
        self._log_outcome(payload_id)
        self.handled.add(payload_id)

    def _log_outcome(self, payload_id):
        outcome = ask(f"  outcome {OUTCOMES}: ")
        tested_by = ask("  tested by: ") or getpass.getuser()
        observed = ask("  observed result: ")
        try:
            record = build_outcome_record(self.doc, payload_id, outcome, tested_by, observed)
        except ProposalOutcomeError as e:
            print(f"  not logged: {e}")
            return
        self.store.record_proposal_outcome(**record)
        print("  logged.")

    # ================= 5. Manual confirmation of a Finding =================
    def manual_confirm_action(self):
        finding_id = ask("finding id (F-...): ")
        run_id, finding = self.store.get_finding(finding_id)
        if finding is None:
            print(f"no finding {finding_id} in {self.a.db}")
            return
        performed_by = ask("performed by: ") or getpass.getuser()
        action_description = ask("action performed: ")
        payload_sent = ask("payload sent (verbatim): ")
        observed_result = ask("observed result (verbatim): ")
        notes = ask("notes (optional): ")
        try:
            updated = apply_manual_action(finding, performed_by, action_description, payload_sent, observed_result, notes)
        except ManualConfirmError as e:
            print(f"not recorded: {e}")
            return
        self.store.add_manual_action(finding_id, performed_by, action_description, payload_sent, observed_result, notes)
        self.store.save_finding(run_id, updated)
        os.makedirs(self.a.out, exist_ok=True)
        base = os.path.join(self.a.out, f"manual-confirmation-{finding_id}")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(updated, f, indent=2)
        with open(base + ".md", "w", encoding="utf-8") as f:
            f.write(finding_markdown(updated))
        print(f"finding {finding_id} status is now: {updated['status']} - wrote {base}.json/.md")

    # ================= 6. Knowledge base =================
    def kb_update_action(self):
        source = ask(f"source {tuple(sorted(KB_SOURCES))}: ")
        if source not in KB_SOURCES:
            print("unknown source")
            return
        local = ask("local file path (blank to download from the network): ")
        os.makedirs(os.path.dirname(self.a.kb), exist_ok=True)
        if local:
            with open(local, "rb") as f:
                url, raw = "local-file:" + os.path.basename(local), f.read()
        else:
            url, raw = fetch_source(source)
        print(json.dumps(kb_ingest(KBStore(self.a.kb), source, raw, url, self.a.raw_dir), indent=2))

    def kb_validate_mapping_action(self):
        m = load_mapping(self.a.mapping)
        print("structural problems:", check_mapping(m) or "none")
        for r in check_against_kb(m, KBStore(self.a.kb)):
            print(f"{r['rule']:<45} {r['cwe_id']:<9} [{r['review_status']}] {r['name']}  ({r['status']}) {r['problem']}")

    # ================= 7. Settings =================
    def show_settings(self):
        print(json.dumps({"scope_file": self.a.scope, "engagement_id": self.scope.engagement_id, "run_id": self.run_id,
                          "source_run_id": self.source_run_id, "generation_model": self.a.model,
                          "reasoning_model": self.a.reasoning_model or f"(same as generation: {self.a.model})",
                          "auto_review": self.auto_review, "ollama": self.a.ollama,
                          "db": self.a.db, "audit": self.a.audit, "approvals": self.a.approvals,
                          "kb": self.a.kb, "mapping": self.a.mapping, "out": self.a.out}, indent=2))

    def toggle_auto_review(self):
        self.auto_review = not self.auto_review
        print(f"auto_review is now {self.auto_review}")

    def set_models(self):
        gen = ask(f"generation model [{self.a.model or '(none)'}]: ")
        if gen:
            self.a.model = gen
        reasoning = ask(f"reasoning model [{self.a.reasoning_model or '(same as generation)'}]: ")
        if reasoning:
            self.a.reasoning_model = reasoning
        print(f"generation={self.a.model}  reasoning={self.a.reasoning_model or '(same as generation)'}")

    def change_scope(self):
        path = ask("new scope file path: ")
        if not path:
            return
        try:
            new_scope = Scope.load(path)
        except (ScopeError, OSError) as e:
            print(f"could not load {path}: {e}")
            return
        self.a.scope = path
        self._bind_scope(new_scope)
        self.doc, self.doc_path, self.handled = None, None, set()
        print(f"switched to {path} (engagement={new_scope.engagement_id}); new run_id={self.run_id}")

    # ================= 8. Session summary / quit =================
    def show_summary(self):
        print(f"\nsession run_id={self.run_id}: {len(self.findings)} finding(s) produced")
        for f in self.findings:
            print(f"  {f.id}  {f.status:<13} {f.title}")
        rows = self.store.proposal_outcomes_for_run(self.run_id)
        if rows:
            print("manual outcome tally:", json.dumps(summarize(rows)))

    def finish(self):
        self._write_component_report("agent", self.findings)
        print("audit chain intact:", AuditLog.verify(self.a.audit))


HELP = """
================ FULL COMMAND REFERENCE ================
[1] Discovery & Assessment - passive, read-only HTTP/port discovery, header-based candidates,
    verification, CWE enrichment.                           (= scripts/run_assessment.py)
[2] Crawl - fetches exactly scope.crawl_seeds (read-only), reports discovered links/params/
    scripts and JS-sourced endpoint/secret heuristics.       (= scripts/run_crawl.py)
[3] Intrusive Probing
    [a] Run reflect_probe/sqli_probe/login_sqli_probe against every scope.allowed_probe_targets
        entry. First pass requests approval; rerun after [3b] to execute.  (= scripts/run_intrusive.py)
    [b] Review pending approval requests, one at a time.      (= scripts/approve.py)
    [c] Run fuzz_probe (expanded, still fixed-in-code diagnostic battery per category - NOT a
        wordlist/content discovery tool) against every non-login allowed_probe_targets entry.
        Same first-pass-requests-approval, rerun-after-[3b]-to-execute flow as [3a].
[4] AI Proposals (model proposes, nothing here executes without your y). Two-pass, proposal-only:
    a REASONING pass (--reasoning-model, [7d]) reviews current findings against real recent
    evidence (pagent.evidence - actual sanitized response content, not just status/length) and
    decides what's worth a closer look; a GENERATION pass (--model, [7d]) then proposes
    hypotheses+payloads only for that reviewed subset, with the same evidence attached. The two
    passes can be different models - Ollama loads/unloads whichever is requested per call. Runs
    AUTOMATICALLY after any data-gathering action ([1]/[2]/[3a]/[3c]/[9]) that produced a
    candidate finding, unless disabled with --no-auto-review or toggled off at [7c].
    [a] Generate hypotheses + payload proposals from findings so far (manual trigger).
                                                                    (= scripts/propose_tests.py)
    [b] Open an existing proposals-run<id>.json file instead.
    [c] Review each pending payload; y resolves + approves + executes the exact restricted-adapter
        call; non-executable categories (e.g. boolean_pair) offer manual outcome logging.
                                                               (= scripts/execute_proposal.py + approve.py)
    [d] Log an outcome for one payload id directly.           (= scripts/log_proposal_outcome.py)
[5] Manual Confirmation - record a human-performed test (browser/curl/Burp) against an existing
    Finding; never sends anything itself.                     (= scripts/log_manual_action.py)
[6] Knowledge Base
    [a] Update KB from CISA KEV or MITRE CWE (network or a local file).  (= scripts/kb_update.py)
    [b] Validate config/cwe_mapping.json against the KB.      (= scripts/validate_mapping.py)
[7] Settings
    [a] Show current scope/paths/models/run_id/auto_review.
    [b] Switch to a different scope file (starts a new run_id under it).
    [c] Toggle auto-review on/off.
    [d] Set the generation and/or reasoning model names.
[8] Session summary - findings produced + manual-outcome tally so far this session.
[9] Content Discovery - GETs scope.discovery_prefixes x the small, checked-in wordlist
    (config/content_discovery_wordlist.json), read-only, no approval needed, no external tool.
    Reports anything that responded other than 404.          (= scripts/run_content_discovery.py)
[10] AI next-action recommendation - chooses one action from the current scope registry. A
     read-only batch action runs only after you confirm; targeted actions remain in the intrusive
     menu and approval flow. A batch action may make multiple calls defined by its existing method.
[--lab-brain] Runs the evidence-driven, read-only local lab loop in one launch. It requires a model
     and accepts only a single loopback host and one port; --lab-routine remains an alias.
[h] This help.   [q] Quit - writes a combined report over every Finding from this session.
==========================================================
"""

MAIN_MENU = """
 [1] Discovery & Assessment      [2] Crawl
 [3] Intrusive Probing >         [4] AI Proposals >
 [5] Manual Confirmation         [6] Knowledge Base >
 [7] Settings >                  [8] Session summary
 [9] Content Discovery           [10] AI next-action recommendation
 [h] Help                        [q] Quit
"""


def submenu(title, items, back_label="[back] return to main menu"):
    """items: {code: (label, callable)}. Loops until 'back'/'q'."""
    print(title)
    for code, (label, _) in items.items():
        print(f"  [{code}] {label}")
    print(f"  {back_label}")
    while True:
        choice = ask(f"{title.strip()}> ").lower()
        if choice in ("back", "q", ""):   # NOT "b" - several submenus use b/c/d as real item codes
            return
        entry = items.get(choice)
        if entry is None:
            print(title)
            for code, (label, _) in items.items():
                print(f"  [{code}] {label}")
            print(f"  {back_label}")
            continue
        entry[1]()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--model", help="Ollama model name for the GENERATION pass (hypotheses + payloads); "
                                    "if omitted you'll be asked once, only when you choose [4a]")
    ap.add_argument("--reasoning-model", help="Ollama model name for the REASONING/triage pass that decides "
                                              "which findings are worth generating hypotheses for; defaults "
                                              "to --model if omitted. Can be a different, smaller/faster model - "
                                              "Ollama loads/unloads whichever is requested per call.")
    ap.add_argument("--no-auto-review", action="store_true",
                    help="disable automatic review+proposal generation after each data-gathering action "
                         "(discovery/crawl/fuzzing/content discovery/intrusive probing); still available "
                         "manually via [4a]")
    ap.add_argument("--lab-brain", "--lab-routine", dest="lab_brain", action="store_true",
                    help="run the evidence-driven read-only brain loop for a validated loopback lab scope and exit")
    ap.add_argument("--ollama", default="http://127.0.0.1:11434")
    ap.add_argument("--db", default="data/pentest.db")
    ap.add_argument("--audit", default="audit/audit.jsonl")
    ap.add_argument("--approvals", default="data/approvals.db")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--kb", default="data/kb.db")
    ap.add_argument("--mapping", default="config/cwe_mapping.json")
    ap.add_argument("--raw-dir", default="data/kb/raw")
    ap.add_argument("--include-proposed", action="store_true", help="assessment: also attach CWE mappings not yet marked reviewed")
    a = ap.parse_args()
    if a.lab_brain:
        if not a.model and a.reasoning_model:
            a.model = a.reasoning_model
        if not a.model:
            ap.error("--lab-brain requires --model or --reasoning-model")
        try:
            validate_local_lab_routine_scope(Scope.load(a.scope))
        except (OSError, ScopeError, RoutineScopeError) as e:
            ap.error(f"--lab-brain scope rejected: {e}")
    for p in (a.db, a.audit, a.approvals, a.kb):
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    os.makedirs(a.out, exist_ok=True)

    s = Session(a)
    print(f"session run_id={s.run_id}  scope={a.scope}  engagement={s.scope.engagement_id}")
    if a.lab_brain:
        try:
            s.run_local_lab_brain()
        finally:
            s.finish()
        return
    print(MAIN_MENU)
    while True:
        choice = ask("> ").lower()
        if choice == "q":
            break
        elif choice == "h":
            print(HELP)
        elif choice == "1":
            s.run_assessment()
        elif choice == "2":
            s.run_crawl_action()
        elif choice == "3":
            submenu("Intrusive Probing", {"a": ("Run probes against all allowed_probe_targets", s.run_intrusive_targets),
                                          "b": ("Review pending approvals", s.review_approvals),
                                          "c": ("Run payload fuzzing against all allowed_probe_targets", s.run_fuzz_targets)})
        elif choice == "4":
            submenu("AI Proposals", {"a": ("Generate proposals", s.generate_proposals),
                                     "b": ("Open an existing proposals file", s.open_proposals),
                                     "c": ("Review pending payloads", s.review),
                                     "d": ("Log an outcome for one payload id", s.log_outcome_action)})
        elif choice == "5":
            s.manual_confirm_action()
        elif choice == "6":
            submenu("Knowledge Base", {"a": ("Update KB (kev/cwe)", s.kb_update_action),
                                       "b": ("Validate CWE mapping", s.kb_validate_mapping_action)})
        elif choice == "7":
            submenu("Settings", {"a": ("Show current settings", s.show_settings),
                                 "b": ("Switch scope file", s.change_scope),
                                 "c": ("Toggle auto-review (currently: " + str(s.auto_review) + ")", s.toggle_auto_review),
                                 "d": ("Set generation/reasoning models", s.set_models)})
        elif choice == "8":
            s.show_summary()
        elif choice == "9":
            s.run_content_discovery_action()
        elif choice == "10":
            s.recommend_next_action()
        else:
            print(MAIN_MENU)
    s.finish()


if __name__ == "__main__":
    main()
