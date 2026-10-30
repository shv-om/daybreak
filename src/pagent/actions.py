"""Phase 2 of the agentic build plan: the unified action registry.

One place describing every action a model (or a human) could pick next for a given scope -
generated FROM the live Scope (and the same dispatch logic pagent.intrusive/pagent.tools already
use), never hand-duplicated, so it can't drift out of sync with what PolicyGateway would actually
accept. No loop consumes this yet (that's Phase 3) - this module only describes what's available.

Describing an action here does not grant it: PolicyGateway.evaluate() still independently
re-checks scope/cross_check/approval for every real tool call, exactly as today. This registry is
a menu, not a permission.

Two kinds of entries:
  - BATCH actions: coarse, no target argument needed (run_assessment / run_crawl /
    run_content_discovery / generate_proposals). These already loop over every in-scope target
    internally - the exact same methods scripts/agent.py's menu already calls - so this module
    doesn't reimplement that looping, only describes when each one is usable and whether it ever
    needs human approval (none of them do: they're built from read_only tool calls, or in
    generate_proposals' case, the AI proposal pipeline itself, which never executes anything).
  - TARGETED actions: one entry per concrete (tool, host, port, path, parameter[, category]) this
    scope currently authorizes for an approval-gated tool (sqli_probe / reflect_probe /
    login_sqli_probe / fuzz_probe), generated from scope.allowed_probe_targets using the exact
    same login-vs-non-login dispatch pagent.intrusive.LOGIN_TARGETS already defines for
    scripts/run_intrusive.py - never a second copy of that logic.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from .intrusive import LOGIN_TARGETS
from .tools.fuzz_probe import CATEGORIES as FUZZ_CATEGORIES

BATCH_DESCRIPTIONS = {
    "run_assessment": "Passive discovery: HEAD requests, open ports, security headers. Read-only, no approval needed.",
    "run_crawl": "Fetch every scope.crawl_seeds path and extract links/params/JS signals. Read-only, no approval needed.",
    "run_content_discovery": ("GET scope.discovery_prefixes x the checked-in wordlist for common filenames. "
                              "Read-only, no approval needed."),
    "generate_proposals": ("Ask the model (two-pass: review then generate) for test hypotheses + payload "
                           "proposals from findings so far. Produces suggestions only - never executes anything."),
}
TARGETED_DESCRIPTIONS = {
    "sqli_probe": "Boolean/quote-break SQL injection probe, GET query parameter. REQUIRES APPROVAL.",
    "reflect_probe": "Single-marker reflected-input (XSS signal) probe, GET query parameter. REQUIRES APPROVAL.",
    "login_sqli_probe": "Boolean/quote-break SQL injection probe against a login JSON body field. REQUIRES APPROVAL.",
    "fuzz_probe": "Expanded fixed-value diagnostic battery for one category. REQUIRES APPROVAL.",
}


@dataclass(frozen=True)
class ActionSpec:
    name: str          # unique key the model/caller picks by, e.g. "sqli_probe:/rest/user/login#email"
    kind: str           # "batch" | "targeted"
    tool: str            # underlying tool or Session-method name, e.g. "sqli_probe", "run_crawl"
    description: str      # natural-language, for a model or a human
    read_only: bool        # mirrors ToolSpec.read_only / whether this ever requires ApprovalStore approval
    args: dict = field(default_factory=dict)   # concrete, ready-to-use args for a targeted action; empty for batch


def _host_port(scope):
    host = sorted(scope.allowed_hosts)[0] if scope.allowed_hosts else "localhost"
    port = min(scope.allowed_ports) if scope.allowed_ports else None
    return host, port


def build_actions(scope) -> list:
    """Every ActionSpec currently available for this scope. Batch actions whose own precondition
    holds (mirroring the exact guards scripts/agent.py's action methods already enforce), plus one
    targeted action per (tool, allowed_probe_targets entry, [category]) the scope's allowed_tools
    actually permits - skipping any tool not present in scope.allowed_tools, the same way
    PolicyGateway.evaluate() would deny it regardless of what this registry said."""
    host, port = _host_port(scope)
    actions = []

    actions.append(ActionSpec("run_assessment", "batch", "run_assessment", BATCH_DESCRIPTIONS["run_assessment"], True))
    if scope.crawl_seeds:
        actions.append(ActionSpec("run_crawl", "batch", "run_crawl", BATCH_DESCRIPTIONS["run_crawl"], True))
    if scope.discovery_prefixes and "dir_probe" in scope.allowed_tools:
        actions.append(ActionSpec("run_content_discovery", "batch", "run_content_discovery",
                                  BATCH_DESCRIPTIONS["run_content_discovery"], True))
    actions.append(ActionSpec("generate_proposals", "batch", "generate_proposals",
                              BATCH_DESCRIPTIONS["generate_proposals"], True))

    if scope.intrusive_allowed:
        for path, param in sorted(scope.allowed_probe_targets):
            if (path, param) in LOGIN_TARGETS:
                if "login_sqli_probe" in scope.allowed_tools:
                    args = {"host": host, "port": port, "path": path, "field": param}
                    actions.append(ActionSpec(f"login_sqli_probe:{path}#{param}", "targeted", "login_sqli_probe",
                                              TARGETED_DESCRIPTIONS["login_sqli_probe"], False, args))
                continue
            if "sqli_probe" in scope.allowed_tools:
                args = {"host": host, "port": port, "path": path, "param": param}
                actions.append(ActionSpec(f"sqli_probe:{path}#{param}", "targeted", "sqli_probe",
                                          TARGETED_DESCRIPTIONS["sqli_probe"], False, args))
            if "reflect_probe" in scope.allowed_tools:
                args = {"host": host, "port": port, "path": path, "param": param}
                actions.append(ActionSpec(f"reflect_probe:{path}#{param}", "targeted", "reflect_probe",
                                          TARGETED_DESCRIPTIONS["reflect_probe"], False, args))
            if "fuzz_probe" in scope.allowed_tools:
                for category in FUZZ_CATEGORIES:
                    args = {"host": host, "port": port, "path": path, "param": param, "category": category}
                    actions.append(ActionSpec(f"fuzz_probe:{path}#{param}:{category}", "targeted", "fuzz_probe",
                                              TARGETED_DESCRIPTIONS["fuzz_probe"], False, args))
    return actions


def actions_as_text(actions: list) -> str:
    """Plain, numbered-by-order text rendering for a model prompt (Phase 3). Not untrusted - every
    byte here is derived from Scope + code, nothing a target ever supplied, so this does NOT go
    through request_structured's untrusted_context (unlike pagent.evidence.evidence_as_text)."""
    lines = []
    for a in actions:
        tier = "read-only, auto-runs" if a.read_only else "REQUIRES APPROVAL"
        line = f"- {a.name}  [{tier}]: {a.description}"
        if a.args:
            line += f"  args={a.args}"
        lines.append(line)
    return "\n".join(lines)
