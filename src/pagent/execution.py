"""Approved Proposal -> Restricted Tool Call mapping.

This module computes, from an already-generated proposals-run<id>.json file, the single
(tool_name, args) call that a human is being asked to approve for ONE payload id. It never talks
to the network, never imports pagent.policy or pagent.approvals, and has no execution path itself -
scripts/execute_proposal.py owns the actual PolicyGateway call, the same way scripts/run_intrusive.py
(not pagent.intrusive) owns it for the deterministic probes.

Why this is not a "payload string -> adapter" mapping:
sqli_probe, login_sqli_probe and reflect_probe (see pagent.tools) each already send a FIXED,
internally-generated diagnostic value on every call. None of their arg_schema accepts a
caller-supplied payload/value at all - that was true before this module existed and is not changed
by it. So there is no "pass the model's exact string through to the adapter" option on the table
for these three tools; the only real decision is which existing fixed-shape adapter applies to a
given (category, path, parameter). That is what CATEGORY_TOOL below encodes, and it is derived
from deterministic facts only (the scope file's allowed_probe_targets, and pagent.intrusive.LOGIN_TARGETS)
- never from the model's free-text payload/expected_signal/rationale fields. Those fields are
carried through unread into the human-facing approval context and the eventual evidence record;
they are not inputs to tool or argument selection.

boolean_pair has no adapter (classify() in pagent.tools.sqli_probe already performs quote-pair
boolean comparison on every sqli_probe/login_sqli_probe call, so "boolean_pair" as its own,
separate operation - e.g. a tautology payload - is simply not implemented anywhere in this
project). It is rejected here with a clear, stable reason instead of silently vanishing, so it
stays visible for manual review (see pagent.suggestions.outcomes) until an adapter for it is
explicitly designed, reviewed and tested.

A stored proposals-run<id>.json file is treated as untrusted input here, exactly like raw model
output is treated as untrusted input in pagent.proposals: it lives on disk and could have been
hand-edited between generation and execution, so every field this module relies on is re-validated
rather than trusted.
"""
from __future__ import annotations

from dataclasses import dataclass

from .intrusive import LOGIN_TARGETS
from .proposals import PAYLOAD_CATEGORIES, recompute_hypothesis_id, recompute_payload_id
from .scope import Scope
from .suggestions.outcomes import find_payload

# category -> tool, for an ordinary query-string parameter target. A target in LOGIN_TARGETS
# overrides this for quote_break only (see resolve_tool_call).
CATEGORY_TOOL = {
    "quote_break": "sqli_probe",
    "reflection_marker": "reflect_probe",
    "html_context_marker": "reflect_probe",
}
# Categories pagent.proposals accepts as suggestions but that no restricted adapter implements.
# Never add a category here and to CATEGORY_TOOL at the same time.
NON_EXECUTABLE_CATEGORIES = {"boolean_pair"}


class ProposalExecutionError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedCall:
    tool: str
    args: dict
    hypothesis_id: str
    payload_id: str
    category: str


def _require_unedited(h: dict, p: dict) -> None:
    """Fail closed if the stored ids no longer match what their own content hashes to - the
    cheapest possible defense against a hand-edited proposals-run file being used to smuggle a
    different path/parameter/category/payload past review under an id a human already saw."""
    try:
        recomputed_h = recompute_hypothesis_id(h)
        recomputed_p = recompute_payload_id(recomputed_h, p)
    except KeyError as e:
        raise ProposalExecutionError(f"hypothesis/payload missing expected field: {e}") from e
    if recomputed_h != h.get("id"):
        raise ProposalExecutionError("hypothesis content does not match its id; file may have been edited")
    if recomputed_p != p.get("id"):
        raise ProposalExecutionError("payload content does not match its id; file may have been edited")


def _require_still_proposal_only(p: dict) -> None:
    if p.get("execution_state") != "suggested_only" or not p.get("requires_approval", True):
        raise ProposalExecutionError("payload is not marked suggested_only/requires_approval; refusing to execute")


def resolve_tool_call(hypothesis: dict, payload: dict, scope: Scope) -> ResolvedCall:
    """Deterministically map one already-looked-up (hypothesis, payload) pair, PLUS the active
    scope, to an exact (tool, args). Reads payload['category'] to choose the tool; never reads
    payload['payload'] for that purpose. host/port are not proposal fields - like
    scripts/run_intrusive.py, this project's scope files name exactly one lab target, so the
    single allowed host and the lowest allowed port are used; add host/port disambiguation here
    first if a scope file is ever given more than one of either."""
    _require_unedited(hypothesis, payload)
    _require_still_proposal_only(payload)

    category = payload["category"]
    weakness_type = hypothesis["weakness_type"]
    path, param = hypothesis["path"], hypothesis["parameter"]

    if weakness_type not in PAYLOAD_CATEGORIES or category not in PAYLOAD_CATEGORIES[weakness_type]:
        raise ProposalExecutionError(f"category {category!r} is not valid for weakness_type {weakness_type!r}")
    if category in NON_EXECUTABLE_CATEGORIES:
        raise ProposalExecutionError(
            f"category {category!r} has no restricted adapter yet; it stays suggested_only - "
            "log a manual outcome instead (see pagent.suggestions.outcomes)")
    if not scope.check_probe_target(path, param):
        raise ProposalExecutionError(f"{path}?{param} is not in allowed_probe_targets")

    if (path, param) in LOGIN_TARGETS:
        if category != "quote_break":
            raise ProposalExecutionError(f"{path}?{param} is a login target; only quote_break is executable there")
        if "login_sqli_probe" not in scope.allowed_tools:
            raise ProposalExecutionError("login_sqli_probe is not in scope.allowed_tools")
        args = {"host": _single_host(scope), "port": _single_port(scope), "path": path, "field": param}
        return ResolvedCall(tool="login_sqli_probe", args=args, hypothesis_id=hypothesis["id"],
                            payload_id=payload["id"], category=category)

    tool = CATEGORY_TOOL[category]
    if tool not in scope.allowed_tools:
        raise ProposalExecutionError(f"{tool} is not in scope.allowed_tools")
    args = {"host": _single_host(scope), "port": _single_port(scope), "path": path, "param": param}
    return ResolvedCall(tool=tool, args=args, hypothesis_id=hypothesis["id"], payload_id=payload["id"], category=category)


def _single_host(scope: Scope) -> str:
    return sorted(scope.allowed_hosts)[0] if scope.allowed_hosts else "localhost"


def _single_port(scope: Scope) -> int:
    return min(scope.allowed_ports)


def resolve_from_file(proposals_doc: dict, payload_id: str, scope: Scope) -> ResolvedCall:
    """Convenience wrapper: look up payload_id (reusing the same lookup
    pagent.suggestions.outcomes.find_payload already uses for manual outcome logging, so there is
    only one place that knows how to find a payload inside a proposals-run file), then resolve.
    This is the one function scripts/execute_proposal.py needs to call."""
    try:
        h, p = find_payload(proposals_doc, payload_id)
    except Exception as e:   # pagent.suggestions.outcomes.ProposalOutcomeError, kept decoupled from this module
        raise ProposalExecutionError(str(e)) from e
    return resolve_tool_call(h, p, scope)
