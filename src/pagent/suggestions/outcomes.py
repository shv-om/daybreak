"""Proposal outcome tracking.

This module records what a HUMAN observed after manually trying a model-suggested payload
against the authorized lab target - it never sends anything to any target itself, and it never
mutates a Finding (use pagent.manual_confirm / scripts/log_manual_action.py for that, once a
signal is confirmed and you want the finding itself updated). Its only job is to let a
PayloadProposal be marked with what actually happened, so suggestion quality can be measured
over time instead of just felt.
"""
from __future__ import annotations

from ..parse import sanitize

OUTCOMES = ("confirmed_signal", "no_signal", "inconclusive", "false_lead")
REQUIRED = ("tested_by", "observed_result")


class ProposalOutcomeError(ValueError):
    pass


def find_payload(proposals: dict, payload_id: str) -> tuple:
    """Looks up a payload_id inside a loaded proposals-run<id>.json dict. Returns
    (hypothesis, payload) dicts. Raises if not found - an outcome can't be logged against a
    payload that was never actually suggested."""
    for h in proposals.get("hypotheses", []):
        for p in h.get("payloads", []):
            if p.get("id") == payload_id:
                return h, p
    raise ProposalOutcomeError(f"no payload with id {payload_id!r} in this proposals file")


def build_outcome_record(proposals: dict, payload_id: str, outcome: str, tested_by: str,
                         observed_result: str, notes: str = "") -> dict:
    """Pure function: validates inputs and returns the record to store. Takes/returns dicts only;
    no I/O, no network, no Finding mutation."""
    if outcome not in OUTCOMES:
        raise ProposalOutcomeError(f"outcome must be one of {OUTCOMES}")
    values = {"tested_by": tested_by, "observed_result": observed_result}
    empty = [k for k, v in values.items() if not str(v).strip()]
    if empty:
        raise ProposalOutcomeError(f"required and cannot be empty: {empty}")
    hypothesis, payload = find_payload(proposals, payload_id)
    return {
        "run_id": proposals.get("run_id"),
        "model": proposals.get("model"),
        "hypothesis_id": hypothesis["id"],
        "payload_id": payload["id"],
        "weakness_type": hypothesis["weakness_type"],
        "category": payload["category"],
        "payload_text": payload["payload"],          # copied from the proposal, never re-typed
        "outcome": outcome,
        "tested_by": sanitize(tested_by, 100),
        "observed_result": sanitize(observed_result, 2000),
        "notes": sanitize(notes, 1000),
    }


def summarize(outcome_rows: list) -> dict:
    """outcome_rows: Store.proposal_outcomes_for_run()-shaped dicts. A simple precision-style
    breakdown - how many of the payloads someone actually tested turned out to matter."""
    total = len(outcome_rows)
    counts = {o: 0 for o in OUTCOMES}
    for r in outcome_rows:
        if r["outcome"] in counts:
            counts[r["outcome"]] += 1
    confirmed = counts["confirmed_signal"]
    return {
        "total_tested": total,
        "counts": counts,
        "confirmed_rate": round(confirmed / total, 3) if total else None,
    }
