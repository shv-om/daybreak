"""Contextual hypothesis and payload proposals.

This module is deliberately proposal-only. It does not import the policy gateway, approvals,
or any tool adapter, and it has no execution path. Model output is treated as untrusted data,
validated against the authorization scope, then normalized for human review.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field


class ContextProposalError(ValueError):
    pass


WEAKNESS_TYPES = ("reflected_input", "sql_injection")
PAYLOAD_CATEGORIES = {
    "reflected_input": ("reflection_marker", "html_context_marker"),
    "sql_injection": ("quote_break", "boolean_pair"),
}
CONFIDENCE_LEVELS = ("low", "medium", "high")
MAX_HYPOTHESES = 4
MAX_PAYLOADS_PER_HYPOTHESIS = 3
MAX_PAYLOAD_LEN = 256


def contextual_proposal_schema() -> dict:
    payload = {
        "type": "object",
        "properties": {
            "payload": {"type": "string", "maxLength": MAX_PAYLOAD_LEN},
            "category": {"type": "string", "enum": sorted({c for v in PAYLOAD_CATEGORIES.values() for c in v})},
            "expected_signal": {"type": "string", "maxLength": 500},
            "rationale": {"type": "string", "maxLength": 1000},
        },
        "required": ["payload", "category", "expected_signal", "rationale"],
        "additionalProperties": False,
    }
    hypothesis = {
        "type": "object",
        "properties": {
            "weakness_type": {"type": "string", "enum": list(WEAKNESS_TYPES)},
            "path": {"type": "string"},
            "parameter": {"type": "string"},
            "rationale": {"type": "string", "maxLength": 1000},
            "confidence": {"type": "string", "enum": list(CONFIDENCE_LEVELS)},
            "evidence_refs": {"type": "array", "items": {"type": "string"}, "maxItems": 12},
            "payloads": {"type": "array", "items": payload, "maxItems": MAX_PAYLOADS_PER_HYPOTHESIS},
        },
        "required": ["weakness_type", "path", "parameter", "rationale", "confidence", "evidence_refs", "payloads"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "hypotheses": {"type": "array", "items": hypothesis, "maxItems": MAX_HYPOTHESES},
        },
        "required": ["hypotheses"],
        "additionalProperties": False,
    }


def _stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(parts).encode()
    return prefix + hashlib.sha256(raw).hexdigest()[:12]


@dataclass(frozen=True)
class PayloadProposal:
    id: str
    hypothesis_id: str
    payload: str
    category: str
    expected_signal: str
    rationale: str
    requires_approval: bool = True
    execution_state: str = "suggested_only"


@dataclass(frozen=True)
class TestHypothesis:
    id: str
    weakness_type: str
    path: str
    parameter: str
    rationale: str
    confidence: str
    evidence_refs: list[str] = field(default_factory=list)
    payloads: list[PayloadProposal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _require_exact_keys(obj: dict, expected: set[str], where: str) -> None:
    if not isinstance(obj, dict) or set(obj) != expected:
        raise ContextProposalError(f"{where}: wrong keys")


def parse_contextual_output(obj_or_text) -> dict:
    """Parse only structural shape. Scope/evidence checks happen in validate_contextual_output()."""
    if isinstance(obj_or_text, str):
        try:
            obj = json.loads(obj_or_text)
        except json.JSONDecodeError as e:
            raise ContextProposalError("not valid JSON") from e
    else:
        obj = obj_or_text
    _require_exact_keys(obj, {"hypotheses"}, "root")
    hs = obj["hypotheses"]
    if not isinstance(hs, list) or len(hs) > MAX_HYPOTHESES:
        raise ContextProposalError("hypotheses must be a bounded list")
    hkeys = {"weakness_type", "path", "parameter", "rationale", "confidence", "evidence_refs", "payloads"}
    pkeys = {"payload", "category", "expected_signal", "rationale"}
    for i, h in enumerate(hs):
        _require_exact_keys(h, hkeys, f"hypothesis[{i}]")
        if h["weakness_type"] not in WEAKNESS_TYPES:
            raise ContextProposalError(f"hypothesis[{i}]: unsupported weakness_type")
        if not all(isinstance(h[k], str) for k in ("path", "parameter", "rationale", "confidence")):
            raise ContextProposalError(f"hypothesis[{i}]: string field has wrong type")
        if h["confidence"] not in CONFIDENCE_LEVELS:
            raise ContextProposalError(f"hypothesis[{i}]: unsupported confidence")
        if not isinstance(h["evidence_refs"], list) or not all(isinstance(x, str) for x in h["evidence_refs"]):
            raise ContextProposalError(f"hypothesis[{i}]: evidence_refs must be strings")
        ps = h["payloads"]
        if not isinstance(ps, list) or len(ps) > MAX_PAYLOADS_PER_HYPOTHESIS:
            raise ContextProposalError(f"hypothesis[{i}]: payloads must be a bounded list")
        for j, p in enumerate(ps):
            _require_exact_keys(p, pkeys, f"hypothesis[{i}].payload[{j}]")
            if not all(isinstance(p[k], str) for k in pkeys):
                raise ContextProposalError(f"hypothesis[{i}].payload[{j}]: fields must be strings")
            if not p["payload"] or len(p["payload"]) > MAX_PAYLOAD_LEN or "\x00" in p["payload"] or "\r" in p["payload"] or "\n" in p["payload"]:
                raise ContextProposalError(f"hypothesis[{i}].payload[{j}]: invalid payload")
            if p["category"] not in PAYLOAD_CATEGORIES[h["weakness_type"]]:
                raise ContextProposalError(f"hypothesis[{i}].payload[{j}]: category does not match weakness_type")
    return obj


def recompute_hypothesis_id(h: dict) -> str:
    """Recompute the H- id the same way validate_contextual_output() originally derived it, from
    a hypothesis dict as stored in a proposals-run<id>.json file. Lets a later consumer (see
    pagent.execution) detect whether a saved hypothesis was hand-edited after generation, without
    duplicating the id formula."""
    return _stable_id("H-", h["weakness_type"], h["path"], h["parameter"], h["rationale"])


def recompute_payload_id(hypothesis_id: str, p: dict) -> str:
    """Recompute the P- id for one payload dict, same formula as validate_contextual_output()."""
    return _stable_id("P-", hypothesis_id, p["category"], p["payload"], p["expected_signal"])


def validate_contextual_output(raw, scope, valid_evidence_refs=()) -> list[TestHypothesis]:
    """Validate model output against deterministic scope and known evidence references.

    A proposal outside allowed_probe_targets is rejected even though it is not executable. This keeps
    generated testing guidance aligned with the same authorization boundary used by the tool layer.
    """
    obj = parse_contextual_output(raw)
    valid_refs = set(valid_evidence_refs)
    out: list[TestHypothesis] = []
    for h in obj["hypotheses"]:
        if not scope.check_probe_target(h["path"], h["parameter"]):
            raise ContextProposalError(f"target not authorized for active probing: {h['path']}#{h['parameter']}")
        unknown = set(h["evidence_refs"]) - valid_refs
        if unknown:
            raise ContextProposalError("unknown evidence reference(s): " + ", ".join(sorted(unknown)))
        hid = _stable_id("H-", h["weakness_type"], h["path"], h["parameter"], h["rationale"])
        payloads = []
        for p in h["payloads"]:
            pid = _stable_id("P-", hid, p["category"], p["payload"], p["expected_signal"])
            payloads.append(PayloadProposal(id=pid, hypothesis_id=hid, payload=p["payload"], category=p["category"],
                                            expected_signal=p["expected_signal"], rationale=p["rationale"]))
        out.append(TestHypothesis(id=hid, weakness_type=h["weakness_type"], path=h["path"], parameter=h["parameter"],
                                  rationale=h["rationale"], confidence=h["confidence"],
                                  evidence_refs=list(h["evidence_refs"]), payloads=payloads))
    return out


SYSTEM_PROMPT = """You are a proposal-only security testing planner for an explicitly authorized local lab.
Return only the requested structured JSON. You may propose hypotheses and non-destructive candidate payloads,
but you cannot authorize or execute anything. Use only the exact authorized path+parameter pairs provided.
Do not invent evidence. evidence_refs must contain only identifiers supplied in the input. If evidence is weak,
use low confidence or return fewer hypotheses. Prefer small diagnostic payloads over exploit chains, destructive
operations, persistence, credential theft, shell commands, file writes, or state-changing actions."""


class ContextualProposalEngine:
    def __init__(self, client):
        self.client = client

    def generate(self, scope, context: dict, valid_evidence_refs=(), evidence_text: str = "") -> tuple[list[TestHypothesis], dict]:
        """evidence_text: optional output of pagent.evidence.evidence_as_text() - actual raw
        target response content (sanitized, capped), passed through request_structured's
        untrusted_context parameter so it stays clearly labeled data, never prompt instructions.
        `context` stays as-is for the finding-shaped metadata ContextBuilder already produces."""
        targets = [{"path": p, "parameter": param} for p, param in scope.allowed_probe_targets]
        user = json.dumps({
            "authorized_probe_targets": targets,
            "supported_weakness_types": list(WEAKNESS_TYPES),
            "valid_evidence_refs": sorted(valid_evidence_refs),
            "context": context,
            "constraints": {
                "proposal_only": True,
                "max_hypotheses": MAX_HYPOTHESES,
                "max_payloads_per_hypothesis": MAX_PAYLOADS_PER_HYPOTHESIS,
                "no_state_change": True,
            },
        }, sort_keys=True)
        raw, stats = self.client.request_structured(
            SYSTEM_PROMPT, user, schema=contextual_proposal_schema(), parser=parse_contextual_output,
            untrusted_context=evidence_text)
        return validate_contextual_output(raw, scope, valid_evidence_refs), stats
