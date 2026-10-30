"""Test Strategy schema.

A TestStrategy describes HOW to test a hypothesis (what to hold constant, what to compare, what
would count as a signal) rather than just handing back payload strings. Like
pagent.proposals.TestHypothesis / PayloadProposal, this is proposal-only: this module has no
import of the policy gateway, approvals, or any tool adapter, and produces nothing with execution
authority. Model output is untrusted input - parsed structurally, then validated deterministically
against scope and known evidence, exactly like the existing proposal path.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

from .registry import SuggestionSourceRegistry
from ..proposals import CONFIDENCE_LEVELS, WEAKNESS_TYPES

TEST_CATEGORIES = WEAKNESS_TYPES   # a strategy's test_category is one of the same supported weakness types
MAX_HYPOTHESES = 4
MAX_TEXT_LEN = 1000
MAX_SHORT_TEXT_LEN = 300
MAX_SUGGESTION_SOURCES = 4


class TestStrategyError(ValueError):
    pass


def _stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(parts).encode()
    return prefix + hashlib.sha256(raw).hexdigest()[:12]


@dataclass(frozen=True)
class TestStrategy:
    id: str
    hypothesis_id: str
    objective: str
    test_category: str
    target_parameter: str
    parameter_context: str
    baseline_requirement: str
    comparison_method: str
    expected_signal: str
    negative_control: str
    interpretation_notes: str
    confidence: str
    suggestion_sources: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def test_strategy_schema() -> dict:
    text = {"type": "string", "maxLength": MAX_TEXT_LEN}
    short_text = {"type": "string", "maxLength": MAX_SHORT_TEXT_LEN}
    strategy = {
        "type": "object",
        "properties": {
            "hypothesis_id": short_text,
            "objective": text,
            "test_category": {"type": "string", "enum": list(TEST_CATEGORIES)},
            "target_parameter": short_text,
            "parameter_context": text,
            "baseline_requirement": text,
            "comparison_method": text,
            "expected_signal": text,
            "negative_control": text,
            "interpretation_notes": text,
            "confidence": {"type": "string", "enum": list(CONFIDENCE_LEVELS)},
            "suggestion_sources": {"type": "array", "items": {"type": "string"},
                                   "maxItems": MAX_SUGGESTION_SOURCES},
        },
        "required": ["hypothesis_id", "objective", "test_category", "target_parameter", "parameter_context",
                     "baseline_requirement", "comparison_method", "expected_signal", "negative_control",
                     "interpretation_notes", "confidence", "suggestion_sources"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {"strategies": {"type": "array", "items": strategy, "maxItems": MAX_HYPOTHESES}},
        "required": ["strategies"],
        "additionalProperties": False,
    }


def _require_exact_keys(obj: dict, expected: set, where: str) -> None:
    if not isinstance(obj, dict) or set(obj) != expected:
        raise TestStrategyError(f"{where}: wrong keys")


_STRATEGY_KEYS = {"hypothesis_id", "objective", "test_category", "target_parameter", "parameter_context",
                  "baseline_requirement", "comparison_method", "expected_signal", "negative_control",
                  "interpretation_notes", "confidence", "suggestion_sources"}
_STRING_KEYS = _STRATEGY_KEYS - {"test_category", "confidence", "suggestion_sources"}


def parse_test_strategy(obj_or_text) -> dict:
    """Parse only structural shape. Scope/evidence/registry checks happen in validate_test_strategy()."""
    if isinstance(obj_or_text, str):
        try:
            obj = json.loads(obj_or_text)
        except json.JSONDecodeError as e:
            raise TestStrategyError("not valid JSON") from e
    else:
        obj = obj_or_text
    _require_exact_keys(obj, {"strategies"}, "root")
    strategies = obj["strategies"]
    if not isinstance(strategies, list) or len(strategies) > MAX_HYPOTHESES:
        raise TestStrategyError("strategies must be a bounded list")
    for i, s in enumerate(strategies):
        _require_exact_keys(s, _STRATEGY_KEYS, f"strategy[{i}]")
        if not all(isinstance(s[k], str) for k in _STRING_KEYS):
            raise TestStrategyError(f"strategy[{i}]: string field has wrong type")
        if not s["hypothesis_id"] or not s["target_parameter"]:
            raise TestStrategyError(f"strategy[{i}]: hypothesis_id and target_parameter must be non-empty")
        if s["test_category"] not in TEST_CATEGORIES:
            raise TestStrategyError(f"strategy[{i}]: unsupported test_category")
        if s["confidence"] not in CONFIDENCE_LEVELS:
            raise TestStrategyError(f"strategy[{i}]: unsupported confidence")
        src = s["suggestion_sources"]
        if not isinstance(src, list) or len(src) > MAX_SUGGESTION_SOURCES or not all(isinstance(x, str) for x in src):
            raise TestStrategyError(f"strategy[{i}]: suggestion_sources must be a bounded list of strings")
    return obj


def validate_test_strategy(raw, scope, valid_evidence_refs=(), registry: SuggestionSourceRegistry | None = None,
                           ) -> list:
    """Validate model output against deterministic scope, known evidence, and (if provided) the
    suggestion source registry. `target_parameter` is expected as "path#parameter" so it can be
    checked the same way pagent.proposals checks a hypothesis's path+parameter: a strategy for a
    target outside allowed_probe_targets is rejected even though strategies cannot execute
    anything, to keep generated guidance aligned with the same authorization boundary as the tool
    layer. `hypothesis_id` is treated as an evidence-style reference and must be one of
    valid_evidence_refs when that set is non-empty, so a strategy can't be invented for a
    hypothesis that doesn't exist."""
    obj = parse_test_strategy(raw)
    valid_refs = set(valid_evidence_refs)
    out = []
    for s in obj["strategies"]:
        if valid_refs and s["hypothesis_id"] not in valid_refs:
            raise TestStrategyError(f"unknown hypothesis_id: {s['hypothesis_id']}")
        if "#" not in s["target_parameter"]:
            raise TestStrategyError(f"target_parameter must be 'path#parameter', got: {s['target_parameter']}")
        path, _, param = s["target_parameter"].partition("#")
        if not scope.check_probe_target(path, param):
            raise TestStrategyError(f"target not authorized for active probing: {path}#{param}")
        if registry is not None:
            unknown = [c for c in s["suggestion_sources"] if registry.get(c) is None]
            if unknown:
                raise TestStrategyError("unknown suggestion source categor(y/ies): " + ", ".join(sorted(unknown)))
        sid = _stable_id("TS-", s["hypothesis_id"], s["test_category"], s["target_parameter"], s["objective"])
        out.append(TestStrategy(
            id=sid, hypothesis_id=s["hypothesis_id"], objective=s["objective"], test_category=s["test_category"],
            target_parameter=s["target_parameter"], parameter_context=s["parameter_context"],
            baseline_requirement=s["baseline_requirement"], comparison_method=s["comparison_method"],
            expected_signal=s["expected_signal"], negative_control=s["negative_control"],
            interpretation_notes=s["interpretation_notes"], confidence=s["confidence"],
            suggestion_sources=list(s["suggestion_sources"])))
    return out
