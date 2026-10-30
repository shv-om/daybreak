"""Proposal -> bounded payload-fuzz batch resolution and result-to-Finding conversion.

This module does not make network requests.  It treats a saved proposals file as untrusted,
revalidates proposal ids/state/scope, and constructs the exact args that a human can approve for
pagent.tools.payload_fuzz.  The model supplies only the parameter *values*; the target and request
shape stay deterministic and scope-bound.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .findings import Finding, finding_id
from .proposals import PAYLOAD_CATEGORIES, recompute_hypothesis_id, recompute_payload_id
from .scope import Scope
from .suggestions.outcomes import find_payload
from .tools.payload_fuzz import MAX_PAYLOADS, request_mode_for_target, valid_payload_batch


class PayloadFuzzError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedFuzzBatch:
    tool: str
    args: dict
    payload_ids: tuple[str, ...]
    hypothesis_ids: tuple[str, ...]


def _single_host(scope: Scope) -> str:
    if not scope.allowed_hosts:
        raise PayloadFuzzError("payload fuzzing currently requires one explicit allowed_hosts entry")
    return sorted(scope.allowed_hosts)[0]


def _single_port(scope: Scope) -> int:
    return min(scope.allowed_ports)


def _validate_saved(h: dict, p: dict) -> None:
    try:
        hid = recompute_hypothesis_id(h)
        pid = recompute_payload_id(hid, p)
    except KeyError as e:
        raise PayloadFuzzError(f"hypothesis/payload missing expected field: {e}") from e
    if hid != h.get("id"):
        raise PayloadFuzzError("hypothesis content does not match its id; file may have been edited")
    if pid != p.get("id"):
        raise PayloadFuzzError("payload content does not match its id; file may have been edited")
    if p.get("execution_state") != "suggested_only" or not p.get("requires_approval", True):
        raise PayloadFuzzError("payload is not marked suggested_only/requires_approval")
    weakness = h.get("weakness_type")
    if weakness not in PAYLOAD_CATEGORIES or p.get("category") not in PAYLOAD_CATEGORIES[weakness]:
        raise PayloadFuzzError("payload category is inconsistent with its hypothesis weakness_type")


def resolve_payload_batch(proposals_doc: dict, payload_ids, scope: Scope) -> ResolvedFuzzBatch:
    ids = list(payload_ids)
    if not ids or len(ids) > MAX_PAYLOADS:
        raise PayloadFuzzError(f"select between 1 and {MAX_PAYLOADS} payload ids")
    if len(set(ids)) != len(ids):
        raise PayloadFuzzError("payload ids must be unique")
    if "payload_fuzz" not in scope.allowed_tools:
        raise PayloadFuzzError("payload_fuzz is not in scope.allowed_tools")

    selected = []
    for payload_id in ids:
        try:
            h, p = find_payload(proposals_doc, payload_id)
        except Exception as e:
            raise PayloadFuzzError(str(e)) from e
        _validate_saved(h, p)
        selected.append((h, p))

    targets = {(h["path"], h["parameter"]) for h, _ in selected}
    if len(targets) != 1:
        raise PayloadFuzzError("one fuzz batch may target only one path+parameter")
    path, param = next(iter(targets))
    if not scope.check_probe_target(path, param):
        raise PayloadFuzzError(f"{path}?{param} is not in allowed_probe_targets")

    payloads = [p["payload"] for _, p in selected]
    if not valid_payload_batch(payloads):
        raise PayloadFuzzError("selected payloads exceed fuzz batch count/size/control-character limits")

    args = {
        "host": _single_host(scope),
        "port": _single_port(scope),
        "path": path,
        "param": param,
        "mode": request_mode_for_target(path, param),
        "payloads": payloads,
    }
    return ResolvedFuzzBatch(
        tool="payload_fuzz",
        args=args,
        payload_ids=tuple(p["id"] for _, p in selected),
        hypothesis_ids=tuple(dict.fromkeys(h["id"] for h, _ in selected)),
    )


def payload_fuzz_finding(call_id: int, output_sha256: str, asset: str, path: str, param: str,
                         output: str, payload_ids=()) -> Finding:
    try:
        data = json.loads(output)
        cases = data.get("cases", []) if isinstance(data, dict) else []
        changed = int(data.get("response_changed_count", 0))
        total = len(cases)
        mode = str(data.get("mode", "unknown"))
    except (ValueError, TypeError, json.JSONDecodeError):
        data, cases, changed, total, mode = {}, [], 0, 0, "unknown"

    status = "candidate" if changed else "informational"
    delimiter = "#" if mode == "json_login" else "?"
    title = (f"Payload fuzzing produced {changed} response differential(s) on {path}{delimiter}{param}"
             if changed else f"Payload fuzzing produced no response differentials on {path}{delimiter}{param}")
    verification = {
        "method": "one fixed control followed by an approved bounded payload batch; response shape only",
        "result": f"{changed}/{total} payload responses differed from the control",
        "request_mode": mode,
        "payload_ids": list(payload_ids),
    }
    return Finding(
        id=finding_id(f"payload-fuzz:{path}:{param}:{','.join(payload_ids)}", asset),
        rule_id="payload-fuzz-response-differential",
        asset=f"{asset}{path}{delimiter}{param}",
        title=title,
        status=status,
        applicability="Only the exact approved path, parameter and payload batch were tested",
        verification=verification,
        evidence=[{"tool_call_id": call_id, "observation_ids": [], "output_sha256": output_sha256, "role": "initial"}],
        confidence={
            "level": "low" if changed else "medium",
            "why": ("response-shape differences are triage signals and may have non-security causes"
                    if changed else "no status/content-type/length differential was observed for this bounded batch"),
        },
        limitations=[
            "This is differential fuzzing, not exploit confirmation; a changed response does not identify a vulnerability by itself.",
            "Only status, bounded body length, content type and transport errors are compared; response bodies are discarded.",
            "The control is one fixed benign string, so application-specific validation can produce benign differences.",
            f"At most {MAX_PAYLOADS} approved payloads are sent in one batch; target, parameter and request mode cannot be changed by a payload.",
        ],
        remediation="Review any differential with a category-specific validation step before assigning a vulnerability or severity.",
        next_steps="Correlate changed cases with their approved payload ids and use the existing restricted verification path before confirmation.",
    )
