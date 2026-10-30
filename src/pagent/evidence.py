"""Phase 1 of the agentic build plan: rich, compact, sanitized evidence of what the target
actually said - not just parsed observation summaries (which is all pagent.suggestions.context
.ContextBuilder gives the model today). This module reads ONLY from Store (already-captured,
already-capped raw tool output, from pagent.store.Store.record_tool_call); it talks to no network
and runs no tool itself. It exists so a later orchestrator - and any human reading it - can see
*why* something looked interesting, not just that it did. ContextBuilder's finding-shaped metadata
is unchanged by this module; this is the complementary raw-content view.

Everything this module returns is explicitly labeled untrusted ("source": "untrusted_target_
response"): it is text a target sent back, never an instruction, and any later prompt construction
(pagent.actions / pagent.orchestrator, Phase 2/3) must keep treating it that way - evidence to
read, never text to follow.
"""
from __future__ import annotations
import json
import re

DEFAULT_MAX_CALLS = 12
# Conservative on purpose: both models in use (qwen2.5-coder:3b, qwen3:4b) are small, and Ollama's
# default context window is easy to blow through with a few raw HTTP response bodies. Tune this
# per model once Phase 2/3 knows the real context budget - this default is deliberately cautious.
DEFAULT_MAX_BODY_CHARS = 1200

# Strips genuinely dangerous/non-printable control characters only - NOT newlines, tabs, or
# non-ASCII text. pagent.parse.sanitize() is tuned for single-line observation VALUES and would
# turn every newline (and every non-ASCII byte) in a multi-line HTTP body into '?', which is both
# unreadable and pointless to ship to a model that's supposed to read the body's actual structure.
_BODY_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_body(value: str, limit: int) -> str:
    return _BODY_UNSAFE.sub("?", value)[:limit]


def build_evidence(store, run_id: int, asset_prefix: str | None = None, max_calls: int = DEFAULT_MAX_CALLS,
                   max_body_chars: int = DEFAULT_MAX_BODY_CHARS) -> list:
    """Most-recent-first list of up to max_calls tool-call summaries for this run (optionally
    filtered to calls whose host:port[+path] starts with asset_prefix - see Store.tool_call_rows).
    Each entry carries the tool, its (already-scoped-and-validated) args, whether it was allowed,
    and - for an allowed call with recorded output - a sanitized, hard-capped excerpt of the
    actual raw response. A denied/failed call has no excerpt (there is nothing untrusted to show -
    the target never responded), but is still included: "this was tried and denied" is useful
    context for a later decision too.
    """
    rows = store.tool_call_rows(run_id, asset_prefix=asset_prefix)
    rows = list(reversed(rows))[:max_calls]
    out = []
    for r in rows:
        entry = {"tool_call_id": r["id"], "tool": r["tool"], "args": r["args"], "allowed": r["allowed"],
                "reason": r["reason"], "ts": r["ts"], "source": "untrusted_target_response",
                "output_excerpt": None, "output_truncated": False}
        if r["allowed"]:
            raw = store.raw_output_for_call(r["id"])
            if raw is not None:
                clean = _sanitize_body(raw, limit=len(raw))   # strip unsafe control chars only; truncate ourselves next
                entry["output_excerpt"] = clean[:max_body_chars]
                entry["output_truncated"] = len(clean) > max_body_chars
        out.append(entry)
    return out


def evidence_as_text(entries: list) -> str:
    """Renders build_evidence() output as a plain, clearly-labeled text block. Every byte in an
    excerpt is text a TARGET sent back - never an instruction - which is why this is meant to be
    passed as OllamaClient.request_structured(..., untrusted_context=...), never concatenated
    directly into a system/user prompt string: request_structured wraps it in explicit
    <untrusted_tool_output> tags and an instructions-vs-data reminder on its own."""
    lines = []
    for e in entries:
        header = f"### tool_call #{e['tool_call_id']} | {e['tool']} | allowed={e['allowed']}"
        if not e["allowed"] and e["reason"]:
            header += f" | denied_reason={e['reason']}"
        lines.append(header)
        lines.append(f"args: {json.dumps(e['args'], sort_keys=True)}")
        if e["output_excerpt"] is not None:
            lines.append("response" + (" [TRUNCATED]:" if e["output_truncated"] else ":"))
            lines.append(e["output_excerpt"])
        lines.append("")
    return "\n".join(lines)
