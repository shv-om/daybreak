"""JSON + Markdown reports generated from the same data structure (so they cannot drift apart)."""
from __future__ import annotations
from datetime import datetime, timezone
from . import __version__
from .findings import STATUSES
from .store import scope_fingerprint

GLOBAL_LIMITS = ["Findings come from deterministic rules over stored observations; the language model is not a source of evidence.",
                 "'confirmed' means either an independent repeat check agreed, or a human operator directly performed and logged "
                 "the action (see any Manual confirmation log). Neither implies exploitability or business impact beyond what is described.",
                 "Severity is not assessed; no CVSS or other score is claimed."]


def build_report(run_id: int, scope, findings: list, action_ledger: list | None = None) -> dict:
    counts = {s: sum(f.status == s for f in findings) for s in STATUSES}
    return {"schema_version": "0.1", "pagent_version": __version__, "engagement_id": scope.engagement_id,
            "run_id": run_id, "scope_sha256": scope_fingerprint(scope),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"total": len(findings), **counts}, "global_limitations": GLOBAL_LIMITS,
            "findings": [f.to_dict() for f in findings], "action_ledger": action_ledger or []}


def finding_block(f: dict) -> list:
    L = [f"### {f['id']} - {f['title']}", "",
         f"- Asset: `{f['asset']}`  |  Status: **{f['status']}**  |  Confidence: {f['confidence']['level']} ({f['confidence']['why']})",
         f"- Severity: {f['severity']['rating']} - {f['severity']['rationale']}",
         f"- Applicability: {f['applicability']}",
         f"- Verification: {f['verification']['method']} -> {f['verification']['result']}",
         "- Evidence: " + "; ".join(f"call {e['tool_call_id']} ({e['role']}, sha256 {str(e['output_sha256'])[:12]})" for e in f["evidence"]),
         f"- Weakness IDs: {', '.join(f['weakness_ids']) or 'none assigned'}",
         "- References:" + ("" if f["references"] else " none")]
    L += [f"  - {x}" for x in f["references"]]
    L += [f"- Remediation: {f['remediation']}"]
    if f.get("next_steps"):
        L.append(f"- Suggested next step (human action, not performed by this tool): {f['next_steps']}")
    L.append("- Limitations:")
    L += [f"  - {x}" for x in f["limitations"]]
    if f.get("manual_actions"):
        L.append("- Manual confirmation log (performed by a human operator, not this tool):")
        for act in f["manual_actions"]:
            L += [f"  - {act['performed_at']} by {act['performed_by']}:",
                 f"    - Action: {act['action_description']}",
                 f"    - Payload sent (as entered by the operator): `{act['payload_sent']}`",
                 f"    - Observed result: {act['observed_result']}"]
            if act.get("notes"):
                L.append(f"    - Notes: {act['notes']}")
    L.append(f"- Tools: pagent {f['tool_versions']['pagent']}, python {f['tool_versions']['python']}")
    return L


def finding_markdown(f: dict) -> str:
    return "\n".join(finding_block(f))


def to_markdown(report: dict) -> str:
    s = report["summary"]
    L = [f"# Assessment report - {report['engagement_id']}", "",
         f"- Run: {report['run_id']}  |  Generated: {report['generated_at']}",
         f"- Scope fingerprint (sha256): `{report['scope_sha256']}`", "",
         "## Summary", "", "| Status | Count |", "|---|---|"]
    L += [f"| {k} | {s[k]} |" for k in STATUSES] + [f"| **total** | **{s['total']}** |", "", "## Limitations", ""]
    L += [f"- {x}" for x in report["global_limitations"]]
    ledger = report.get("action_ledger", [])
    if ledger:
        L += ["", "## Action ledger", "",
              "| Step | Time (UTC) | Type | Model | Action / tool | Target | Decision | Outcome | Findings | Rationale |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for row in ledger:
            timestamp = datetime.fromtimestamp(row["timestamp"], timezone.utc).isoformat()
            values = [row.get("step_id", ""), timestamp, row.get("type", ""), row.get("model", ""),
                      row.get("action", "") or row.get("tool", ""), row.get("target", ""),
                      row.get("decision", ""), row.get("outcome", ""),
                      ", ".join(row.get("finding_ids", [])), row.get("rationale", "")]
            L.append("| " + " | ".join(_table_cell(v) for v in values) + " |")
    L += ["", "## Findings", ""]
    for f in report["findings"]:
        L += finding_block(f) + [""]
    return "\n".join(L)


def _table_cell(value) -> str:
    """Keep model text and tool errors from breaking the Markdown table layout."""
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|").replace("\r", " ").replace("\n", " "))
