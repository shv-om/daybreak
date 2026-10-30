"""Candidate findings from the two intrusive probes. Both yield 'candidate' at best - a signal,
never a confirmed exploit. No payload execution, no data was ever extracted or modified by design."""
from __future__ import annotations
from .findings import Finding, finding_id
from .parse import parse_reflect_probe, parse_sqli_probe

# Single source of truth for which (path, param) pairs are login-style targets that must go
# through login_sqli_probe (POST/JSON, field=) instead of sqli_probe (GET query, param=).
# scripts/run_intrusive.py and pagent.execution both import this rather than each keeping their
# own copy, so the two can never silently drift apart.
LOGIN_TARGETS = {("/rest/user/login", "email")}

REFLECT_LIMITS = ["This is a textual reflection check over one HTTP response, not a browser. It cannot confirm "
                  "that script would execute (DOM XSS, framework sanitizers, and Content-Security-Policy are not evaluated).",
                  "Only the exact path and parameter named below were tested, with one fixed marker shape.",
                  "A 'raw' signal means the input was echoed without HTML-entity escaping; it is evidence worth human review, not proof of exploitability."]
SQLI_LIMITS = ["This is a response-shape comparison (status/length) across three requests, not data extraction.",
               "A 'signal' result can also occur for non-SQL reasons (e.g. generic input validation); it requires human review.",
               "No login was attempted and no data was read, written, or modified by this probe."]


def reflect_finding(call_id, output_sha256, asset, path, param, output: str) -> Finding:
    r = parse_reflect_probe(output)
    status = "candidate" if r["signal"] == "raw" else "informational"
    return Finding(id=finding_id(f"reflect:{path}:{param}", asset), rule_id="reflected-input-signal", asset=f"{asset}{path}?{param}",
                   title=f"Unescaped reflection signal on {path}?{param}" if status == "candidate" else f"No unescaped reflection observed on {path}?{param}",
                   status=status, applicability="Single GET request to one named path and parameter",
                   verification={"method": "one fixed marker, textual check only", "result": r["signal"]},
                   evidence=[{"tool_call_id": call_id, "observation_ids": [], "output_sha256": output_sha256, "role": "initial"}],
                   confidence={"level": "low" if status == "candidate" else "medium",
                              "why": "single textual observation; no execution context" if status == "candidate" else "marker not reflected unescaped"},
                   limitations=list(REFLECT_LIMITS), remediation="Review server-side output encoding for this parameter; verify in a browser before acting.")


def sqli_finding(call_id, output_sha256, asset, path, param, output: str) -> Finding:
    r = parse_sqli_probe(output)
    status = "candidate" if r["signal"] == "signal" else "informational"
    return Finding(id=finding_id(f"sqli:{path}:{param}", asset), rule_id="sqli-boolean-signal", asset=f"{asset}{path}?{param}",
                   title=f"Boolean-based SQL injection signal on {path}?{param}" if status == "candidate" else f"No SQL injection signal observed on {path}?{param}",
                   status=status, applicability="Single parameter on one named path, GET only",
                   verification={"method": "boolean pair (quote vs escaped quote) vs control, status+length comparison", "result": r["signal"]},
                   evidence=[{"tool_call_id": call_id, "observation_ids": [], "output_sha256": output_sha256, "role": "initial"}],
                   confidence={"level": "low" if status == "candidate" else "medium",
                              "why": "response-shape heuristic only; not confirmed against real query behaviour" if status == "candidate" else "no boolean-pattern difference observed"},
                   limitations=list(SQLI_LIMITS), remediation="Use parameterized queries; review this endpoint manually before concluding anything.")


LOGIN_SQLI_LIMITS = SQLI_LIMITS + [
    "Only quote-breaking values were sent (a trailing single or doubled quote). No tautology "
    "payload (e.g. OR 1=1) was ever constructed or sent, so this probe cannot itself complete an "
    "authentication bypass.",
    "The response body was read and discarded unread by this tool; no session token, cookie, or "
    "body content was parsed or stored."]

MANUAL_CONFIRMATION_NOTE = (
    "If reviewing this signal, a human may manually test standard boolean-bypass payloads (for "
    "example, a bogus email followed by \"' OR 1=1--\" ) directly in a browser or a tool such as "
    "Burp Repeater, on the authorized target only. This tool did not send, and will not send, any "
    "such payload itself.")


def login_sqli_finding(call_id, output_sha256, asset, path, field, output: str) -> Finding:
    r = parse_sqli_probe(output)
    status = "candidate" if r["signal"] == "signal" else "informational"
    f = Finding(id=finding_id(f"login-sqli:{path}:{field}", asset), rule_id="login-sqli-boolean-signal",
               asset=f"{asset}{path}#{field}",
               title=f"Boolean-based SQL injection signal on login field '{field}'" if status == "candidate"
                     else f"No SQL injection signal observed on login field '{field}'",
               status=status, applicability="Single field on one named login endpoint, quote-breaking values only",
               verification={"method": "boolean pair (quote vs escaped quote) vs control, status+length comparison; "
                                       "no tautology payload used", "result": r["signal"]},
               evidence=[{"tool_call_id": call_id, "observation_ids": [], "output_sha256": output_sha256, "role": "initial"}],
               confidence={"level": "low" if status == "candidate" else "medium",
                          "why": "response-shape heuristic only; authentication bypass was neither attempted nor confirmed"
                                if status == "candidate" else "no boolean-pattern difference observed"},
               limitations=list(LOGIN_SQLI_LIMITS),
               remediation="Use parameterized queries for authentication; never build SQL from raw credential input.")
    if status == "candidate":
        f.next_steps = MANUAL_CONFIRMATION_NOTE
    return f
