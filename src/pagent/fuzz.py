"""Candidate findings from the fuzz_probe tool (see pagent.tools.fuzz_probe for exactly what is,
and is not, sent). Still 'candidate' at best - a broader diagnostic battery is more coverage than
sqli_probe's/reflect_probe's single pair/marker, but it is not a confirmed exploit and still needs
human review, same discipline as every other intrusive probe in this project."""
from __future__ import annotations
from .findings import Finding, finding_id
from .parse import parse_fuzz_probe

SQLI_FUZZ_LIMITS = [
    "This compares response status/length across several fixed syntax-probe values vs a baseline, "
    "not data extraction.",
    "No tautology (e.g. OR 1=1) or comment-based bypass shape was ever constructed or sent.",
    "A differing variant can also occur for non-SQL reasons (e.g. generic input validation); it "
    "requires human review, same as sqli_probe's 'signal' result.",
    "No login was attempted and no data was read, written, or modified by this probe.",
]
REFLECT_FUZZ_LIMITS = [
    "This is a textual reflection check over one HTTP response per variant, not a browser. It "
    "cannot confirm that script would execute (DOM XSS, framework sanitizers, and "
    "Content-Security-Policy are not evaluated).",
    "Only the exact path and parameter named below were tested, with three fixed marker shapes.",
    "A 'raw' result for a variant means that specific character was echoed without HTML-entity "
    "escaping; it is evidence worth human review, not proof of exploitability.",
]
MANUAL_CONFIRMATION_NOTE = (
    "If reviewing this signal, a human may manually test standard boolean-bypass or "
    "context-breaking payloads directly in a browser or a tool such as Burp Repeater, on the "
    "authorized target only. This tool did not send, and will not send, any such payload itself.")


def _differing_sqli_variants(variants: dict) -> list:
    return sorted(name for name, v in variants.items() if name != "baseline" and v.get("differs") == "yes")


def _raw_reflect_variants(variants: dict) -> list:
    return sorted(name for name, v in variants.items() if v.get("signal") == "raw")


def sqli_fuzz_finding(call_id, output_sha256, asset, path, param, output: str) -> Finding:
    parsed = parse_fuzz_probe(output)
    differing = _differing_sqli_variants(parsed["variants"])
    status = "candidate" if differing else "informational"
    total_checked = max(len(parsed["variants"]) - 1, 0)   # minus the baseline itself
    f = Finding(
        id=finding_id(f"sqli-fuzz:{path}:{param}", asset), rule_id="sqli-fuzz-signal", asset=f"{asset}{path}?{param}",
        title=f"SQL injection fuzz signal on {path}?{param}" if status == "candidate"
              else f"No SQL injection fuzz signal observed on {path}?{param}",
        status=status, applicability="Single parameter on one named path, GET only, fixed diagnostic values only",
        verification={"method": f"{total_checked}-variant syntax-probe battery vs baseline, status+length comparison",
                      "result": "signal" if differing else "no_signal", "differing_variants": differing},
        evidence=[{"tool_call_id": call_id, "observation_ids": [], "output_sha256": output_sha256, "role": "initial"}],
        confidence={"level": "low", "why": f"{len(differing)}/{total_checked} diagnostic variants differed from baseline"
                                          if differing else "no diagnostic variant differed from baseline"},
        limitations=list(SQLI_FUZZ_LIMITS),
        remediation="Use parameterized queries; review this endpoint manually before concluding anything.")
    if status == "candidate":
        f.next_steps = MANUAL_CONFIRMATION_NOTE
    return f


def reflect_fuzz_finding(call_id, output_sha256, asset, path, param, output: str) -> Finding:
    parsed = parse_fuzz_probe(output)
    raw = _raw_reflect_variants(parsed["variants"])
    status = "candidate" if raw else "informational"
    total_checked = len(parsed["variants"])
    f = Finding(
        id=finding_id(f"reflect-fuzz:{path}:{param}", asset), rule_id="reflected-input-fuzz-signal",
        asset=f"{asset}{path}?{param}",
        title=f"Unescaped reflection signal on {path}?{param}" if status == "candidate"
              else f"No unescaped reflection observed on {path}?{param}",
        status=status, applicability="Single GET request to one named path and parameter, three marker shapes",
        verification={"method": f"{total_checked}-variant marker battery, textual check only",
                      "result": "signal" if raw else "no_signal", "raw_variants": raw},
        evidence=[{"tool_call_id": call_id, "observation_ids": [], "output_sha256": output_sha256, "role": "initial"}],
        confidence={"level": "low" if status == "candidate" else "medium",
                   "why": f"{len(raw)}/{total_checked} marker shapes reflected unescaped" if raw
                          else "no marker shape reflected unescaped"},
        limitations=list(REFLECT_FUZZ_LIMITS),
        remediation="Review server-side output encoding for this parameter; verify in a browser before acting.")
    return f
