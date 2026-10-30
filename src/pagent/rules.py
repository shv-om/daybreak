"""Deterministic candidate rules over stored observations. No model involved."""
from __future__ import annotations
from .findings import Finding, finding_id
from .store import Store

HEADER_RULES = {
    "content-security-policy": ("Content-Security-Policy header not observed",
        "Define a Content-Security-Policy that matches the application's content sources and test it before enforcing."),
    "x-frame-options": ("X-Frame-Options header not observed",
        "Restrict framing with X-Frame-Options or a CSP frame-ancestors directive, as suits the application."),
    "x-content-type-options": ("X-Content-Type-Options header not observed",
        "Send 'X-Content-Type-Options: nosniff' unless a documented exception exists."),
    "referrer-policy": ("Referrer-Policy header not observed",
        "Set a Referrer-Policy that matches the application's privacy requirements."),
    "permissions-policy": ("Permissions-Policy header not observed",
        "Set a Permissions-Policy limiting browser features the application does not use."),
}
BASE_LIMITS = ["Only one request (HEAD /) was examined; headers may differ for other paths or methods (e.g. GET).",
               "A missing header is a hardening observation, not proof of an exploitable weakness."]


def candidates_from_observations(store: Store, run_id: int) -> list:
    rows = [r for r in store.observation_rows(run_id) if r["kind"] in ("http_status", "http_header")]
    first_call: dict = {}
    for r in rows:
        first_call.setdefault(r["asset"], r["tool_call_id"])
    out = []
    for asset, call_id in sorted(first_call.items()):
        mine = [r for r in rows if r["tool_call_id"] == call_id]
        status_ids = [r["id"] for r in mine if r["kind"] == "http_status"]
        if not status_ids:
            continue          # no valid response: nothing can be concluded about absence
        present = {r["key"] for r in mine if r["kind"] == "http_header"}
        ev = [{"tool_call_id": call_id, "observation_ids": status_ids,
               "output_sha256": store.tool_call_row(call_id)["output_sha256"], "role": "initial"}]
        for header, (title, fix) in HEADER_RULES.items():
            if header not in present:
                out.append(Finding(
                    id=finding_id(header, asset), rule_id=f"missing-header:{header}", asset=asset, title=title,
                    status="candidate", applicability="HTML responses over HTTP(S); asset served a valid response",
                    verification={"method": "pending", "result": "pending"}, evidence=list(ev),
                    confidence={"level": "low", "why": "single observation, not yet repeated"},
                    limitations=list(BASE_LIMITS), remediation=fix))
        if "strict-transport-security" not in present:
            out.append(Finding(
                id=finding_id("strict-transport-security", asset), rule_id="missing-header:strict-transport-security",
                asset=asset, title="Strict-Transport-Security header not observed (not assessable over plain HTTP)",
                status="inconclusive", applicability="HTTPS responses only",
                verification={"method": "not attempted", "result": "not_applicable_over_plain_http"},
                evidence=list(ev), confidence={"level": "low", "why": "check does not apply to how the target was tested"},
                limitations=["Target was tested over plain HTTP only. Browsers honour HSTS only on HTTPS responses, so its "
                             "absence here is not evidence of a gap. TLS configuration was not assessed."],
                remediation="Assess over HTTPS before drawing any conclusion about HSTS."))
    return out


CRAWL_SURFACE_KINDS = ("discovered_link", "discovered_script", "discovered_param", "external_link")
CRAWL_LIMITS = ["Regex-based extraction, not a full HTML/JS parser; a link, script or parameter could be missed or misread.",
               "Nothing listed here was fetched or tested - only the explicitly-scoped seed page itself was.",
               "A link's presence in markup does not mean the endpoint is reachable, still valid, or authorized for testing."]


def candidates_from_crawl(store: Store, run_id: int) -> list:
    """One per-asset 'informational' Finding listing what a crawled seed page linked to (never
    fetched further - see pagent.discover.run_crawl), plus, where present, a separate 'candidate'
    Finding for JS-sourced endpoint/secret heuristics (extract_js_signals). All next_steps here are
    human-actionable suggestions only, per Finding.next_steps's contract - nothing here expands
    scope.crawl_seeds or allowed_probe_targets by itself."""
    rows = store.observation_rows(run_id)
    by_asset: dict = {}
    for r in rows:
        if r["kind"] in CRAWL_SURFACE_KINDS or r["kind"] in ("js_endpoint_candidate", "js_secret_candidate"):
            by_asset.setdefault(r["asset"], []).append(r)
    out = []
    for asset, mine in sorted(by_asset.items()):
        def evidence_for(rows_subset):
            call_ids = sorted({r["tool_call_id"] for r in rows_subset})
            return [{"tool_call_id": cid, "observation_ids": [r["id"] for r in rows_subset if r["tool_call_id"] == cid],
                    "output_sha256": store.tool_call_row(cid)["output_sha256"], "role": "initial"} for cid in call_ids]

        surface = [r for r in mine if r["kind"] in CRAWL_SURFACE_KINDS]
        if surface:
            links = sorted({r["value"] for r in surface if r["kind"] == "discovered_link"})
            scripts = sorted({r["value"] for r in surface if r["kind"] == "discovered_script"})
            params = sorted({f"{r['key']}?{r['value']}" for r in surface if r["kind"] == "discovered_param"})
            external = sorted({r["value"] for r in surface if r["kind"] == "external_link"})
            out.append(Finding(
                id=finding_id("crawl-discovered-surface", asset), rule_id="crawl-discovered-surface", asset=asset,
                title=f"Crawl of this seed found {len(links)} link(s), {len(scripts)} script(s), "
                     f"{len(params)} parameter(s) not yet in scope ({len(external)} off-host link(s) ignored)",
                status="informational", applicability="Markup directly present in one explicitly-crawled seed page",
                verification={"method": "regex link/attribute extraction from one http_get response", "result": "discovered_not_tested"},
                evidence=evidence_for(surface),
                confidence={"level": "high", "why": "links/params were read directly out of the fetched page's own markup"},
                limitations=list(CRAWL_LIMITS),
                next_steps="Review these; add any path you want crawled to scope.crawl_seeds, or any path+param "
                          "you want actively probed to scope.allowed_probe_targets, in the next scope file. "
                          f"links={links} scripts={scripts} params={params}"))
        js = [r for r in mine if r["kind"] == "js_endpoint_candidate"]
        if js:
            paths = sorted({r["value"] for r in js})
            out.append(Finding(
                id=finding_id("js-endpoint-candidate", asset), rule_id="js-endpoint-candidate", asset=asset,
                title=f"{len(paths)} candidate endpoint path(s) referenced in this JavaScript source",
                status="candidate", applicability="String literals present in one explicitly-scoped JS file",
                verification={"method": "regex scan of fetched JS source for quoted path-shaped strings", "result": "unverified"},
                evidence=evidence_for(js),
                confidence={"level": "low", "why": "a quoted path-shaped string literal is not proof an endpoint exists or is reachable"},
                limitations=["High false-positive rate: any quoted string shaped like a path matches, including ones never used as a route.",
                            "No request was made to any of these paths."],
                next_steps=f"Review these; add any you confirm is real to scope.allowed_probe_targets before testing it. paths={paths}"))
        secrets = [r for r in mine if r["kind"] == "js_secret_candidate"]
        if secrets:
            redacted = sorted({r["value"] for r in secrets})
            out.append(Finding(
                id=finding_id("js-secret-candidate", asset), rule_id="js-secret-candidate", asset=asset,
                title=f"{len(redacted)} possible credential-like string(s) observed in this JavaScript source (heuristic, verify manually)",
                status="candidate", applicability="String literals present in one explicitly-scoped JS file",
                verification={"method": "regex scan for assignment-shaped/AWS-key-shaped strings; values are redacted before storage", "result": "unverified"},
                evidence=evidence_for(secrets),
                confidence={"level": "low", "why": "regex heuristic on client-side JS; both false positives (e.g. placeholder values) "
                                                   "and false negatives are expected, and nothing here was tested against any system"},
                limitations=["Matched value is redacted; this cannot and does not confirm the string is a real, live credential.",
                            "No attempt was made to use, validate, or verify any matched value against anything."],
                remediation="If a match turns out to be real, rotate it and stop shipping it in client-side JS; secrets belong server-side.",
                next_steps=f"Manually inspect the source at this asset near: {redacted}. Do not treat this as confirmed."))
    return out


DISCOVERY_LIMITS = [
    "Only a GET to a small, fixed, checked-in wordlist of common filenames (config/content_discovery_wordlist.json) "
    "was tried under the explicitly scoped prefix - absence of a result here is not evidence nothing else exists.",
    "A non-404 status means something responded; it is not evidence of sensitivity or exploitability on its own "
    "and always needs human review before acting on it.",
    "No request body or data beyond the fixed candidate path was ever sent; the response body was not read or stored.",
]
_DISCOVERY_NOT_FOUND = {"404"}


def candidates_from_discovery(store: Store, run_id: int) -> list:
    """One 'candidate' Finding per asset where run_content_discovery got a non-404 response - see
    pagent.discover.run_content_discovery / pagent.tools.dir_probe for exactly what was sent."""
    rows = [r for r in store.observation_rows(run_id) if r["kind"] in ("http_status", "http_header")]
    first_call: dict = {}
    for r in rows:
        if r["kind"] == "http_status":
            first_call.setdefault(r["asset"], r["tool_call_id"])
    out = []
    for asset, call_id in sorted(first_call.items()):
        mine = [r for r in rows if r["tool_call_id"] == call_id]
        status_rows = [r for r in mine if r["kind"] == "http_status"]
        if not status_rows or status_rows[0]["value"] in _DISCOVERY_NOT_FOUND:
            continue
        status = status_rows[0]["value"]
        content_type = next((r["value"] for r in mine if r["kind"] == "http_header" and r["key"] == "content-type"), "")
        ev = [{"tool_call_id": call_id, "observation_ids": [r["id"] for r in mine],
              "output_sha256": store.tool_call_row(call_id)["output_sha256"], "role": "initial"}]
        out.append(Finding(
            id=finding_id("content-discovery-hit", asset), rule_id="content-discovery-hit", asset=asset,
            title=f"Content discovery: {asset} responded {status}" + (f" ({content_type})" if content_type else ""),
            status="candidate", applicability="One GET to a path from the checked-in content-discovery wordlist",
            verification={"method": "single GET, status/content-type only, no body stored", "result": f"status_{status}"},
            evidence=ev, confidence={"level": "low", "why": "a single non-404 response; not yet reviewed or repeated"},
            limitations=list(DISCOVERY_LIMITS),
            next_steps="Review manually; if this path should stay in scope, add it explicitly to scope.crawl_seeds "
                      "(read-only fetch) or scope.allowed_probe_targets (active probing) in the next scope file."))
    return out


def open_port_findings(store: Store, run_id: int) -> list:
    rows = [r for r in store.observation_rows(run_id) if r["kind"] in ("port_state", "port_service_guess")]
    guesses = {(r["asset"], r["key"]): r["value"] for r in rows if r["kind"] == "port_service_guess"}
    out = []
    for r in rows:
        if r["kind"] != "port_state" or r["value"] != "open":
            continue
        port = r["key"].split("/")[1]
        asset = f"{r['asset']}:{port}"
        guess = guesses.get((r["asset"], r["key"]), "unknown")
        out.append(Finding(
            id=finding_id("open-port", asset), rule_id="open-port", asset=asset,
            title=f"Open {r['key'].upper()} port observed", status="informational",
            applicability="Reachable from the testing host at scan time",
            verification={"method": "single TCP connect scan (nmap -sT) through the policy gateway",
                          "result": "observed_open", "repeats": 0},
            evidence=[{"tool_call_id": r["tool_call_id"], "observation_ids": [r["id"]],
                       "output_sha256": store.tool_call_row(r["tool_call_id"])["output_sha256"], "role": "initial"}],
            confidence={"level": "medium", "why": "a TCP connection succeeded in one scan"},
            limitations=[f"Service name '{guess}' is nmap's port-number guess; no service probing was done.",
                         "Only ports listed in the authorization scope were tested; others were not examined.",
                         "State may change over time; this is a point-in-time observation."],
            remediation="Confirm this port is expected to be exposed; close or restrict it if not."))
    return out
