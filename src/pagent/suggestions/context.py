"""Context Builder.

Converts an existing Finding (plus whatever observations its evidence actually references) into
a compact, structured dict the model can use to generate better-targeted test suggestions.

This module never talks to the network, never calls the policy gateway, and never fabricates a
value that was not actually observed or that is not a deterministic function of already-known
facts (the finding's own rule_id/asset). A field is simply left out of the context when the
underlying evidence isn't there - a missing field is information too, and a model that is told
"you don't know the baseline" should behave differently than one given an invented baseline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# asset strings are built by pagent.discover / pagent.intrusive as "{host}:{port}{path}?{param}"
# (query-string probes) or "{host}:{port}{path}#{field}" (json-body probes). This mirrors that
# format rather than inventing a new one.
_ASSET_RE = re.compile(r"^(?P<host>[^:/]+):(?P<port>\d+)(?P<path>/[^?#]*)(?:\?(?P<param>[^?#]+)|#(?P<field>[^?#]+))?$")

# Deterministic, not model-derived: which rule_id prefixes correspond to which weakness_type /
# HTTP method / parameter location. Extending this list extends what the context builder can
# describe; it does not change what the proposal engine is allowed to do with that description.
_RULE_HINTS = (
    # (rule_id prefix,              weakness_type,     method, param_location)
    ("login-sqli-boolean-signal",    "sql_injection",   "POST", "json_body"),
    ("sqli-boolean-signal",          "sql_injection",   "GET",  "query"),
    ("sqli-fuzz-signal",             "sql_injection",   "GET",  "query"),
    ("reflected-input-fuzz-signal",  "reflected_input", "GET",  "query"),
    ("reflected-input-signal",       "reflected_input", "GET",  "query"),
)

# Best-effort, naming-based classification of what an endpoint is for. This is a heuristic over
# the path string, not a claim backed by evidence, so it is always safe to omit when nothing
# matches - it is only ever used to help the model prioritize, never to authorize anything.
_ENDPOINT_ROLE_HINTS = (
    ("login", "authentication"),
    ("auth", "authentication"),
    ("search", "search"),
    ("admin", "administration"),
)


class ContextBuilderError(ValueError):
    pass


def _rule_hint(rule_id: str):
    for prefix, weakness_type, method, location in _RULE_HINTS:
        if rule_id.startswith(prefix):
            return weakness_type, method, location
    return None


def _endpoint_role(path: str) -> str | None:
    lowered = path.lower()
    for needle, role in _ENDPOINT_ROLE_HINTS:
        if needle in lowered:
            return role
    return None


def _evidence_observation_ids(finding: dict) -> list:
    out: list = []
    for ev in finding.get("evidence", []):
        out.extend(ev.get("observation_ids", []))
    return out


@dataclass(frozen=True)
class EndpointParameter:
    """Parsed out of the finding's asset string. None fields mean "not expressed in this asset",
    not "unknown" - e.g. a header finding's asset has no path/param at all."""
    host: str
    port: int
    path: str
    param: str | None
    field: str | None


def _parse_asset(asset: str) -> EndpointParameter | None:
    m = _ASSET_RE.match(asset)
    if not m:
        return None
    return EndpointParameter(host=m.group("host"), port=int(m.group("port")), path=m.group("path"),
                             param=m.group("param"), field=m.group("field"))


class ContextBuilder:
    """Builds model context from a Store (for observation lookups) and, optionally, a Scope
    (used only to confirm the candidate's target is still a recognized probe target - this is a
    courtesy cross-check, not a substitute for the deterministic scope/evidence validation that
    pagent.proposals already does on the model's output)."""

    def __init__(self, store=None, scope=None):
        self.store = store
        self.scope = scope

    def build(self, finding: dict) -> dict:
        """finding: a Finding.to_dict()-shaped mapping (as returned by Store.get_finding /
        Store.findings_for_run). Returns a dict with only the top-level keys that evidence
        actually supports; keys with nothing to report are omitted entirely rather than set to
        null/placeholder values."""
        if not isinstance(finding, dict) or not finding.get("id") or not finding.get("asset"):
            raise ContextBuilderError("finding must be a dict with at least 'id' and 'asset'")

        rule_id = finding.get("rule_id", "")
        asset = finding["asset"]
        parsed = _parse_asset(asset)
        hint = _rule_hint(rule_id)

        context: dict = {}

        if parsed is not None and (parsed.param or parsed.field) and hint is not None:
            weakness_type, method, location = hint
            param_name = parsed.param or parsed.field
            context["endpoint"] = self._endpoint_context(parsed, method)
            context["parameter"] = {
                "name": param_name,
                "location": location,
                "observed_type": "string",   # every current probe only ever sends string values
            }
            tech = {}
            role = _endpoint_role(parsed.path)
            if role is not None:
                tech["endpoint_role"] = role
            if context["endpoint"].get("content_type"):
                tech["interface_type"] = "JSON API" if "json" in context["endpoint"]["content_type"] else "HTTP"
            if tech:
                context["technology_context"] = tech
        else:
            weakness_type = None

        baseline = self._baseline_context(finding)
        if baseline:
            context["baseline"] = baseline

        candidate: dict = {
            "finding_id": finding["id"],
            "rule_id": rule_id,
        }
        if weakness_type is not None:
            candidate["weakness_type"] = weakness_type
        confidence = finding.get("confidence") or {}
        if confidence.get("level"):
            candidate["confidence"] = confidence["level"]
        obs_ids = _evidence_observation_ids(finding)
        if obs_ids:
            candidate["observation_ids"] = [str(i) for i in obs_ids]
        verification = finding.get("verification") or {}
        if verification.get("result"):
            candidate["observed_result"] = verification["result"]
        context["candidate"] = candidate

        return context

    def _endpoint_context(self, parsed: EndpointParameter, method: str) -> dict:
        endpoint = {"method": method, "path": parsed.path}
        if self.store is not None:
            content_type = self._observed_header(f"{parsed.host}:{parsed.port}", "content-type")
            if content_type:
                endpoint["content_type"] = content_type
        return endpoint

    def _observed_header(self, asset: str, header_name: str) -> str | None:
        """Best-effort lookup of a previously-observed response header for this host:port, from
        whatever discovery observations happen to be in the store. Returns None - never a guess -
        when nothing was actually recorded."""
        try:
            cur = self.store.db.execute(
                "SELECT value FROM observations WHERE asset=? AND kind='http_header' AND key=? "
                "ORDER BY id DESC LIMIT 1", (asset, header_name))
            row = cur.fetchone()
        except Exception:
            return None
        return row[0] if row else None

    def _baseline_context(self, finding: dict) -> dict:
        if self.store is None:
            return {}
        obs_ids = _evidence_observation_ids(finding)
        if not obs_ids:
            return {}
        rows = self.store.observations_by_ids(obs_ids)
        baseline: dict = {}
        for r in rows:
            if r["kind"] == "http_status" and r["key"] == "status":
                try:
                    baseline["status_code"] = int(r["value"])
                except ValueError:
                    pass
            elif r["kind"] == "http_header" and r["key"] == "content-type":
                baseline["response_content_type"] = r["value"]
            elif r["kind"] == "http_header" and r["key"] == "content-length":
                try:
                    baseline["response_length"] = int(r["value"])
                except ValueError:
                    pass
        return baseline


def build_context(finding: dict, store=None, scope=None) -> dict:
    """Convenience wrapper around ContextBuilder for one-off calls."""
    return ContextBuilder(store=store, scope=scope).build(finding)
