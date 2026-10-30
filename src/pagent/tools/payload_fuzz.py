"""Bounded payload fuzzing adapter for explicitly scoped path+parameter targets.

Unlike the fixed-shape diagnostic probes, this adapter is intentionally able to send caller-
supplied payload strings so an approved AI proposal can be tested verbatim.  The authority stays
narrow, however: the caller cannot choose an arbitrary URL, method, headers, body shape, or second
parameter.  The active Scope still has to allow the exact path+parameter, the request shape is
selected deterministically from that target, and the PolicyGateway requires human approval for
the exact payload batch before this ToolSpec can run.

No external fuzzer is invoked.  Requests are made with Python's http.client only.  One fixed
control request is followed by a small, bounded payload batch.  Only response-shape metadata is
returned; response bodies are read up to a hard cap and discarded.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import time
import urllib.parse

from ..intrusive import LOGIN_TARGETS
from ..policy import ToolSpec
from .login_sqli_probe import DUMMY_SECRET

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]{0,200}$")
_PARAM_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")

QUERY_GET = "query_get"
JSON_LOGIN = "json_login"
REQUEST_MODES = (QUERY_GET, JSON_LOGIN)

MAX_PAYLOADS = 8
MAX_PAYLOAD_BYTES = 256
MAX_TOTAL_PAYLOAD_BYTES = 1536
MAX_RESPONSE_BYTES = 32768
INTER_REQUEST_DELAY_S = 0.10
CONTROL_VALUE = "pagent-fuzz-control"


def request_mode_for_target(path: str, param: str) -> str:
    """The request shape is a deterministic property of the already-authorized target.

    Keeping this out of model/user control is what stops payload fuzzing from turning into a
    generic HTTP executor.  Existing login targets use the same POST/JSON shape as
    login_sqli_probe; all other current probe targets use GET query-string requests.
    """
    return JSON_LOGIN if (path, param) in LOGIN_TARGETS else QUERY_GET


def valid_payload_batch(payloads) -> bool:
    if type(payloads) is not list or not (1 <= len(payloads) <= MAX_PAYLOADS):
        return False
    total = 0
    seen = set()
    for value in payloads:
        if type(value) is not str or not value or value in seen:
            return False
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            return False
        raw = value.encode("utf-8")
        if len(raw) > MAX_PAYLOAD_BYTES:
            return False
        total += len(raw)
        if total > MAX_TOTAL_PAYLOAD_BYTES:
            return False
        seen.add(value)
    return True


def _read_shape(response) -> tuple[int, int, str, bool]:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(raw) > MAX_RESPONSE_BYTES
    size = min(len(raw), MAX_RESPONSE_BYTES)
    content_type = (response.getheader("Content-Type") or "")[:120]
    return response.status, size, content_type, truncated


def _default_transport(host, port, path, param, mode, value, timeout):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        headers = {"User-Agent": "pagent/0.1 (authorized-lab)"}
        if mode == QUERY_GET:
            target = f"{path}?{urllib.parse.urlencode({param: value})}"
            conn.request("GET", target, headers=headers)
        elif mode == JSON_LOGIN:
            body = json.dumps({param: value, "password": DUMMY_SECRET}).encode("utf-8")
            headers["Content-Type"] = "application/json"
            conn.request("POST", path, body=body, headers=headers)
        else:  # handler/cross_check should make this unreachable; fail closed anyway.
            raise ValueError("unsupported request mode")
        return _read_shape(conn.getresponse())
    finally:
        conn.close()


def _case(value: str, result, baseline) -> dict:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    if isinstance(result, Exception):
        return {
            "payload_sha256_16": digest,
            "transport_error": type(result).__name__,
            "response_changed": True,
        }
    status, size, content_type, truncated = result
    base_status, base_size, base_content_type, _ = baseline
    status_changed = status != base_status
    content_type_changed = content_type != base_content_type
    length_delta = size - base_size
    return {
        "payload_sha256_16": digest,
        "status": status,
        "bytes_read": size,
        "length_delta": length_delta,
        "content_type": content_type,
        "truncated": truncated,
        "status_changed": status_changed,
        "content_type_changed": content_type_changed,
        "response_changed": status_changed or content_type_changed or length_delta != 0,
    }


def make_payload_fuzz(scope, transport=_default_transport, sleeper=time.sleep) -> ToolSpec:
    def cross_check(args):
        path, param = args.get("path", ""), args.get("param", "")
        if not scope.check_probe_target(path, param):
            return False, "path+param not in allowed_probe_targets"
        expected_mode = request_mode_for_target(path, param)
        if args.get("mode") != expected_mode:
            return False, f"request mode must be {expected_mode!r} for this target"
        return True, "target and request mode authorized"

    def handler(host: str, port: int, path: str, param: str, mode: str, payloads: list,
                timeout: float) -> str:
        if not scope.check_probe_target(path, param):
            raise PermissionError(f"{path}?{param} is not in allowed_probe_targets")
        expected_mode = request_mode_for_target(path, param)
        if mode != expected_mode:
            raise PermissionError(f"request mode {mode!r} is not authorized for {path}#{param}")
        if not valid_payload_batch(payloads):
            raise ValueError("payload batch violates count/size/control-character limits")

        baseline = transport(host, port, path, param, mode, CONTROL_VALUE, timeout)
        cases = []
        for value in payloads:
            sleeper(INTER_REQUEST_DELAY_S)
            try:
                result = transport(host, port, path, param, mode, value, timeout)
            except Exception as e:  # a single malformed-input response must not erase the rest of the batch
                result = e
            cases.append(_case(value, result, baseline))

        changed = sum(1 for item in cases if item["response_changed"])
        out = {
            "schema_version": "0.1",
            "mode": mode,
            "request_count": len(payloads) + 1,
            "baseline": {
                "status": baseline[0],
                "bytes_read": baseline[1],
                "content_type": baseline[2],
                "truncated": baseline[3],
            },
            "cases": cases,
            "response_changed_count": changed,
        }
        return json.dumps(out, sort_keys=True, separators=(",", ":"))

    return ToolSpec(
        name="payload_fuzz",
        read_only=False,  # active input testing always requires approval, even when the request is GET
        cross_check=cross_check,
        arg_schema={
            "host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
            "port": (int, lambda p: 1 <= p <= 65535),
            "path": (str, lambda v: bool(_PATH_RE.match(v))),
            "param": (str, lambda v: bool(_PARAM_RE.match(v))),
            "mode": (str, lambda v: v in REQUEST_MODES),
            "payloads": (list, valid_payload_batch),
        },
        max_calls=10,
        timeout_s=10.0,
        max_output_bytes=8192,
        handler=handler,
    )
