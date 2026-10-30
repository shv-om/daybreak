"""POST-JSON variant of the boolean SQLi probe, scoped to a login-style endpoint.
Sends ONLY quote-breaking values (never a tautology like OR 1=1) so a 'signal' result can never
itself BE a successful authentication bypass. The response body is discarded unread beyond
status+length - no token, cookie, or body content is parsed, stored, or acted on."""
from __future__ import annotations
import http.client, json, re
from ..policy import ToolSpec
from .sqli_probe import BASELINE, BREAK, ESCAPE, classify

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]{0,200}$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")
DUMMY_SECRET = "pagentctl-not-a-real-password"   # same fixed value on every call; never varied


def _default_transport(host, port, path, field, value, timeout):
    body = json.dumps({field: f"{value}@pagent.invalid" if field == "email" else value,
                       "password": DUMMY_SECRET}).encode()
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json",
                                                         "User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        length = len(r.read(65536))   # read and discard; body content is never inspected or stored
        return r.status, length
    finally:
        conn.close()


def make_login_sqli_probe(scope, transport=_default_transport) -> ToolSpec:
    cross_check = lambda args: (scope.check_probe_target(args.get("path", ""), args.get("field", "")),
                                "path+field not in allowed_probe_targets")

    def handler(host: str, port: int, path: str, field: str, timeout: float) -> str:
        base = transport(host, port, path, field, BASELINE, timeout)
        brk = transport(host, port, path, field, BREAK, timeout)
        esc = transport(host, port, path, field, ESCAPE, timeout)
        return (f"base_status={base[0]} base_len={base[1]}\nbreak_status={brk[0]} break_len={brk[1]}\n"
                f"escape_status={esc[0]} escape_len={esc[1]}\nsignal={classify(base, brk, esc)}")

    return ToolSpec(name="login_sqli_probe", read_only=False, cross_check=cross_check,
                    arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                                "port": (int, lambda p: 1 <= p <= 65535),
                                "path": (str, lambda v: bool(_PATH_RE.match(v))),
                                "field": (str, lambda v: bool(_FIELD_RE.match(v)))},
                    max_calls=20, timeout_s=10.0, max_output_bytes=512, handler=handler)
