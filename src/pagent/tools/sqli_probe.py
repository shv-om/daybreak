"""ONE narrow intrusive adapter: a classic boolean-pair probe (quote vs escaped-quote) against an
explicitly scoped path+param, comparing status and body length. Read-only requests (GET) - no
login attempted, no data extracted, no write performed. Reports a signal only; never claims impact."""
from __future__ import annotations
import http.client, re, urllib.parse
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]{0,200}$")
_PARAM_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")
BASELINE, BREAK, ESCAPE = "pagentsqlictl", "pagentsqlictl'", "pagentsqlictl''"


def _default_transport(host, port, path, param, value, timeout):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        url = f"{path}?{urllib.parse.urlencode({param: value})}"
        conn.request("GET", url, headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        return r.status, len(r.read(65536))
    finally:
        conn.close()


def classify(base, brk, esc) -> str:
    """base=(status,len) for the control value; brk for the single-quote value; esc for the
    doubled (escaped) quote value. 'signal' means brk differs from BOTH base and esc while esc
    matches base - the classic boolean-based pattern. Anything else is reported as 'no_signal'."""
    if brk != base and brk != esc and esc == base:
        return "signal"
    return "no_signal"


def make_sqli_probe(scope, transport=_default_transport) -> ToolSpec:
    def handler(host: str, port: int, path: str, param: str, timeout: float) -> str:
        if not scope.check_probe_target(path, param):
            raise PermissionError(f"{path}?{param} is not in allowed_probe_targets")
        base = transport(host, port, path, param, BASELINE, timeout)
        brk = transport(host, port, path, param, BREAK, timeout)
        esc = transport(host, port, path, param, ESCAPE, timeout)
        return (f"base_status={base[0]} base_len={base[1]}\nbreak_status={brk[0]} break_len={brk[1]}\n"
                f"escape_status={esc[0]} escape_len={esc[1]}\nsignal={classify(base, brk, esc)}")

    cross_check = lambda args: (scope.check_probe_target(args.get("path", ""), args.get("param", "")), "path+param not in allowed_probe_targets")
    return ToolSpec(name="sqli_probe", read_only=False, cross_check=cross_check,
                    arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                                "port": (int, lambda p: 1 <= p <= 65535),
                                "path": (str, lambda v: bool(_PATH_RE.match(v))),
                                "param": (str, lambda v: bool(_PARAM_RE.match(v)))},
                    max_calls=20, timeout_s=10.0, max_output_bytes=1024, handler=handler)
