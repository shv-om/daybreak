"""ONE narrow intrusive adapter: sends a single fixed, inert marker string as a query-string value
to an explicitly scoped path+param and reports whether it was reflected unescaped in the response.
No script execution, no browser, no arbitrary payload from the model - the marker shape is fixed here."""
from __future__ import annotations
import http.client, re, secrets, urllib.parse
from ..parse import make_xss_marker, reflection_signal
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]{0,200}$")
_PARAM_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")


def _default_transport(host, port, path, param, value, timeout):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        url = f"{path}?{urllib.parse.urlencode({param: value})}"
        conn.request("GET", url, headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        return r.status, r.read(65536).decode("utf-8", "replace")
    finally:
        conn.close()


def make_reflect_probe(scope, transport=_default_transport) -> ToolSpec:
    def handler(host: str, port: int, path: str, param: str, timeout: float) -> str:
        if not scope.check_probe_target(path, param):
            raise PermissionError(f"{path}?{param} is not in allowed_probe_targets")
        token = secrets.token_hex(6)
        value, _ = make_xss_marker(token)
        status, body = transport(host, port, path, param, value, timeout)
        return f"status={status}\ntoken={token}\nsignal={reflection_signal(body, token)}"

    cross_check = lambda args: (scope.check_probe_target(args.get("path", ""), args.get("param", "")), "path+param not in allowed_probe_targets")
    return ToolSpec(name="reflect_probe", read_only=False, cross_check=cross_check,
                    arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                                "port": (int, lambda p: 1 <= p <= 65535),
                                "path": (str, lambda v: bool(_PATH_RE.match(v))),
                                "param": (str, lambda v: bool(_PARAM_RE.match(v)))},
                    max_calls=20, timeout_s=10.0, max_output_bytes=2048, handler=handler)
