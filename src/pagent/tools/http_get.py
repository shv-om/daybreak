"""Read-only adapter: one HTTP GET of an explicitly scoped path (see Scope.check_crawl_seed).
Same read_only=True tier as http_head - no approval required - but GET can reach more of an
application than HEAD /, so the path argument is cross-checked against scope.crawl_seeds the same
way sqli_probe/login_sqli_probe cross-check path+param against allowed_probe_targets. No form is
submitted, no header or cookie beyond a fixed User-Agent is sent, and the response body is capped
hard at a few tens of KB regardless of what the server sends."""
from __future__ import annotations
import http.client
import re
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.~%-]{0,255}$")
_BODY_CAP = 65536


def _default_transport(host: str, port: int, path: str, timeout: float):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        content_type = r.getheader("Content-Type", "")
        body = r.read(_BODY_CAP)
        return r.status, content_type, body.decode("utf-8", "replace")
    finally:
        conn.close()


def make_http_get(scope, transport=_default_transport) -> ToolSpec:
    def handler(host: str, port: int, path: str, timeout: float) -> str:
        if not scope.check_crawl_seed(path):
            raise PermissionError(f"{path} is not in crawl_seeds")
        status, content_type, body = transport(host, port, path, timeout)
        return f"status={status}\ncontent-type={content_type}\n\n{body}"

    cross_check = lambda args: (scope.check_crawl_seed(args.get("path", "")), "path not in crawl_seeds")
    return ToolSpec(
        name="http_get", read_only=True, cross_check=cross_check,
        arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                    "port": (int, lambda p: 1 <= p <= 65535),
                    "path": (str, lambda v: bool(_PATH_RE.match(v)))},
        max_calls=50, timeout_s=8.0, max_output_bytes=_BODY_CAP + 256, handler=handler)
