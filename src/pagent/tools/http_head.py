"""Read-only adapter: one HTTP HEAD request. Transport is injectable for tests."""
from __future__ import annotations
import http.client
import re
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def _default_transport(host: str, port: int, timeout: float):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("HEAD", "/", headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        return r.status, dict(r.getheaders())
    finally:
        conn.close()


def make_http_head(transport=_default_transport) -> ToolSpec:
    def handler(host: str, port: int, timeout: float) -> str:
        status, headers = transport(host, port, timeout)
        lines = [f"status={status}"] + [f"{k}: {v}" for k, v in sorted(headers.items())]
        return "\n".join(lines)

    return ToolSpec(
        name="http_head", read_only=True,
        arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                    "port": (int, lambda p: 1 <= p <= 65535)},
        max_calls=50, timeout_s=5.0, max_output_bytes=4096, handler=handler)
