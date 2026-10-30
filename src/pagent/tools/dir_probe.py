"""Read-only content-discovery adapter: ONE GET of a path built by joining one of
scope.discovery_prefixes with ONE candidate segment from the small, checked-in wordlist at
config/content_discovery_wordlist.json (see pagent.wordlist for how that file is loaded and
validated, and pagent.discover.run_content_discovery for the loop that calls this once per
prefix x candidate).

This is explicitly NOT ffuf/wfuzz/gobuster/any external binary, and NOT a general-purpose path
fetch: cross_check only accepts a path that starts with one of scope.discovery_prefixes (a human
must have explicitly named that prefix), and which candidate segment can ever be appended is
bounded, by construction, to the small fixed wordlist the orchestrator iterates over - nothing
from a model or a user ever supplies the path or the candidate segment at request time, the same
discipline as sqli_probe's/reflect_probe's internally-fixed values.

Same read_only=True (no per-call approval) tier as http_head/http_get/crawl: a GET that checks
whether a well-known, benign filename exists is the same risk shape as fetching a path already
known to exist. The response BODY is read-and-discarded, never stored or returned - only status,
content-type, and content-length are reported, since content discovery only needs "does this
exist", not the page content.
"""
from __future__ import annotations
import http.client
import re
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.~%-]{0,255}$")


def _default_transport(host: str, port: int, path: str, timeout: float):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        status, content_type = r.status, r.getheader("Content-Type", "")
        length = len(r.read(65536))   # read-and-discard: frees the connection; body itself is never stored/returned
        return status, content_type, length
    finally:
        conn.close()


def make_dir_probe(scope, transport=_default_transport) -> ToolSpec:
    def handler(host: str, port: int, path: str, timeout: float) -> str:
        if not scope.check_discovery_path(path):
            raise PermissionError(f"{path} does not start with any scope.discovery_prefixes entry")
        status, content_type, length = transport(host, port, path, timeout)
        return f"status={status}\ncontent-type={content_type}\ncontent-length={length}"

    cross_check = lambda args: (scope.check_discovery_path(args.get("path", "")),
                                "path not under any scope.discovery_prefixes entry")
    return ToolSpec(
        name="dir_probe", read_only=True, cross_check=cross_check,
        arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                    "port": (int, lambda p: 1 <= p <= 65535),
                    "path": (str, lambda v: bool(_PATH_RE.match(v)))},
        max_calls=300, timeout_s=8.0, max_output_bytes=256, handler=handler)
