"""ONE narrow intrusive adapter: payload FUZZING, in the sense of trying several fixed, reviewed
diagnostic values against ONE explicitly scoped path+param and comparing/reporting per-variant -
NOT a wordlist tool, NOT content/directory discovery (that is a separate, later increment), and
NOT a channel for any model- or user-supplied string. Every value sent by this tool is a literal
constant defined right here, selected only by `category`; nothing about which bytes get sent is
ever read from model output, exactly like sqli_probe.BASELINE/BREAK/ESCAPE and
reflect_probe.make_xss_marker. No tautology (no "OR 1=1" shape), no comment-based auth-bypass
shape, no destructive or data-mutating syntax, no browser, no script execution - this still only
measures response-shape/reflection differences, same discipline as the two existing probes this
one complements rather than replaces.

sql_injection category: an expanded syntax-probing battery (quote/backslash/comment-token) beyond
the single boolean pair sqli_probe already sends - broader coverage of "does this special
character change the response at all", not a stricter boolean-pattern classifier like
sqli_probe.classify(). Use both: sqli_probe for the classic boolean-pair pattern, fuzz_probe for
wider syntax coverage.

reflected_input category: three distinct marker shapes (angle brackets, double quote, single
quote) instead of reflect_probe's one, so you can see which specific HTML-meaningful characters
survive unescaped and which don't - still a textual check over one response, never a browser,
never confirms a real DOM XSS.
"""
from __future__ import annotations
import http.client, re, secrets, urllib.parse
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]{0,200}$")
_PARAM_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")
CATEGORIES = ("sql_injection", "reflected_input")

# Fixed, reviewed, non-destructive syntax-probe values ONLY. Deliberately small - this is not a
# payload library (see project README's "Important Decision"); it exists to broaden signal
# coverage a little beyond the single quote/escaped-quote pair sqli_probe already sends, not to
# enumerate every known SQLi shape.
SQLI_VARIANTS = (
    ("baseline", "pagentfz"),
    ("single_quote", "pagentfz'"),
    ("double_quote", 'pagentfz"'),
    ("escaped_quote", "pagentfz''"),
    ("backslash", "pagentfz\\"),
    ("sql_comment", "pagentfz--"),
)

# name -> the HTML-meaningful character(s) this variant probes.
XSS_VARIANTS = (("angle_bracket", "<>"), ("double_quote", '"'), ("single_quote", "'"))
_ESCAPE_MAP = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}


def _default_sqli_transport(host, port, path, param, value, timeout):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        url = f"{path}?{urllib.parse.urlencode({param: value})}"
        conn.request("GET", url, headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        return r.status, len(r.read(65536))
    finally:
        conn.close()


def _default_reflect_transport(host, port, path, param, value, timeout):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        url = f"{path}?{urllib.parse.urlencode({param: value})}"
        conn.request("GET", url, headers={"User-Agent": "pagent/0.1 (authorized-lab)"})
        r = conn.getresponse()
        return r.status, r.read(65536).decode("utf-8", "replace")
    finally:
        conn.close()


def _run_sqli_fuzz(host, port, path, param, timeout, transport) -> str:
    results = {name: transport(host, port, path, param, value, timeout) for name, value in SQLI_VARIANTS}
    base = results["baseline"]
    lines = [f"baseline_status={base[0]} baseline_len={base[1]}"]
    for name, _ in SQLI_VARIANTS:
        if name == "baseline":
            continue
        status, length = results[name]
        differs = "yes" if (status, length) != base else "no"
        lines.append(f"{name}_status={status} {name}_len={length} {name}_differs={differs}")
    return "\n".join(lines)


def _xss_marker(token: str, chars: str) -> str:
    return f"pagentfz{token}{chars}pagentfz"


def _variant_signal(body: str, token: str, chars: str) -> str:
    marker = f"pagentfz{token}"
    if marker not in body:
        return "absent"
    if _xss_marker(token, chars) in body:
        return "raw"
    escaped_chars = "".join(_ESCAPE_MAP.get(c, c) for c in chars)
    if _xss_marker(token, escaped_chars) in body:
        return "escaped"
    return "present_unparsed"


def _run_reflect_fuzz(host, port, path, param, timeout, transport) -> str:
    token = secrets.token_hex(6)
    lines = [f"token={token}"]
    for name, chars in XSS_VARIANTS:
        status, body = transport(host, port, path, param, _xss_marker(token, chars), timeout)
        lines.append(f"{name}_status={status} {name}_signal={_variant_signal(body, token, chars)}")
    return "\n".join(lines)


def make_fuzz_probe(scope, sqli_transport=_default_sqli_transport,
                    reflect_transport=_default_reflect_transport) -> ToolSpec:
    def handler(host: str, port: int, path: str, param: str, category: str, timeout: float) -> str:
        if not scope.check_probe_target(path, param):
            raise PermissionError(f"{path}?{param} is not in allowed_probe_targets")
        if category == "sql_injection":
            return _run_sqli_fuzz(host, port, path, param, timeout, sqli_transport)
        return _run_reflect_fuzz(host, port, path, param, timeout, reflect_transport)   # "reflected_input"; arg_schema already restricts category to CATEGORIES

    cross_check = lambda args: (scope.check_probe_target(args.get("path", ""), args.get("param", "")), "path+param not in allowed_probe_targets")
    return ToolSpec(name="fuzz_probe", read_only=False, cross_check=cross_check,
                    arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))),
                                "port": (int, lambda p: 1 <= p <= 65535),
                                "path": (str, lambda v: bool(_PATH_RE.match(v))),
                                "param": (str, lambda v: bool(_PARAM_RE.match(v))),
                                "category": (str, lambda v: v in CATEGORIES)},
                    max_calls=20, timeout_s=15.0, max_output_bytes=2048, handler=handler)
