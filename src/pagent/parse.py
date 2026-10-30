"""Deterministic parsing of tool output into structured observations.
Raw tool output is untrusted evidence: it is stored, never fed to the model verbatim."""
from __future__ import annotations
import re
import urllib.parse
import xml.etree.ElementTree as ET

_NONPRINT = re.compile(r"[^\x20-\x7e]")
_HEADER_NAME = re.compile(r"^[a-z0-9-]{1,64}$")
_PRODUCT = re.compile(r"^[A-Za-z0-9._-]{1,40}(/[0-9][A-Za-z0-9._-]{0,20})?")
_MIME = re.compile(r"^[a-z0-9.+-]{1,40}/[a-z0-9.+-]{1,40}")

SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy")


def sanitize(value: str, limit: int = 200) -> str:
    return _NONPRINT.sub("?", value)[:limit]


def parse_http_head(output: str) -> list:
    """Returns [(kind, key, value)] from the http_head adapter's text format."""
    obs = []
    for line in output.splitlines():
        if line.startswith("status="):
            code = line[7:].strip()
            if code.isdigit() and 100 <= int(code) <= 599:
                obs.append(("http_status", "status", code))
        elif ": " in line:
            name, value = line.split(": ", 1)
            name = name.strip().lower()
            if _HEADER_NAME.match(name):
                obs.append(("http_header", name, sanitize(value)))
    return obs


def model_view(observations: list) -> list:
    """Compact, whitelisted facts for the planner. Free text from the target is reduced to a
    product/version token or a MIME type; security headers are presence flags only.
    LIMITATION: this narrows the injection surface, it does not make target data trustworthy."""
    by_asset: dict = {}
    for asset, kind, key, value in observations:
        by_asset.setdefault(asset, []).append((kind, key, value))
    out = []
    for asset, items in sorted(by_asset.items()):
        headers = {k: v for kind, k, v in items if kind == "http_header"}
        facts = {"asset": asset}
        for kind, k, v in items:
            if kind == "http_status":
                facts["status"] = int(v)
        for name in ("server", "x-powered-by"):
            m = _PRODUCT.match(headers.get(name, ""))
            if m:
                facts[name] = m.group(0)
        m = _MIME.match(headers.get("content-type", "").lower())
        if m:
            facts["content_type"] = m.group(0)
        facts["security_headers_present"] = [h for h in SECURITY_HEADERS if h in headers]
        facts["security_headers_absent"] = [h for h in SECURITY_HEADERS if h not in headers]
        out.append(facts)
    return out


_PORT_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}


def parse_nmap_xml(text: str) -> list:
    """[(kind, key, value)] from nmap -oX output. Raises ValueError on bad or suspicious XML.
    Service names here come from nmap's port-number table (no -sV), so they are GUESSES."""
    if "<!ENTITY" in text:
        raise ValueError("entity declarations not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError("unparseable nmap XML") from e
    obs = []
    for port in root.iter("port"):
        state, svc = port.find("state"), port.find("service")
        proto, pid = port.get("protocol", ""), port.get("portid", "")
        if state is None or proto not in ("tcp", "udp") or not pid.isdigit() or state.get("state") not in _PORT_STATES:
            continue
        obs.append(("port_state", f"{proto}/{pid}", state.get("state")))
        if svc is not None and svc.get("name"):
            obs.append(("port_service_guess", f"{proto}/{pid}", sanitize(svc.get("name"), 40)))
    return obs


def parse_http_get(output: str) -> dict:
    """{'status': int|None, 'content_type': str, 'body': str} from the http_get adapter's text
    format (status/content-type header lines, a blank line, then the body verbatim). The body is
    returned AS IS - still untrusted, still never fed to the model; extract_links/extract_js_signals
    below are what reduce it to short, sanitized, whitelisted-shape fragments worth storing."""
    head, _, body = output.partition("\n\n")
    status, content_type = None, ""
    for line in head.splitlines():
        if line.startswith("status="):
            v = line[7:].strip()
            if v.isdigit() and 100 <= int(v) <= 599:
                status = int(v)
        elif line.startswith("content-type="):
            content_type = sanitize(line[13:], 100)
    return {"status": status, "content_type": content_type, "body": body}


_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#\s>]{1,500})["\']', re.I)
_MAX_LINKS = 100


def extract_links(body: str, base_host: str, base_port: int) -> list:
    """Regex-only extraction (no HTML parser - nothing the page contains is ever executed or
    rendered) of href/src/action attribute values from an already-fetched page, resolved against
    the page's own host:port. Returns up to _MAX_LINKS distinct
    {'path': str, 'params': [str,...], 'is_script': bool, 'same_host': bool} dicts. Nothing
    returned here is fetched by this function - pagent.discover.run_crawl only ever fetches a path
    that is ALSO explicitly listed in scope.crawl_seeds; everything else is a candidate for a
    human to review and add next time, never auto-followed."""
    base = f"http://{base_host}:{base_port}/"
    same_host_netlocs = {base_host.lower(), f"{base_host}:{base_port}".lower()}
    seen, out = set(), []
    for raw in _LINK_RE.findall(body):
        if len(out) >= _MAX_LINKS:
            break
        try:
            u = urllib.parse.urlsplit(urllib.parse.urljoin(base, raw))
        except ValueError:
            continue
        if u.scheme not in ("http", "https") or not u.path.startswith("/"):
            continue
        params = tuple(sorted({k for k, v in urllib.parse.parse_qsl(u.query)}))
        same_host = u.netloc.lower() in same_host_netlocs
        key = (u.path, params, same_host)
        if key in seen:
            continue
        seen.add(key)
        out.append({"path": sanitize(u.path, 200), "params": [sanitize(p, 60) for p in params],
                    "is_script": u.path.lower().endswith(".js"), "same_host": same_host})
    return out


_JS_ENDPOINT_RE = re.compile(r'["\'](/[A-Za-z][A-Za-z0-9_\-/]{1,78})["\']')
_JS_SECRET_RE = re.compile(r'(?i)\b(?:api[_-]?key|secret|token|auth)\w*\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{16,80})["\']')
_AWS_KEY_RE = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_MAX_JS_SIGNALS = 50


def _redact(secret: str) -> str:
    return secret[:4] + "..." + secret[-4:] if len(secret) > 8 else "*" * len(secret)


def extract_js_signals(body: str) -> list:
    """Heuristic regex scan of already-fetched JavaScript source text. Returns [(kind, key, value)]:
    'js_endpoint_candidate' for quoted, path-shaped string literals that MIGHT be an API endpoint,
    and 'js_secret_candidate' for assignment-shaped strings that LOOK like a credential (value
    always redacted before being returned - the full secret is never stored). Both have a real
    false-positive rate; this is a heuristic for a human to triage, never a confirmed finding -
    see rules.candidates_from_crawl for how it is reported."""
    out = []
    for m in sorted(set(_JS_ENDPOINT_RE.findall(body)))[:_MAX_JS_SIGNALS]:
        out.append(("js_endpoint_candidate", "path", sanitize(m, 80)))
    secrets = set(_JS_SECRET_RE.findall(body)) | set(_AWS_KEY_RE.findall(body))
    for m in sorted(secrets)[:_MAX_JS_SIGNALS]:
        out.append(("js_secret_candidate", "redacted_value", _redact(sanitize(m, 80))))
    return out


def make_xss_marker(token: str) -> tuple:
    """Returns (value_to_send, html_needle). The needle is a short HTML-meaningful fragment embedded
    in a value unique enough that any match is overwhelmingly likely to be this exact probe."""
    value = f"pagentmk{token}<pagentmk>"
    return value, f"<pagentmk>"


def reflection_signal(body: str, token: str) -> str:
    """'raw' if the probe's angle brackets appear unescaped in body (reflected, unneutralized),
    'escaped' if only the HTML-entity form appears, 'absent' if the token isn't in body at all.
    Textual check only - never executes anything and cannot confirm a real DOM XSS."""
    value, needle = make_xss_marker(token)
    if f"pagentmk{token}" not in body:
        return "absent"
    if needle in body:
        return "raw"
    if needle.replace("<", "&lt;").replace(">", "&gt;") in body:
        return "escaped"
    return "present_unparsed"   # token found but the specific bracket fragment wasn't recognizable either way


def parse_reflect_probe(output: str) -> dict:
    d = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    return {"status": d.get("status"), "signal": d.get("signal", "absent")}


def parse_dir_probe(output: str) -> dict:
    d = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    status = d.get("status", "")
    length = d.get("content-length", "")
    return {"status": int(status) if status.isdigit() else None,
           "content_type": d.get("content-type", ""),
           "content_length": int(length) if length.isdigit() else None}


def parse_sqli_probe(output: str) -> dict:
    d = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    return {"signal": d.get("signal", "no_signal")}


def parse_fuzz_probe(output: str) -> dict:
    """fuzz_probe (either category) writes one 'token=...' line (reflected_input only) plus one
    line per variant shaped 'name_status=.. name_len=..' / 'name_differs=yes|no' (sql_injection)
    or 'name_status=.. name_signal=raw|escaped|absent|present_unparsed' (reflected_input).
    Returns {"token": str|None, "variants": {name: {field: value, ...}, ...}}."""
    token = None
    variants: dict = {}
    for line in output.splitlines():
        for part in line.split():          # each line can hold several space-separated key=value pairs
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key == "token":
                token = value
                continue
            for suffix in ("_status", "_len", "_differs", "_signal"):
                if key.endswith(suffix):
                    name = key[: -len(suffix)]
                    variants.setdefault(name, {})[suffix[1:]] = value
                    break
    return {"token": token, "variants": variants}
