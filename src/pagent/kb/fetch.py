"""Only fixed, allowlisted source URLs can be fetched. The model never supplies a URL."""
from __future__ import annotations
import urllib.request
from .sources import KBError

ALLOWED = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
}


def fetch_source(source: str, opener=urllib.request.urlopen, timeout: float = 60.0, max_bytes: int = 100 * 2**20):
    if source not in ALLOWED:
        raise KBError(f"unknown source {source!r}")
    url = ALLOWED[source]
    req = urllib.request.Request(url, headers={"User-Agent": "pagent-kb/0.1"})
    with opener(req, timeout=timeout) as r:
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise KBError("download exceeds size limit")
    return url, data
