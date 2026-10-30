"""Facet-separated view of a CVE, and CWE enrichment of findings. Sources are never merged into one verdict."""
from __future__ import annotations
import json, time
from .db import KB
from .sources import CVE_RE

DAY = 86400


def _stale(ts, now, days):
    return ts is None or (now - ts) > days * DAY


def describe_cve(kb: KB, cve_id: str, now=None, stale_after_days=7) -> dict:
    if not CVE_RE.match(cve_id):
        raise ValueError("bad CVE id")
    now = now or time.time()
    nvd, kev, ep = kb.get_nvd(cve_id), kb.get_kev(cve_id), kb.get_epss(cve_id)
    kev_src = kb.latest_source("kev")
    if nvd is None:
        existence = {"status": "not_checked", "note": "NVD was not queried for this CVE"}
    elif not nvd["found"]:
        existence = {"status": "not_found_in_nvd", "retrieved_at": nvd["retrieved_at"]}
    else:
        rejected = (nvd["vuln_status"] or "").lower().startswith("rejected")
        existence = {"status": "rejected" if rejected else "published", "nvd_vuln_status": nvd["vuln_status"],
                     "published": nvd["published"], "last_modified": nvd["last_modified"], "source": "NVD",
                     "stale": _stale(nvd["retrieved_at"], now, stale_after_days)}
    weakness = {"status": "not_checked"} if nvd is None or not nvd["found"] else {
        "status": "reported_by_source", "source": "NVD", "weaknesses": nvd["weaknesses"]}
    if kev_src is None:
        k = {"status": "not_checked", "note": "KEV catalog not loaded"}
    elif kev is None:
        k = {"status": "not_listed", "catalog_version": kev_src["version"], "stale": _stale(kev_src["retrieved_at"], now, stale_after_days)}
    else:
        k = {"status": "listed", "date_added": kev["date_added"], "catalog_version": kev["catalog_version"],
             "stale": _stale(kev["retrieved_at"], now, stale_after_days)}
    if ep is None:
        e = {"status": "not_checked"}
    elif not ep["found"]:
        e = {"status": "no_score_returned"}
    else:
        e = {"status": "scored", "epss": ep["epss"], "percentile": ep["percentile"], "score_date": ep["score_date"],
             "stale": _stale(ep["retrieved_at"], now, 2)}
    return {"cve_id": cve_id,
            "existence": existence, "weakness": weakness,
            "exploitation_signals": {"cisa_kev": k, "epss": e,
                                     "note": "Signals about the wild, not proof that THIS target is exploitable."},
            "severity": {"status": "not_assessed", "note": "No documented severity method applied; source scores are not reproduced here."},
            "applicability": {"status": "not_established",
                              "note": "Requires verified product and version evidence for this target. A banner resembling an affected product is not sufficient."},
            "verified_target_impact": {"status": "not_established", "note": "Only a verification step on the target can establish this."}}


def load_mapping(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return {k: v for k, v in json.load(f).items() if not k.startswith("_")}


def enrich_findings(kb: KB, findings: list, mapping: dict) -> int:
    """Attach CWE ids only when the id exists in the ingested CWE catalog. Name and version come from the catalog."""
    n = 0
    for f in findings:
        m = mapping.get(f.rule_id)
        if not m:
            continue
        for cid in m.get("cwe", []):
            row = kb.get_cwe(cid)
            if row is None or cid in f.weakness_ids:
                continue
            f.weakness_ids.append(cid)
            f.references.append(f"{cid}: {row['name']} (CWE list v{row['catalog_version']}); mapping {m.get('review', 'unreviewed')}")
            n += 1
    return n
