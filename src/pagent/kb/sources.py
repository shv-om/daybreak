"""Parsers + validators for KEV and CWE. Parsed text is UNTRUSTED data: stored, never fed raw to the model."""
from __future__ import annotations
import io, json, re, zipfile
import xml.etree.ElementTree as ET
from datetime import date
from ..parse import sanitize


class KBError(ValueError):
    pass


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_REF_RE = re.compile(r"^(CWE-\d+|NVD-CWE-[A-Za-z]+)$")
KEV_REQUIRED = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded")


def _is_date(s) -> bool:
    try:
        date.fromisoformat(s)
        return True
    except (TypeError, ValueError):
        return False


def parse_kev(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise KBError("KEV feed is not valid JSON") from e
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise KBError("KEV feed has no 'vulnerabilities' list")
    entries, rejects, dups, warnings, seen = [], [], [], [], set()
    for i, v in enumerate(data["vulnerabilities"]):
        ident = v.get("cveID", f"#{i}") if isinstance(v, dict) else f"#{i}"
        if not isinstance(v, dict):
            rejects.append((ident, "not an object")); continue
        missing = [k for k in KEV_REQUIRED if not isinstance(v.get(k), str) or not v[k].strip()]
        if missing:
            rejects.append((ident, f"missing {missing}")); continue
        cve = v["cveID"].strip().upper()
        if not CVE_RE.match(cve):
            rejects.append((ident, "bad CVE id")); continue
        if not _is_date(v["dateAdded"]):
            rejects.append((cve, "bad dateAdded")); continue
        if cve in seen:
            dups.append(cve); continue
        seen.add(cve)
        due = v.get("dueDate") or ""
        if due and not _is_date(due):
            warnings.append(f"{cve}: invalid dueDate ignored"); due = ""
        cwes = [c for c in (v.get("cwes") or []) if isinstance(c, str) and CWE_REF_RE.match(c)]
        entries.append({"cve_id": cve, "vendor": sanitize(v["vendorProject"], 200), "product": sanitize(v["product"], 200),
                        "name": sanitize(v["vulnerabilityName"], 300), "date_added": v["dateAdded"], "due_date": due,
                        "ransomware_use": sanitize(str(v.get("knownRansomwareCampaignUse", "")), 40),
                        "cwes_json": json.dumps(sorted(cwes)), "short_description": sanitize(str(v.get("shortDescription", "")), 2000),
                        "required_action": sanitize(str(v.get("requiredAction", "")), 1000)})
    declared = data.get("count")
    if isinstance(declared, int) and declared != len(data["vulnerabilities"]):
        warnings.append(f"declared count {declared} != {len(data['vulnerabilities'])} entries present")
    return {"version": str(data.get("catalogVersion", "")), "entries": entries, "rejects": rejects,
            "duplicates": dups, "warnings": warnings}


def read_zip_text(raw: bytes, max_uncompressed: int = 300 * 2**20) -> str:
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        xmls = [i for i in z.infolist() if i.filename.lower().endswith(".xml")]
        if len(xmls) != 1:
            raise KBError("expected exactly one XML file in the zip")
        if xmls[0].file_size > max_uncompressed:
            raise KBError("XML in zip is unexpectedly large")
        return z.read(xmls[0]).decode("utf-8")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_cwe_xml(text: str) -> dict:
    if "<!ENTITY" in text:
        raise KBError("entity declarations not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise KBError("CWE XML is not parseable") from e
    entries, rejects, dups, seen = [], [], [], set()
    for el in root.iter():
        if _local(el.tag) != "Weakness":
            continue
        raw_id, name = el.get("ID", ""), el.get("Name", "")
        if not raw_id.isdigit() or not name.strip():
            rejects.append((raw_id or "?", "bad ID or missing name")); continue
        cid = f"CWE-{int(raw_id)}"
        if cid in seen:
            dups.append(cid); continue
        seen.add(cid)
        desc = next((c.text or "" for c in el if _local(c.tag) == "Description"), "")
        entries.append({"cwe_id": cid, "name": sanitize(name, 300), "abstraction": sanitize(el.get("Abstraction", ""), 30),
                        "status": sanitize(el.get("Status", ""), 30), "description": sanitize(" ".join(desc.split()), 2000)})
    return {"version": root.get("Version", ""), "entries": entries, "rejects": rejects, "duplicates": dups, "warnings": []}
