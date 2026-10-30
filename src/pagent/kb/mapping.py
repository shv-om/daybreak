"""Curated rule -> CWE mapping. Humans own it; code only validates it against the CWE snapshot.
Only mappings with review_status == 'reviewed' are attached to findings unless include_proposed=True."""
from __future__ import annotations
import json, re
from ..rules import HEADER_RULES

KNOWN_RULES = {"open-port", "missing-header:strict-transport-security",
               *[f"missing-header:{h}" for h in HEADER_RULES]}
_CWE = re.compile(r"^CWE-\d+$")
STATUSES = ("proposed", "reviewed")


def load_mapping(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["mappings"]


def check_mapping(mapping: dict) -> list:
    """Structural problems. Every known rule needs an explicit entry (an empty list is a decision)."""
    problems = [f"unknown rule: {r}" for r in mapping if r not in KNOWN_RULES]
    problems += [f"missing entry for rule: {r}" for r in sorted(KNOWN_RULES - set(mapping))]
    for r, m in mapping.items():
        if not isinstance(m.get("cwe_ids"), list) or not all(isinstance(c, str) and _CWE.match(c) for c in m["cwe_ids"]):
            problems.append(f"{r}: cwe_ids must be a list of 'CWE-<n>'")
        if m.get("review_status") not in STATUSES:
            problems.append(f"{r}: review_status must be one of {STATUSES}")
        if not str(m.get("rationale", "")).strip():
            problems.append(f"{r}: rationale required")
    return problems


def check_against_kb(mapping: dict, kb) -> list:
    """One row per (rule, CWE): name from the snapshot so a human can confirm it matches the intent."""
    rows = []
    for rule, m in sorted(mapping.items()):
        for cid in m.get("cwe_ids", []):
            e = kb.cwe_lookup(cid)
            problem = "not in CWE snapshot" if e is None else ("deprecated in snapshot" if e["status"] == "Deprecated" else "")
            rows.append({"rule": rule, "cwe_id": cid, "name": e["name"] if e else None,
                         "status": e["status"] if e else None, "problem": problem,
                         "review_status": m.get("review_status")})
    return rows


def enrich_findings(findings: list, kb, mapping: dict, include_proposed: bool = False) -> dict:
    info = kb.latest_snapshot_info("cwe")
    attached, skipped = {}, []
    for f in findings:
        m = mapping.get(f.rule_id)
        if not m or not m["cwe_ids"]:
            continue
        if m["review_status"] != "reviewed" and not include_proposed:
            skipped.append((f.id, "mapping not reviewed")); continue
        for cid in m["cwe_ids"]:
            e = kb.cwe_lookup(cid)
            if e is None or e["status"] == "Deprecated" or info is None:
                f.limitations.append(f"Mapped {cid} was not attached: missing from the CWE snapshot or deprecated.")
                skipped.append((f.id, f"{cid} unusable")); continue
            if cid in f.weakness_ids:
                continue
            f.weakness_ids.append(cid)
            f.references.append(f"{cid}: {e['name']} - https://cwe.mitre.org/data/definitions/{int(cid[4:])}.html "
                                f"(CWE v{info['source_version']}, entry status {e['status']}, KB snapshot {info['id']}; mapping {m['review_status']})")
            attached.setdefault(f.id, []).append(cid)
    return {"attached": attached, "skipped": skipped}
