"""Finding record. Statuses:
  candidate     - produced by a rule, not yet verified
  confirmed     - the observation was reproduced by an independent repeat check (within the stated test scope);
                  this does NOT imply exploitability or impact
  informational - noted for context, no action implied
  inconclusive  - could not be verified, or the check does not apply to how we tested
Severity is never invented: it stays 'not_assessed' until a documented method is applied."""
from __future__ import annotations
import hashlib, platform
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from . import __version__

STATUSES = ("candidate", "confirmed", "informational", "inconclusive")


def finding_id(rule_id: str, asset: str) -> str:
    return "F-" + hashlib.sha256(f"{rule_id}|{asset}".encode()).hexdigest()[:10]


@dataclass
class Finding:
    id: str
    rule_id: str
    asset: str
    title: str
    status: str
    applicability: str
    verification: dict
    evidence: list
    confidence: dict
    severity: dict = field(default_factory=lambda: {
        "rating": "not_assessed",
        "rationale": "No documented severity method has been applied; no CVSS or other score is claimed."})
    weakness_ids: list = field(default_factory=list)      # CWE ids, to be filled from the knowledge base
    references: list = field(default_factory=list)        # to be filled from the knowledge base
    limitations: list = field(default_factory=list)
    remediation: str = ""
    next_steps: str = ""   # human-actionable suggestions ONLY; the agent never acts on this itself
    manual_actions: list = field(default_factory=list)   # human-performed confirmations; see manual_confirm.py
    tool_versions: dict = field(default_factory=lambda: {"pagent": __version__, "python": platform.python_version()})
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"bad status {self.status}")

    def to_dict(self) -> dict:
        return asdict(self)
