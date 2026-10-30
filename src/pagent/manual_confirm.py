"""Human-performed exploitation confirmation. This module records what a HUMAN did; nothing here
sends any request to any target. The agent never constructs or sends an exploit payload - a person
runs it themselves (browser, curl, Burp, etc.) and reports back what happened, verbatim."""
from __future__ import annotations
from datetime import datetime, timezone
from .parse import sanitize

REQUIRED = ("performed_by", "action_description", "payload_sent", "observed_result")


class ManualConfirmError(ValueError):
    pass


def apply_manual_action(finding: dict, performed_by: str, action_description: str, payload_sent: str,
                        observed_result: str, notes: str = "") -> dict:
    """Returns an updated finding dict. Pure function: takes/returns dicts, touches no I/O, no network."""
    values = {"performed_by": performed_by, "action_description": action_description,
             "payload_sent": payload_sent, "observed_result": observed_result}
    empty = [k for k, v in values.items() if not str(v).strip()]
    if empty:
        raise ManualConfirmError(f"required and cannot be empty: {empty}")
    entry = {"performed_by": sanitize(performed_by, 100), "performed_at": datetime.now(timezone.utc).isoformat(),
             "action_description": sanitize(action_description, 2000), "payload_sent": sanitize(payload_sent, 2000),
             "observed_result": sanitize(observed_result, 2000), "notes": sanitize(notes, 1000)}
    out = dict(finding)
    out["manual_actions"] = [*finding.get("manual_actions", []), entry]
    out["status"] = "confirmed"
    out["verification"] = {"method": "human-performed manual action (see Manual confirmation log below); "
                                     "not executed, constructed, or sent by this tool",
                           "result": "reproduced_by_human", "repeats": len(out["manual_actions"])}
    out["confidence"] = {"level": "high", "why": "a human operator directly performed and observed this action"}
    out["limitations"] = [*finding.get("limitations", []),
                          "Confirmed by human-reported action, not independently re-verified by this tool; "
                          "the payload and result above are exactly as the operator entered them."]
    return out
