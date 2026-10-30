"""Verification: an independent repeat request through the policy gateway, then compare."""
from __future__ import annotations
from .parse import parse_http_head


def verify_candidates(gateway, store, run_id: int, findings: list) -> None:
    by_asset: dict = {}
    for f in findings:
        if f.status == "candidate" and f.verification.get("method") == "pending":
            by_asset.setdefault(f.asset, []).append(f)
    for asset, fs in by_asset.items():
        host, port = asset.rsplit(":", 1)
        args = {"host": host, "port": int(port)}
        res = gateway.execute("http_head", args, proposed_by="deterministic")
        call_id = store.record_tool_call(run_id, "http_head", args, res)
        headers, obs_ids = None, []
        if res["ok"]:
            obs = parse_http_head(res["untrusted_output"])
            if any(o[0] == "http_status" for o in obs):
                headers = {key for kind, key, _ in obs if kind == "http_header"}
            for kind, key, value in obs:
                obs_ids.append(store.add_observation(run_id, call_id, asset, kind, key, value))
        sha = store.tool_call_row(call_id)["output_sha256"]
        for f in fs:
            f.evidence.append({"tool_call_id": call_id, "observation_ids": obs_ids, "output_sha256": sha, "role": "verification"})
            header = f.rule_id.split(":", 1)[1]
            method = "independent repeat of HEAD / through the policy gateway"
            if headers is None:
                f.status = "inconclusive"
                f.verification = {"method": method, "result": "error_or_no_valid_response", "repeats": 1}
                f.confidence = {"level": "low", "why": "verification request failed or was denied"}
            elif header in headers:
                f.status = "inconclusive"
                f.verification = {"method": method, "result": "not_reproduced_header_present_on_repeat", "repeats": 1}
                f.confidence = {"level": "low", "why": "the two responses disagree"}
            else:
                f.status = "confirmed"
                f.verification = {"method": method, "result": "reproduced_header_absent_in_both_responses", "repeats": 1}
                f.confidence = {"level": "medium",
                                "why": "two independent responses agree; only HEAD / was tested"}
