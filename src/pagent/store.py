"""SQLite evidence store: runs, tool calls (with raw untrusted output) and structured observations."""
from __future__ import annotations
import hashlib, json, sqlite3, time
from dataclasses import asdict


def _call_asset(args: dict) -> str:
    """Same 'host:port[path]' convention used for observation assets everywhere else in this
    project (pagent.discover, pagent.intrusive, pagent.fuzz) - built from a tool call's own args
    so filtering doesn't depend on any extra bookkeeping at call time."""
    return f"{args.get('host', '')}:{args.get('port', '')}{args.get('path', '')}"


def _ledger_target(args: dict) -> str:
    """Human-readable asset label that omits request values and payload contents."""
    host, port, path = args.get("host"), args.get("port"), args.get("path", "")
    if host is None and port is None and not path:
        return ""
    endpoint = f"{host or '?'}:{port or '?'}"
    return endpoint + str(path)

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY, engagement_id TEXT NOT NULL, scope_sha256 TEXT NOT NULL, started_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tool_calls(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id), tool TEXT NOT NULL,
  args_json TEXT NOT NULL, allowed INTEGER NOT NULL, reason TEXT, output_sha256 TEXT,
  raw_output_untrusted TEXT, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS action_events(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id), ts REAL NOT NULL,
  event_type TEXT NOT NULL, action_name TEXT, tool TEXT, args_json TEXT,
  rationale TEXT, decision TEXT, outcome TEXT, details_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS action_events_run ON action_events(run_id, id);
CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
  tool_call_id INTEGER NOT NULL REFERENCES tool_calls(id), asset TEXT NOT NULL,
  kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS obs_run ON observations(run_id);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, run_id INTEGER NOT NULL, data_json TEXT NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS manual_actions(
  id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id), performed_by TEXT NOT NULL,
  performed_at REAL NOT NULL, action_description TEXT NOT NULL, payload_sent TEXT NOT NULL,
  observed_result TEXT NOT NULL, notes TEXT, row_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proposal_outcomes(
  id INTEGER PRIMARY KEY, run_id INTEGER, model TEXT, hypothesis_id TEXT NOT NULL, payload_id TEXT NOT NULL,
  weakness_type TEXT NOT NULL, category TEXT NOT NULL, payload_text TEXT NOT NULL,
  outcome TEXT NOT NULL, tested_by TEXT NOT NULL, tested_at REAL NOT NULL,
  observed_result TEXT NOT NULL, notes TEXT, row_sha256 TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS proposal_outcomes_run ON proposal_outcomes(run_id);
CREATE INDEX IF NOT EXISTS proposal_outcomes_payload ON proposal_outcomes(payload_id);
"""


def scope_fingerprint(scope) -> str:
    d = {k: (sorted(map(str, v)) if isinstance(v, (frozenset, tuple)) else str(v))
         for k, v in asdict(scope).items()}
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def start_run(self, scope) -> int:
        cur = self.db.execute("INSERT INTO runs(engagement_id, scope_sha256, started_at) VALUES(?,?,?)",
                              (scope.engagement_id, scope_fingerprint(scope), time.time()))
        self.db.commit()
        return cur.lastrowid

    def record_tool_call(self, run_id: int, tool: str, args: dict, result: dict) -> int:
        out = result.get("untrusted_output")
        cur = self.db.execute(
            "INSERT INTO tool_calls(run_id, tool, args_json, allowed, reason, output_sha256, raw_output_untrusted, ts)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (run_id, tool, json.dumps(args, sort_keys=True), int(result["ok"]), result.get("error"),
             hashlib.sha256(out.encode()).hexdigest() if out is not None else None, out, time.time()))
        self.db.commit()
        return cur.lastrowid

    def record_action_event(self, run_id: int, event_type: str, *, action_name: str | None = None,
                            tool: str | None = None, args: dict | None = None,
                            rationale: str | None = None, decision: str | None = None,
                            outcome: str | None = None, details: dict | None = None) -> int:
        """Append one orchestration decision or lifecycle event; events are never updated."""
        cur = self.db.execute(
            "INSERT INTO action_events(run_id, ts, event_type, action_name, tool, args_json, rationale, "
            "decision, outcome, details_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (run_id, time.time(), event_type, action_name, tool,
             json.dumps(args, sort_keys=True) if args is not None else None,
             rationale, decision, outcome, json.dumps(details or {}, sort_keys=True)))
        self.db.commit()
        return cur.lastrowid

    def action_events_for_run(self, run_id: int) -> list:
        cur = self.db.execute(
            "SELECT id, ts, event_type, action_name, tool, args_json, rationale, decision, outcome, details_json "
            "FROM action_events WHERE run_id=? ORDER BY id", (run_id,))
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for row in rows:
            row["args"] = json.loads(row.pop("args_json")) if row["args_json"] is not None else {}
            row["details"] = json.loads(row.pop("details_json"))
        return rows

    def action_ledger_for_run(self, run_id: int) -> list:
        """Combine planner events with every stored tool call for a chronological report view.

        Tool-call rows intentionally omit response bodies. The audit log and evidence store remain
        the sources for integrity and bounded response excerpts, respectively.
        """
        ledger = []
        for event in self.action_events_for_run(run_id):
            args = event["args"]
            ledger.append({
                "step_id": f"event-{event['id']}", "timestamp": event["ts"],
                "type": event["event_type"], "action": event["action_name"] or "",
                "tool": event["tool"] or "", "target": _ledger_target(args),
                "decision": event["decision"] or "", "outcome": event["outcome"] or "",
                "rationale": event["rationale"] or "", "model": event["details"].get("model", ""),
                "finding_ids": event["details"].get("finding_ids", []),
            })

        findings_by_call = {}
        for finding in self.findings_for_run(run_id):
            for evidence in finding.get("evidence", []):
                call_id = evidence.get("tool_call_id")
                if call_id is not None:
                    findings_by_call.setdefault(int(call_id), set()).add(finding.get("id", ""))

        for call in self.tool_call_rows(run_id):
            error = call["reason"] or ""
            if call["allowed"]:
                decision = "tool_succeeded"
                outcome = error or "response recorded"
            elif error.startswith("tool failed:"):
                decision = "execution_failed"
                outcome = error
            elif error == "approval required":
                decision = "approval_pending"
                outcome = error
            elif error == "approval could not be finalized after execution":
                decision = "execution_completed_approval_finalize_error"
                outcome = error
            else:
                decision = "policy_denied"
                outcome = error or "not executed"
            ledger.append({
                "step_id": f"call-{call['id']}", "timestamp": call["ts"],
                "type": "tool_call", "action": call["tool"], "tool": call["tool"],
                "target": _ledger_target(call["args"]),
                "decision": decision, "outcome": outcome,
                "rationale": "", "model": "",
                "finding_ids": sorted(x for x in findings_by_call.get(call["id"], set()) if x),
            })
        return sorted(ledger, key=lambda row: (row["timestamp"], row["step_id"]))

    def add_observation(self, run_id, call_id, asset, kind, key, value):
        cur = self.db.execute("INSERT INTO observations(run_id, tool_call_id, asset, kind, key, value, ts) VALUES(?,?,?,?,?,?,?)",
                              (run_id, call_id, asset, kind, key, value, time.time()))
        self.db.commit()
        return cur.lastrowid

    def observations(self, run_id: int) -> list:
        return self.db.execute("SELECT asset, kind, key, value FROM observations WHERE run_id=? ORDER BY id",
                               (run_id,)).fetchall()

    def tool_calls(self, run_id: int) -> list:
        return self.db.execute("SELECT tool, args_json, allowed, reason FROM tool_calls WHERE run_id=? ORDER BY id",
                               (run_id,)).fetchall()

    def tool_call_rows(self, run_id: int, asset_prefix: str | None = None) -> list:
        """Richer, dict-shaped per-call rows than tool_calls() (kept separate so that method's
        existing tuple-shaped callers never break). Does NOT include the raw output itself - see
        raw_output_for_call() for that, kept as a deliberate separate step so evidence-assembly
        code (pagent.evidence) can see which calls exist before choosing which bodies to pull.
        asset_prefix, if given, filters to calls whose args resolve to 'host:port[path]' starting
        with it - the same asset-string convention used everywhere else in this project."""
        cur = self.db.execute("SELECT id, tool, args_json, allowed, reason, output_sha256, ts FROM tool_calls "
                              "WHERE run_id=? ORDER BY id", (run_id,))
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["args"] = json.loads(r.pop("args_json"))
            r["allowed"] = bool(r["allowed"])
        if asset_prefix is not None:
            rows = [r for r in rows if _call_asset(r["args"]).startswith(asset_prefix)]
        return rows

    def raw_output_for_call(self, call_id: int) -> str | None:
        """The untrusted raw output a tool call produced, exactly as pagent.tools stored it
        (already capped by that tool's own max_output_bytes/body-read limit). None if the call
        failed/was denied, or the id doesn't exist. Kept as its own explicit method, never folded
        into tool_call_row(), so every call site handling this untrusted target-response content
        is easy to find by name."""
        r = self.db.execute("SELECT raw_output_untrusted FROM tool_calls WHERE id=?", (call_id,)).fetchone()
        return r[0] if r else None

    def observation_rows(self, run_id: int) -> list:
        cur = self.db.execute("SELECT id, tool_call_id, asset, kind, key, value FROM observations "
                              "WHERE run_id=? ORDER BY id", (run_id,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def observations_by_ids(self, ids) -> list:
        """Fetch specific observation rows by id, e.g. the ones referenced in a Finding's evidence.
        Returns [] for an empty/absent id list rather than querying with an empty IN(...)."""
        ids = [int(i) for i in ids]
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        cur = self.db.execute(
            f"SELECT id, tool_call_id, asset, kind, key, value FROM observations WHERE id IN ({placeholders})", ids)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def tool_call_row(self, call_id: int) -> dict:
        r = self.db.execute("SELECT id, output_sha256, ts FROM tool_calls WHERE id=?", (call_id,)).fetchone()
        return {"id": r[0], "output_sha256": r[1], "ts": r[2]}

    def save_finding(self, run_id: int, finding_dict: dict) -> None:
        self.db.execute("INSERT INTO findings(id, run_id, data_json, updated_at) VALUES(?,?,?,?) "
                        "ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id, data_json=excluded.data_json, updated_at=excluded.updated_at",
                        (finding_dict["id"], run_id, json.dumps(finding_dict), time.time()))
        self.db.commit()

    def get_finding(self, finding_id: str):
        r = self.db.execute("SELECT run_id, data_json FROM findings WHERE id=?", (finding_id,)).fetchone()
        return (r[0], json.loads(r[1])) if r else (None, None)

    def findings_for_run(self, run_id: int) -> list:
        return [json.loads(r[0]) for r in self.db.execute("SELECT data_json FROM findings WHERE run_id=? ORDER BY id", (run_id,))]

    def add_manual_action(self, finding_id, performed_by, action_description, payload_sent, observed_result, notes=""):
        row = {"finding_id": finding_id, "performed_by": performed_by, "action_description": action_description,
              "payload_sent": payload_sent, "observed_result": observed_result, "notes": notes}
        h = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
        cur = self.db.execute("INSERT INTO manual_actions(finding_id, performed_by, performed_at, action_description, "
                              "payload_sent, observed_result, notes, row_sha256) VALUES(?,?,?,?,?,?,?,?)",
                              (finding_id, performed_by, time.time(), action_description, payload_sent, observed_result, notes, h))
        self.db.commit()
        return cur.lastrowid

    def manual_actions_for(self, finding_id: str) -> list:
        cur = self.db.execute("SELECT id, performed_by, performed_at, action_description, payload_sent, observed_result, "
                              "notes, row_sha256 FROM manual_actions WHERE finding_id=? ORDER BY id", (finding_id,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def record_proposal_outcome(self, run_id, model, hypothesis_id, payload_id, weakness_type, category,
                                payload_text, outcome, tested_by, observed_result, notes="") -> int:
        """Records what happened when a human manually tried a model-suggested payload. This is a
        scoring/record-keeping log only - it never touches a Finding and implies no execution by
        this tool; the payload_text is copied from the proposal exactly as generated, never
        re-typed, so the record can't drift from what was actually suggested."""
        row = {"run_id": run_id, "model": model, "hypothesis_id": hypothesis_id, "payload_id": payload_id,
              "weakness_type": weakness_type, "category": category, "payload_text": payload_text,
              "outcome": outcome, "tested_by": tested_by, "observed_result": observed_result, "notes": notes}
        h = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
        cur = self.db.execute(
            "INSERT INTO proposal_outcomes(run_id, model, hypothesis_id, payload_id, weakness_type, category, "
            "payload_text, outcome, tested_by, tested_at, observed_result, notes, row_sha256) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, model, hypothesis_id, payload_id, weakness_type, category, payload_text, outcome, tested_by,
             time.time(), observed_result, notes, h))
        self.db.commit()
        return cur.lastrowid

    def proposal_outcomes_for_run(self, run_id) -> list:
        cur = self.db.execute(
            "SELECT id, run_id, model, hypothesis_id, payload_id, weakness_type, category, payload_text, outcome, "
            "tested_by, tested_at, observed_result, notes, row_sha256 FROM proposal_outcomes "
            "WHERE run_id=? ORDER BY id", (run_id,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def proposal_outcomes_for_payload(self, payload_id: str) -> list:
        cur = self.db.execute(
            "SELECT id, run_id, model, hypothesis_id, payload_id, weakness_type, category, payload_text, outcome, "
            "tested_by, tested_at, observed_result, notes, row_sha256 FROM proposal_outcomes "
            "WHERE payload_id=? ORDER BY id", (payload_id,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
