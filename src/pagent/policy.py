"""Policy gateway: the ONLY path from a model-proposed action to a tool.
Fail closed on every error. The model proposes; this module decides."""
from __future__ import annotations
import threading
from dataclasses import dataclass
from .scope import Scope
from .audit import AuditLog


@dataclass(frozen=True)
class ToolSpec:
    name: str
    read_only: bool
    arg_schema: dict          # arg name -> (type, validator or None)
    max_calls: int            # rate limit per gateway lifetime (MVP)
    timeout_s: float
    max_output_bytes: int
    handler: object           # callable(**args) -> str
    cross_check: object = None   # optional callable(args) -> (bool, str); runs BEFORE approval is requested


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class PolicyGateway:
    def __init__(self, scope: Scope, tools: dict, audit: AuditLog, approvals=None):
        self.scope, self.tools, self.audit, self.approvals = scope, tools, audit, approvals
        self._calls: dict = {}
        self._halt = threading.Event()     # emergency stop

    def emergency_stop(self):
        self._halt.set()
        self.audit.record("emergency_stop")

    def _validate_args(self, spec: ToolSpec, args: dict):
        if set(args) != set(spec.arg_schema):
            return Decision(False, f"args must be exactly {sorted(spec.arg_schema)}")
        for k, (typ, check) in spec.arg_schema.items():
            v = args[k]
            if type(v) is not typ:               # strict: bool is not int
                return Decision(False, f"arg {k} must be {typ.__name__}")
            if check and not check(v):
                return Decision(False, f"arg {k} failed validation")
        return Decision(True, "args ok")

    def evaluate(self, tool: str, args: dict, approved: bool = False) -> Decision:
        try:
            if self._halt.is_set():
                return Decision(False, "emergency stop active")
            spec = self.tools.get(tool)
            if spec is None or tool not in self.scope.allowed_tools:
                return Decision(False, "tool not registered or not in scope")
            d = self._validate_args(spec, args)
            if not d.allowed:
                return d
            if spec.cross_check is not None:
                ok, why = spec.cross_check(args)
                if not ok:
                    return Decision(False, f"policy: {why}")
            if "host" in args:
                ports = [args["port"]] if "port" in args else args.get("ports")
                if not ports:
                    return Decision(False, "target tools must declare port(s)")
                for p in ports:
                    ok, why = self.scope.check_target(args["host"], p)
                    if not ok:
                        return Decision(False, f"scope: {why}")
            if self._calls.get(tool, 0) >= spec.max_calls:
                return Decision(False, "rate limit reached")
            if not spec.read_only:     # checked LAST so humans are never asked to approve invalid/out-of-scope actions
                if not self.scope.intrusive_allowed:
                    return Decision(False, "intrusive tools disabled by scope")
                if not approved:
                    return Decision(False, "approval required")
            return Decision(True, "allowed")
        except Exception as e:                    # fail closed
            return Decision(False, f"policy error: {type(e).__name__}")

    def execute(self, tool: str, args: dict, proposed_by: str = "model") -> dict:
        """No 'approved' parameter on purpose: approval can only come from the human-controlled ApprovalStore.
        A matching approval is atomically RESERVED immediately before execution, then CONSUMED only
        after success. A transient handler failure releases the reservation so it can be retried."""
        approval_id = None
        d = self.evaluate(tool, args, approved=False)
        extra = {}
        if not d.allowed and d.reason == "approval required" and self.approvals is not None:
            approval_id = self.approvals.reserve_approved(tool, args)
            if approval_id is None:
                extra["approval_request_id"] = self.approvals.request(tool, args)
            else:
                d = Decision(True, "allowed")
                extra["approval_id"] = approval_id
        self.audit.record("decision", tool=tool, args=args, allowed=d.allowed, reason=d.reason, proposed_by=proposed_by, **extra)
        if not d.allowed:
            return {"ok": False, "error": d.reason, **extra}
        spec = self.tools[tool]
        self._calls[tool] = self._calls.get(tool, 0) + 1
        try:
            out = spec.handler(timeout=spec.timeout_s, **args)
        except Exception as e:
            if approval_id is not None:
                self.approvals.release(approval_id)
            self.audit.record("tool_error", tool=tool, error=type(e).__name__, **extra)
            return {"ok": False, "error": f"tool failed: {type(e).__name__}", **extra}
        if approval_id is not None and not self.approvals.consume(approval_id):
            # The reservation should make this unreachable unless the approval DB was modified or failed.
            # The action DID run, so fail closed and make the state error explicit in the audit trail.
            self.audit.record("approval_finalize_error", tool=tool, approval_id=approval_id)
            return {"ok": False, "error": "approval could not be finalized after execution", **extra}
        raw = out.encode("utf-8", "replace")[: spec.max_output_bytes]
        text = raw.decode("utf-8", "replace")
        self.audit.record("tool_result", tool=tool, bytes=len(raw), **extra)
        # Tool output is UNTRUSTED DATA; callers must wrap it, never treat it as instructions.
        return {"ok": True, "untrusted_output": text, **extra}
