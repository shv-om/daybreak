# Scope-bound orchestrator plan

## Product direction

The goal is a mostly self-running assessment for targets that are already covered by an explicit
authorization scope. The operator should be able to select a target, let the agent complete its
eligible routine checks, review a clear action log, and then decide what to do with any approval-
gated actions.

A target string is a selector, not authorization. A supplied IP or domain must match an existing
scope's allowed hosts or CIDRs, ports, validity window, and exclusions before the run can begin. A
target that does not match a loaded scope fails closed. Discovery results never expand scope or
become new probe targets automatically. Scope validation enforces the configured bounds; it does
not independently prove that the named authorizer granted permission, so the operator remains
responsible for supplying a legitimate engagement scope. The loopback-only lab routine has one
narrow exception for read-only collection: it may fetch up to 10 same-host `.js` references found
in an explicitly scoped seed page, using a transient derived scope. It never follows off-host links
or turns extracted endpoint strings into requests.

## Proposed run flow

1. **Resolve scope.** Load the engagement scope and verify its authorization window. If an optional
   target selector is supplied, confirm that it is inside that scope. Do not infer authorization
   from the target value or silently edit the scope.
2. **Create a run record.** Persist the engagement, scope fingerprint, selected target, start time,
   run state, and configured request/time budgets.
3. **Plan from registered actions.** Give the model the current findings, bounded evidence, and
   actions built from `pagent.actions.build_actions`. Accept only a registered action name or a
   control choice (`stop` / `ask_human`). The model never supplies tool arguments.
4. **Run eligible routine actions.** Execute only actions marked read-only by the registry, subject
   to per-run request and time caps. Revalidate every actual tool call in `PolicyGateway`. Require
   explicit operator start for the run; log each selected action and result.
5. **Build an approval queue.** Keep approval-gated actions pending while routine work continues.
   Do not send them while building the queue. At the review point, show the exact registered action,
   target, arguments, rationale, and relevant evidence. The operator can approve or deny each item.
6. **Execute approved items only.** Revalidate the scope and exact action arguments at execution
   time. An approval is tied to one action and its exact arguments; changes require a new decision.
   Denied or expired items are never sent.
7. **Report and resume.** Produce a findings summary plus a chronological action ledger. Persist
   enough run state to resume safely after a stop or approval review without repeating completed
   actions or mixing scopes.

## Action ledger

The report should include a step table with fields along these lines:

| Field | Purpose |
|---|---|
| Step and timestamp | Preserve the order of decisions and actions. |
| Phase and action ID | Tie a step to the registered workflow action. |
| Tool and scoped asset | Show what the application actually invoked and where. |
| Decision and rationale | Record the planner recommendation and operator choice. |
| Approval state | Show pending, approved, denied, expired, or not required. |
| Result and finding IDs | Summarize outcome and link to evidence/findings. |

Keep the append-only audit record as the source for tool-call integrity. The report ledger is a
readable view over planner decisions, operator approvals, tool calls, and findings; it should not
replace or weaken `AuditLog` or `PolicyGateway`.

## Autonomy and stop conditions

Treat “60–70% autonomous” as a measured outcome, not a permission setting. Measure the share of
eligible routine steps completed without per-step input, alongside scope violations blocked,
approval decisions, repeated actions avoided, report completeness, and human corrections. Never
count approval-gated steps as autonomous simply because they were queued.

Stop or ask a human when the scope is missing, expired, or ambiguous; the action is not in the
registry; the request/time budget is exhausted; evidence is insufficient; a tool fails repeatedly;
or the next action needs approval. Do not let the model widen scope, manufacture targets or
arguments, approve its own work, or continue after a stop condition.

## Implementation milestones

- **Phase 3a — Planner:** completed. The model chooses only a registered action and the application
  resolves the choice against the registry.
- **Phase 3b — Confirmed dispatch:** completed for read-only batch actions. Each recommendation
  requires an operator confirmation. Targeted actions are not dispatched by the planner.
- **Phase 3c — Action ledger:** completed for tool calls and planner lifecycle events. The agent's
  report can render these as a chronological table. Persistent resume state remains to be added.
- **Phase 3d — Loopback lab brain:** implemented as `--lab-brain` (`--lab-routine` alias). After
  each batch action, the model sees updated findings/evidence and selects the next remaining
  read-only registered action. Candidate findings also pass through AI triage, whose model and
  decision are recorded in the action ledger. AI triage prioritizes findings; deterministic repeat
  checks remain the limited verification mechanism. Core local actions cover assessment, content discovery, and crawl;
  crawl can scan up to 10 same-host script references. The mode rejects non-loopback, CIDR,
  intrusive, or broader-tool scopes and stops if a stage's tool calls all fail. It does not accept
  arbitrary target input.
- **Phase 3e — Persistent resume state:** record run status and completed actions before adding
  continuation across process restarts.
- **Phase 3f — Approval queue:** gather exact approval requests, present them together, and execute
  only individually approved items after fresh scope and policy checks.
- **Phase 3g — Evaluation:** measure the routine completion rate and safety/quality metrics on the
  isolated Juice Shop lab before considering any broader use.

## Current limitations

The current `[10]` option recommends one action and can dispatch a confirmed read-only batch
action. `--lab-brain` runs a model-driven loop only for the validated loopback lab. There is no
arbitrary target selector, general remote-target planner loop, persistent resume state, or end-of-run
approval queue. Intrusive actions remain in the existing interactive approval workflow.
