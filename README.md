# pentest-agent (work in progress)

Authorized-lab use only. The model proposes; the policy gateway decides.

## Run tests
    $env:PYTHONPATH="src"
    python -m unittest discover -s tests -v

## Lab (Juice Shop, loopback only)
    docker pull bkimminich/juice-shop
    docker image inspect bkimminich/juice-shop --format "{{index .RepoDigests 0}}"   # paste sha256 into lab/docker-compose.yml
    # If port 3000 is blocked on Windows, to use a different host port, set JUICE_PORT and match it in config/scope.lab.json:
    # default host port is 5000 (container still listens on 3000 internally)
    docker compose -f lab/docker-compose.yml up -d

## Assessment (discovery -> candidates -> verification -> report)
    python scripts/run_assessment.py --scope config/scope.lab.json
Reports are written to reports/ (JSON + Markdown).

## Crawl (read-only link/parameter/JS discovery, no approval needed)
    python scripts/run_crawl.py --scope config/scope.lab.json
Fetches **exactly** the paths listed in the scope file's `crawl_seeds` (GET, read-only - same
no-approval tier as `http_head`) and reports what each seed page linked to: same-host links and
their query parameter names, same-host `<script src>` references, and off-host links (listed, never
followed). A seed whose content-type/extension is JavaScript is instead scanned for candidate
endpoint paths and credential-shaped strings (`AKIA...`-style keys, `apiKey = "..."` assignments) -
matched secret values are redacted before anything is stored or reported.

In the standalone crawler and interactive `[2]`, nothing discovered is fetched further and nothing
is added to the scope file automatically - `crawl_seeds` and `allowed_probe_targets` are explicit,
human-edited allowlists by design. The loopback-only `--lab-brain` described below has a narrow
exception: it may fetch up to 10 same-host `.js` references from a seed page using a transient local
scope. It never follows off-host links or requests endpoint strings found inside JavaScript. The
report tells you what to add to the scope file for future standalone runs: `python scripts/run_crawl.py` writes `reports/crawl-run<id>.json/.md`
with one `informational` Finding per crawled page's discovered surface, and a `candidate` Finding
per JS file for endpoint/secret heuristics (clearly labeled low-confidence; verify before trusting).

General multi-hop crawling is still deferred; the routine's one-hop JavaScript fetch is limited to
the validated loopback lab mode and does not crawl links or discovered endpoints.

## Payload fuzzing (intrusive, approval required)
    python scripts/run_intrusive.py --scope config/scope.lab.intrusive.json
Same two-step approval flow as every other intrusive probe (request, `scripts/approve.py`, rerun).
If `fuzz_probe` is listed in the scope file's `allowed_tools`, `run_intrusive.py` (and `[3c]` in
the interactive agent) also runs it - for both categories (`sql_injection`, `reflected_input`) -
against every non-login `allowed_probe_targets` entry, alongside the existing `reflect_probe`/
`sqli_probe`/`login_sqli_probe` calls.

`fuzz_probe` (`src/pagent/tools/fuzz_probe.py`) is **not** an external tool (no ffuf/wfuzz/
gobuster) and **not** a wordlist - it's a new Python module in the exact same shape as
`sqli_probe.py`/`reflect_probe.py`: pure `http.client` calls, wrapped in the same `ToolSpec`
(arg schema, `cross_check` against `allowed_probe_targets`, intrusive/approval tier, rate and
output-size limits). What it adds is a slightly *wider, still entirely fixed-in-code* battery of
diagnostic values per request, so one call reports several syntax/escaping signals instead of one:
- `category=sql_injection`: baseline control plus five syntax-probe variants (single quote, double
  quote, escaped quote, backslash, SQL comment token) compared against baseline status/length. No
  tautology (`OR 1=1`), no comment-based bypass shape, no destructive syntax - same discipline as
  `sqli_probe`, just more syntax shapes checked per call.
- `category=reflected_input`: three marker shapes (angle brackets, double quote, single quote)
  instead of `reflect_probe`'s one, reporting per-shape whether it was reflected raw or escaped.

A `candidate` Finding here (`sqli-fuzz-signal` / `reflected-input-fuzz-signal`) is still just a
broader diagnostic signal, not a confirmed exploit - treat it exactly like a `sqli_probe`/
`reflect_probe` finding: human review and, if you choose to, manual confirmation via
`scripts/log_manual_action.py`.

## Action registry and next-action planner (Phase 2 / Phase 3)
    python scripts/show_actions.py --scope config/scope.lab.intrusive.json

`pagent.actions.build_actions(scope)` is the single place describing every action available for a
scope - the foundation Phase 3's orchestrator loop will pick from. Generated *from* `Scope` and the
same dispatch logic `pagent.intrusive`/`scripts/run_intrusive.py` already use (e.g.
`LOGIN_TARGETS`), never hand-duplicated, so it can't silently drift out of sync with what
`PolicyGateway` would actually accept. Two kinds of entries:
- **Batch actions** (`run_assessment`, `run_crawl`, `run_content_discovery`, `generate_proposals`)
  - coarse, no target argument, always `read_only=True` (never need `ApprovalStore` approval -
  they're built from read-only tool calls, or for `generate_proposals`, the AI pipeline itself).
  Listed only when their precondition holds (e.g. `run_crawl` needs `crawl_seeds` non-empty).
- **Targeted actions** - one entry per concrete, already-scoped `(tool, host, port, path,
  parameter[, category])` for every `allowed_probe_targets` entry an approval-gated tool
  (`sqli_probe`/`reflect_probe`/`login_sqli_probe`/`fuzz_probe`) is actually registered for.
  Always `read_only=False`. This is deliberately a menu of ready-to-use, concrete calls rather
  than an abstract JSON schema a model would have to reconstruct valid args for itself - safer
  and more reliable for small local models.

`tests/test_actions.py` includes a cross-check that runs every targeted action's args through the
*real* `PolicyGateway` for that scope and asserts it never gets denied for a scope/cross_check
reason (an approval requirement is fine and expected) - proof the registry can't advertise
something the gateway would actually refuse.

Describing an action here grants nothing: `PolicyGateway.evaluate()` still independently
re-validates everything on every real call. The interactive agent's `[10]` option now asks the
configured reasoning model to choose one action from the current registry, or recommend `stop` /
`ask_human`. The model returns only an action name and rationale; the application resolves the name
back to the trusted registry and displays the action details. Target response evidence stays in the
untrusted-context channel. For a read-only batch action, the agent asks for explicit confirmation
before calling the existing session handler. Each recommendation requires its own confirmation;
the batch may still issue the bounded requests defined by that handler. Targeted actions are not
dispatched by the planner and remain in the existing intrusive menu and approval flow.

Interactive-session reports include an **Action ledger** table that merges planner decisions with
the tool calls already stored for the run. It records timestamps, action/tool, scoped target,
operator decision, outcome, linked finding IDs, and planner rationale; response bodies are not copied
into the table. The audit log remains the integrity record for tool calls.

## Content discovery (passive, read-only, no approval needed)
    python scripts/run_content_discovery.py --scope config/scope.lab.json
Or `[9]` in the interactive agent. GETs every combination of `scope.discovery_prefixes` (explicit,
human-named prefixes - e.g. `/`, `/rest/`) and the small, checked-in wordlist at
`config/content_discovery_wordlist.json` (~25 common, benign filenames: `admin`, `.git`, `.env`,
`backup`, `robots.txt`, etc.) - never an external tool (no ffuf/wfuzz/gobuster) and never a
user/model-supplied path list. Requires `"dir_probe"` in the scope's `allowed_tools` and at least
one `discovery_prefixes` entry, same opt-in discipline as `crawl_seeds`/`allowed_probe_targets`.

Safety properties, by design:
- **`dir_probe`** (`src/pagent/tools/dir_probe.py`) only accepts a path that starts with a scoped
  prefix (`Scope.check_discovery_path`); the *candidate segment* appended to that prefix is always
  one of the fixed wordlist entries, by construction of the orchestrator loop - never free text.
- The response **body is never read or stored** - only status, content-type, and content-length,
  since discovery only needs "does this exist".
- `config/content_discovery_wordlist.json` is capped hard at 60 entries
  (`pagent.wordlist.MAX_ENTRIES`) and every entry is validated as one safe path segment (no `/`,
  no `..`) before use - this is an existence-check list, not a general wordlist.
- The orchestrator (`pagent.discover.run_content_discovery`) refuses to send a single request if
  `targets x prefixes x wordlist` would exceed 200 (`MAX_CONTENT_DISCOVERY_REQUESTS`) - narrow
  `discovery_prefixes` instead of removing this cap.
- Same `read_only=True` tier as `http_get`/crawl (no per-call approval) - the risk here is a GET to
  a well-known, benign filename, the same shape as fetching a path already known to exist.

A `candidate` Finding (`content-discovery-hit`) is produced only for a non-404 response; a 404
produces nothing. Review these manually - a `200`/`403`/etc. means something responded, not that
it's sensitive or exploitable. Nothing found is fetched further or added to `crawl_seeds`/
`allowed_probe_targets` automatically.

## Model benchmark (needs Ollama running)
    python bench/run_bench.py --model qwen3:4b-instruct-2507-q4_K_M --repeats 3 --port 5000
Add --constrain to try the stricter output schema (experimental). Results are written to bench/results/ as JSON.

## Interactive agent (one menu for everything below this line)
One process, one scope, one `run_id`, no retyping `--scope`/`--model`/`--db`/... between steps and
no switching between separate scripts for every single action:

    python scripts/agent.py --scope config/scope.lab.intrusive.json

`--model` can be passed up front too; if left off you're asked for it once, only when you choose
to generate proposals. Everything else is a menu choice:

    [1] Discovery & Assessment      [2] Crawl
    [3] Intrusive Probing >         [4] AI Proposals >
    [5] Manual Confirmation         [6] Knowledge Base >
    [7] Settings >                  [8] Session summary
    [h] Help                        [q] Quit

`>` means a submenu (e.g. `[3]` -> `[a]` run probes / `[b]` review pending approvals / `[c]` run
payload fuzzing; `[9]` runs content discovery directly, no submenu; `[4]` ->
`[a]` generate / `[b]` open a saved proposals file / `[c]` review+approve+execute each payload /
`[d]` log an outcome for one payload id). `[h]` prints the full reference with each menu item's
standalone-script equivalent. `[7b]` switches to a different scope file mid-session (starts a new
`run_id` under it - scopes are never mixed). `[q]` writes a combined report over every Finding the
session produced.

This adds **no new trust**: every intrusive/proposal action still goes through the same
`PolicyGateway` + `ApprovalStore` lifecycle as the standalone scripts - typing `y` on a reviewed
payload or approval request *is* the human approval, recorded exactly as `scripts/approve.py`
records it, and every call is still audit-logged. The standalone scripts below are untouched and
still work for scripting/CI; the agent is for interactive use and wraps all of them.

### AI-driven local lab brain

For the checked-in Juice Shop scope, start one bounded local run without navigating the menu:

    python scripts/agent.py --scope config/scope.lab.json --model qwen3:4b-instruct-2507-q4_K_M --lab-brain

Ollama and the selected model are required. After each batch action, the model receives the updated
findings and bounded evidence, chooses the next action from the remaining registered read-only
actions, and continues without a per-action prompt. The core actions are assessment, content
discovery, and crawl; the model chooses their order. Candidate findings trigger the existing
automatic AI triage/proposal pass, and its triage decision is recorded in the action ledger. AI
triage prioritizes findings; it does not confirm that a finding is true. The existing deterministic
repeat checks provide the limited verification described in each finding. Crawl also scans up to 10 same-host `.js` references for the
existing endpoint/key heuristics. Secret-shaped values remain redacted. The brain never follows
off-host links or uses discovered endpoints as targets, and stops if all calls in a stage fail.
`--lab-routine` remains a compatibility alias for `--lab-brain`.

`--lab-brain` rejects any scope that is not exactly one loopback host and one port, has CIDRs,
allows intrusive actions, includes tools outside `http_head`/`http_get`/`dir_probe`, or lacks bounded
crawl seeds and discovery prefixes. It does not accept a raw target as authorization. Reports and
the action ledger are written under `reports/` when the run finishes.

## Contextual AI hypothesis + payload proposals (proposal only, two-pass)
Requires Ollama running. This path **does not execute tools** and does not bypass the existing policy/approval gateway.

    python scripts/propose_tests.py --scope config/scope.lab.intrusive.json \
        --model qwen2.5-coder:3b --reasoning-model qwen3:4b

Two passes, which can be two **different** models - Ollama loads/unloads whichever is requested per call, so there's
no need to keep both resident:
1. **REASONING** (`--reasoning-model`, defaults to `--model` if omitted) - `pagent.review.ReviewEngine` looks at the
   current findings *and* real recent evidence (`pagent.evidence` - actual sanitized response content, not just
   status/length) and decides which findings are worth a closer look. This is also proposal-only: it produces a
   ranked subset of finding ids + short notes, never a payload.
2. **GENERATION** (`--model`) - `pagent.proposals.ContextualProposalEngine` proposes hypotheses+payloads only for
   that reviewed subset, with the same evidence attached (this is the fix for "generic payloads": the model now
   sees actual response content, not just a finding's shape).

Raw evidence is always passed through `OllamaClient.request_structured(..., untrusted_context=...)`, never
concatenated into the system/user prompt directly - it arrives wrapped in explicit `<untrusted_tool_output>` tags
with an instructions-vs-data reminder, since it is text a target sent back, not instructions to follow.

Every proposed path+parameter is still validated against `allowed_probe_targets`; every payload is still recorded as
`suggested_only` with `requires_approval=true`; there is still intentionally no generic model-to-execution adapter.
Writes `reports/proposals-run<id>.json`, now including a `"review"` section showing what was flagged and why.

### Auto-review (interactive agent only)
In `scripts/agent.py`, this two-pass pipeline runs **automatically** after any data-gathering action ([1] assessment,
[2] crawl, [3a] intrusive probes, [3c] fuzzing, [9] content discovery) that produced a `candidate`-status finding -
you don't have to remember to go run [4a] yourself. Disable with `--no-auto-review` at startup, or toggle it at
`[7c]` mid-session. Set/change either model at `[7d]`. A transient Ollama failure (not running, model not pulled,
bad response) prints one line and the session carries on - auto-review never crashes the agent.

## Recording whether a suggested payload actually worked
After you manually try a suggested payload yourself (browser/curl/Burp, as always), log the outcome so suggestion
quality can be measured instead of guessed:

    python scripts/log_proposal_outcome.py --proposals reports/proposals-run5.json \
        --payload-id P-xxxxxxxxxxxx --outcome confirmed_signal --tested-by "your name" \
        --observed-result "describe exactly what you observed" --i-tested-this-manually

`--outcome` is one of `confirmed_signal | no_signal | inconclusive | false_lead`. This only logs a record tied to the
payload_id/hypothesis_id (payload text is copied verbatim from the proposal, never re-typed) - it does not touch the
underlying Finding. If a payload is `confirmed_signal` and you want the Finding itself marked confirmed, also run
`scripts/log_manual_action.py` with the same payload text.

See the running tally for a proposals run at any time:

    python scripts/log_proposal_outcome.py --proposals reports/proposals-run5.json --summary

## Executing an approved proposal (restricted adapters only, human approval required)
This is the automated alternative to manually trying a suggested payload yourself: a `quote_break`,
`reflection_marker` or `html_context_marker` payload from a `proposals-run<id>.json` file can be
run through the **existing** `sqli_probe` / `reflect_probe` / `login_sqli_probe` adapters and the
**existing** policy gateway + human approval lifecycle - the same one `scripts/run_intrusive.py`
already uses. There is still no generic model-to-execution adapter: `pagent.execution` maps a
payload's `category` to exactly one of those three fixed-shape adapters; the model's own payload
string is never sent anywhere. `boolean_pair` has no adapter yet and stays `suggested_only` - keep
using the manual-outcome workflow above for it.

    $ProposalFile = "reports/proposals-run5.json"   # replace with your actual run
    $PayloadId    = "P-xxxxxxxxxxxx"                # replace with the payload id you want to run
    $ScopeFile    = "config/scope.lab.intrusive.json"

    python scripts/execute_proposal.py --proposals $ProposalFile --payload-id $PayloadId --scope $ScopeFile

The first run resolves the payload to its adapter call and requests approval, then exits without
sending anything:

    python scripts/approve.py list
    python scripts/approve.py approve <id>
    # rerun the exact same command - it now executes
    python scripts/execute_proposal.py --proposals $ProposalFile --payload-id $PayloadId --scope $ScopeFile

A successful run produces a candidate Finding the same way `scripts/run_intrusive.py` does (saved
to the evidence DB, same rule_id/limitations/confidence shape) and writes
`reports/proposal-execution-P-xxxxxxxxxxxx.json`, which records the resolved tool+args, the
approval id, and the resulting Finding. The original `proposals-run<id>.json` is never modified.

A saved proposal is re-validated, not just trusted, before anything runs: the stored hypothesis and
payload ids must still match what their own content hashes to (catches a hand-edited file), and the
path+parameter is re-checked against the scope file passed to `execute_proposal.py` - which does
not have to be the same scope file the proposal was originally generated against.
