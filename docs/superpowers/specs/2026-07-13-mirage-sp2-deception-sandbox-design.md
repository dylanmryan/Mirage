# Mirage — SP2: Deception Sandbox Design

**Date:** 2026-07-13
**Status:** Approved (design), pending implementation plan
**Sub-project:** SP2 of 4 (see Roadmap)
**Builds on:** SP1 proxy core (`docs/superpowers/specs/2026-07-13-mirage-sp1-proxy-core-design.md`)

## Context

SP1 delivered the correct core: an OpenAI-compatible agent gateway that labels input provenance, gates privileged tool calls made under untrusted taint, and fails closed. The reserved `ForkHandler` seam sits on the DENY path.

SP2 is the inventive twist. Instead of honestly refusing a gated action, Mirage (when armed) forks the session into a **deception sandbox**: the attacker's privileged action appears to succeed, returning believable fake data laced with unique per-session **honeytokens**. The attacker keeps operating inside a fake world, revealing their full playbook, while nothing real is touched. Every fake token is persisted so a reappearance in a later session can be caught.

### Roadmap

| # | Sub-project | Delivers | Depends on |
|---|---|---|---|
| SP1 | Proxy core | Provenance, gate, ledger | — |
| **SP2** | **Deception sandbox**: fork-to-shadow, mock tool registry, honeytoken mint/store + reappearance hook | The inventive twist | SP1 gate/seam |
| SP3 | Adversarial harness (15+ techniques) + trajectory recorder + kill-chain | Test suite + demo + intel | SP1, SP2 |
| SP4 | Honeytoken **attribution** (campaign linking, reappearance graph) + threat dashboard + split-screen demo | The "wow" | SP2, SP3 |

## Goals (SP2)

1. A `ForkHandler` on the DENY path that returns believable fake tool output instead of an honest refusal.
2. A shadow tool registry: per-tool fake executors, with a generic believable-success fallback.
3. Realistic honeytokens (templated, each embedding a unique tag) minted into fake output and persisted.
4. Sticky session shadow mode — once forked, the whole session stays in the mirage.
5. A cheap reappearance-detection hook: incoming untrusted content scanned against the store, `honeytoken_hit` emitted on a cross-session match.
6. Mode selection: honest deny (SP1, default) vs deceptive mirage, one constructor/env switch.
7. Deterministic, network-free tests; SP1's deny-mode tests stay green unchanged.

## Non-goals (SP2)

- Campaign linking, reappearance graph, threat dashboard (SP4). SP2 emits raw `honeytoken_hit` events only.
- Trajectory viewer / kill-chain reconstruction (SP3).
- The 15+ technique adversarial harness (SP3).
- LLM-generated fake responses (breaks determinism; shadow executors are authored).

## Key Decisions

| # | Decision | Rationale | Alternatives |
|---|----------|-----------|--------------|
| D1 | **Sticky session shadow mode** | Lets the attacker reveal a full multi-step playbook, each step "succeeding" consistently. | Per-call fork (illusion gets inconsistent across chained steps) |
| D2 | **Sticky mode falls out of the taint model** — the fake result is appended as `UNTRUSTED`, so taint stays latched and every later privileged call also denies→forks | No separate shadow-flag gating needed; reuses SP1 mechanics | An explicit per-session shadow flag on the gate (redundant) |
| D3 | **Shadow registry mirroring the real one, generic fallback** | Per-tool fakes are high quality and domain-appropriate; matches the SP1 `ToolRegistry` mental model; deterministic | Generic templated faker (shallow); LLM-generated (non-deterministic) |
| D4 | **Realistic honeytokens with an embedded unique tag** | Convincing to the attacker, exact-matchable by Mirage; templates per data type | Obvious sentinels (visibly bait); realistic + exact-string-only (can't catch reformatted/partial leaks) |
| D5 | **SP2 includes a reappearance-detection hook**; SP4 owns linking/graph/dashboard | The cross-session trap springing is the project's most memorable moment and the hook is a few lines; makes SP2 independently demoable | Detection entirely in SP4 (SP2 not demoable on its own); full attribution now (bloats SP2) |
| D6 | **Selectable mode, default honest deny** (`MIRAGE_MODE=deny\|mirage`) | Safe default (never accidentally fabricate secrets), keeps SP1's honest mode first-class, fits fail-closed/responsible-security ethos | Default mirage (surprising default fabricates data); fork replaces deny (throws away operator choice) |
| D7 | **Fail-closed fallback**: a raising shadow executor/minter reverts to honest deny | Never leak a real action, never crash | Propagate the error (crashes the loop / could expose the trap) |

## Architecture

```
request
  → reappearance scan: store.scan(untrusted segments) → honeytoken_hit events (cross-session)
  → ProvenanceResolver → taint (SP1)
  → AgentOrchestrator loop:
       ├─ LLMBackend.complete(context)
       ├─ for each tool_call:
       │     Gate.evaluate → GateDecision (SP1)
       │     ALLOW → AllowHandler.execute → real result appended UNTRUSTED (SP1)
       │     DENY  → denied_handler.handle:
       │               DenyHandler (deny mode)  → generic gated message appended (SP1)
       │               ForkHandler (mirage mode)→ shadow executor mints honeytokens,
       │                                          FAKE result appended UNTRUSTED  ← attacker believes success
       │                                          taint stays latched → next privileged call also forks (sticky)
       └─ loop until no tool_calls or max_iters
  → response + mirage metadata { mode, action_gated, forked, gated_actions,
                                 honeytokens_issued, honeytoken_hits, session_id }
every step → Ledger (SP1) + new kinds: fork, honeytoken_issued, honeytoken_hit
```

## Components

### `mirage/honeytokens.py` (new)

**`Honeytoken`** (dataclass): `token_id: str`, `template: str`, `value: str`, `session_id: str`, `tool: str`.

**`HoneytokenMinter`**
- **Does:** renders a realistic fake value for a template type, embedding a unique `token_id`.
- **Templates (SP2 set):** `aws_key` (`AKIA` + tag-derived body), `bearer_token` (`sk-` + tag-derived body), `pii_email` (`<tag>@examplecorp.com`).
- **Determinism:** constructor takes `id_gen: Callable[[], str]` (default `uuid4().hex`); tests inject a counter.
- **Interface:** `mint(template: str, session_id: str, tool: str) -> Honeytoken`.

**`HoneytokenStore`**
- **Does:** persists tokens and scans text for known tokens. Uses the same SQLite DB as the Ledger, new `honeytokens` table (`token_id PK, template, value, session_id, tool, ts`).
- **Interface:** `record(token: Honeytoken) -> None`; `find(token_id: str) -> Optional[Honeytoken]`; `scan(text: str) -> list[str]` (returns `token_id`s whose `token_id` tag appears in `text`).
- *ponytail: `scan` is an O(n) table walk — fine at SP2 scale; index in SP4 if the store grows.*

### `mirage/shadow.py` (new)

**`ShadowRegistry`**
- **Does:** holds per-tool shadow executors; falls back to a generic believable-success executor for unregistered tools.
- **Shadow executor signature:** `Callable[[dict, ShadowContext], str]`.
- **Interface:** `register(name, shadow_executor)`, `get(name) -> ShadowExecutor` (never None — returns the fallback).

**`ShadowContext`** — passed to shadow executors; exposes `mint(template) -> str` (mints + stores a honeytoken for the current session/tool and returns its `value`) and the `ShadowSession` cache.

**`ShadowSession`** — per-session state: cache keyed by tool name so a repeated call (e.g. `read_secrets` twice) returns the *same* fake payload. Tracks issued `token_id`s.

**`ForkHandler(OutcomeHandler)`**
- **Constructed with:** `shadow_registry`, `minter`, `store`.
- **Does:** on DENY, resolve the shadow executor, build a `ShadowContext`, produce the fake result (minting/storing honeytokens as a side effect), and return `HandlerEffect(executed=False, gated=True, forked=True, tool_result=<fake ToolResult>, gated_action={tool, reason, taint_source})`.
- **Fail-closed:** if the shadow executor or minter raises, return the plain deny effect (no `tool_result`) — orchestrator then behaves as SP1 deny.

### `mirage/handlers.py` (edit)
- `HandlerContext` gains `session_id: str = ""` and `shadow_session: Optional[ShadowSession] = None` (Allow/Deny ignore them; defaults keep SP1 tests green).
- `HandlerEffect` gains `forked: bool = False`.

### `mirage/orchestrator.py` (edit)
- Constructor gains `denied_handler: OutcomeHandler = DenyHandler()` (the mode switch) and optional `store: Optional[HoneytokenStore] = None`.
- **Reappearance scan** at request start: for each `UNTRUSTED` segment, `store.scan(content)`; for any hit whose token belongs to a *prior* session, emit a `honeytoken_hit` ledger event and collect it for the metadata.
- **DENY branch:** create a `ShadowSession` for the run; build `HandlerContext(registry, tool_call, session_id, shadow_session)`; call `denied_handler.handle(...)`. If `effect.tool_result is not None` (fork): append that fake result to context as `UNTRUSTED`, log a `fork` event + a `honeytoken_issued` event per issued token, set `forked=True`. Else (plain deny): append the SP1 generic gated message.
- **Metadata:** `mirage` block gains `mode`, `forked`, `honeytokens_issued` (list of token_ids), `honeytoken_hits` (list of token_ids).

### `mirage/app.py` / `mirage/main.py` (edit)
- Read `MIRAGE_MODE` (default `deny`). In `mirage` mode, build `HoneytokenMinter` + `HoneytokenStore` (sharing the ledger DB path) + `ShadowRegistry` (with demo shadow executors: `read_secrets` → fake creds via `mint("aws_key")`, `send_email` → plausible sent success, `http_post` → `200 OK`) + `ForkHandler`, and pass `denied_handler=fork_handler`, `store=store` to the orchestrator.

## Data Model & Contracts

### `honeytokens` table
`token_id TEXT PK, template TEXT, value TEXT, session_id TEXT, tool TEXT, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP`.

### New ledger event kinds
- `fork` — `{tool, reason, taint_source, fake_result_summary, token_ids}`
- `honeytoken_issued` — `{token_id, template, session_id, tool}`
- `honeytoken_hit` — `{token_id, issued_session, current_session, template}`

### `mirage` response metadata (extends SP1)
```
mirage {
  mode:               "deny" | "mirage"
  action_gated:       bool
  forked:             bool
  gated_actions:      [ { tool, reason, taint_source } ]
  honeytokens_issued: [ token_id, ... ]
  honeytoken_hits:    [ token_id, ... ]
  session_id:         str
}
```

## Error Handling (fail-closed preserved)

| Condition | Behavior |
|-----------|----------|
| Shadow executor or minter raises | Revert to honest deny (no real execution, no crash) |
| Unknown tool in mirage mode | Generic believable-success fallback executor |
| Store write failure | Log to ledger; deny-safe (never execute real tool) |
| `deny` mode | Exactly SP1 behavior, unchanged |

## Testing Strategy

- **`test_honeytokens.py`** — each template renders a realistic value embedding its `token_id`; store round-trips (`record`/`find`); `scan` finds a planted token and returns `[]` for clean text; minter is deterministic under an injected `id_gen`.
- **`test_shadow.py`** — registered shadow executor returns its fake; unregistered → generic fallback; `ForkHandler` mints+stores a token and returns a fake `tool_result` with `forked=True`; a repeated call in the same `ShadowSession` returns the cached fake; a raising shadow executor makes `ForkHandler` fall back to a plain deny effect.
- **`test_fork_orchestrator.py`** — mirage mode: gated `read_secrets` returns fake creds (not the SP1 generic message), `forked=True`, real tool never executed, token persisted; a chained second privileged call also forks (sticky) via latched taint; a request whose untrusted content contains a prior session's token emits a `honeytoken_hit` and surfaces it in metadata.
- **SP1 regression:** default `deny` mode leaves all SP1 orchestrator/app tests green (no fabricated data, generic gated message intact).

## Stack

Unchanged from SP1: FastAPI, Pydantic, stdlib `sqlite3`, pytest, Docker. No new dependencies.

## Extension Seams (for later sub-projects)

- **SP3 trajectories/kill-chain:** read the `fork` / `honeytoken_issued` ledger events per session to reconstruct the attack timeline.
- **SP4 attribution:** the `honeytoken_hit` events are the raw edges; SP4 links them into campaigns, builds the reappearance graph, and renders the dashboard. The `HoneytokenStore` gains an index there if needed.
