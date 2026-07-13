# Mirage — SP1: Proxy Core Design

**Date:** 2026-07-13
**Status:** Approved (design), pending implementation plan
**Sub-project:** SP1 of 4 (see Roadmap below)

## Context

Mirage is a deception-based LLM security system. Its thesis fuses two 2026 results:

- **Impossibility theorem** ([arXiv:2606.27567](https://arxiv.org/abs/2606.27567)) — instruction/data separation cannot be enforced *inside* a shared-embedding model, so prompt injection cannot be blocked at the model boundary. Conclusion: stop trying to block it there; enforce separation *architecturally*, outside the model, for privileged actions.
- **Knowledge honeypot** ([arXiv:2606.15810](https://arxiv.org/abs/2606.15810)) — traceable bait ("honeytokens") can trap extraction attackers by observing where the bait resurfaces.

Full-system philosophy: *if injection can't be stopped, make it a trap.* When untrusted content triggers a privileged action, route the attacker into a deception sandbox seeded with fingerprinted honeytokens, and record the attack trajectory.

This document specs **only SP1 — the proxy core**, which is the load-bearing foundation every later layer depends on. SP1 delivers the "genuinely correct" part: untrusted content can shape what the model *says*, never what it *does*.

### Roadmap (context for where SP1 sits)

| # | Sub-project | Delivers | Depends on |
|---|---|---|---|
| **SP1** | **Proxy core**: OpenAI-compatible gateway, provenance ledger, policy/gate engine outside the model | Untrusted content can shape output, never actions | — |
| SP2 | Deception sandbox: fork-to-shadow on detected injection, mock tool registry, honeytoken seeding | The inventive twist | SP1 gate |
| SP3 | Adversarial harness (15+ techniques) + trajectory recorder + kill-chain reconstruction | Test suite + demo + intel capture | SP1, SP2 |
| SP4 | Attribution + threat dashboard + split-screen demo + fail-closed hardening | The "wow" | SP2, SP3 |

The honeytoken *store* is introduced in SP2; its *attribution* logic lands in SP4. A thin slice of SP3's harness is pulled forward into SP1 as test fixtures.

## Goals (SP1)

1. An OpenAI-compatible agent gateway that owns tool execution (not a passive passthrough).
2. Provenance labeling of all input as `trusted` vs `untrusted`, fail-closed.
3. A policy/gate engine, *outside the model*, that stops privileged actions taken under taint.
4. A fail-closed deny behavior with a pluggable outcome-handler seam for SP2's fork.
5. An append-only SQLite ledger recording provenance maps and every gate decision — the substrate for SP3/SP4.
6. Deterministic, network-free tests via a scripted LLM backend, seeded with early injection fixtures.

## Non-goals (SP1)

- The deception sandbox / fork behavior (SP2).
- Honeytoken generation, storage, or attribution (SP2/SP4).
- The trajectory viewer, kill-chain reconstruction, and dashboard UI (SP3/SP4).
- Capability tokens / per-turn authorization to auto-allow gated actions (documented future extension; see Decisions).
- Dataflow / token-level taint tracking (documented future extension).
- HTTP-webhook tool executors for third-party apps (in-process executors only in SP1; webhook noted as future).

## Key Decisions

| # | Decision | Rationale | Alternatives considered |
|---|----------|-----------|-------------------------|
| D1 | **Full agent gateway** — Mirage owns tool execution | The core claim ("untrusted content never changes what the model *does*") is only architecturally true if Mirage holds the trigger. Also the prerequisite for SP2's fork. | Passive inspection proxy (gate can only advise, contradicts thesis); hybrid |
| D2 | **Provenance: explicit markers authoritative, role heuristic as default, fail-closed** | Provenance is something the *app* knows, not something a model should infer. Heuristic is a convenience for plain chat only. | Pure role heuristic (breaks on RAG-in-user-message); explicit-only (no zero-config path) |
| D3 | **Heuristic never upgrades against a marker; unlabeled/odd shapes → untrusted** | Prevents an app that stuffs a fetched web page into a `user` message from silently gaining `trusted`. | — |
| D4 | **Gate rule A: `PRIVILEGED` tool + any untrusted content in taint window → gate; `READ_ONLY` always allowed; no auto-allow** | The honest reading of the theorem — do not attribute causation from model output (impossible); enforce a static conservative policy. Guarantees the trap fires reliably. | Capability-token allow (B, deferred); dataflow taint (C, research-grade/fragile) |
| D5 | **Pluggable `LLMBackend`: `real` + `scripted`** | A security proxy needs deterministic tests; the SP3 harness must run in CI without a live model. Identical gate code path either way. | Real-only (flaky, costs money); record/replay (heavier tooling) |
| D6 | **Gate deny in SP1 = fail-closed: drop action, return safe completion + `mirage` metadata block** | Non-crashing, honest, and the metadata block is the exact seam SP2's fork slots into. A hard error would tell the attacker they were caught. | Hard 4xx error; silent drop (no audit trail) |
| D7 | **`GateDecision` + pluggable `OutcomeHandler`; SQLite ledger from day one** | Keeps gate logic pure and SP2 additive; the ledger is the provenance substrate SP3/SP4 read from — in-memory-only would mean rebuilding it. | In-memory ledger; bespoke fork wiring in the gate |

### Documented future extensions (out of scope for SP1)

- **B — Capability tokens:** the trusted plane mints a short-lived, single-use authorization ("user authorized *one* `send_email` this turn") that lets a specific privileged call through despite taint. Realistic for production; more moving parts.
- **Dataflow taint:** track whether untrusted tokens flow into the tool-call *arguments*. Most precise, but fragile and partly relies on the model introspection the theorem says is unreliable.
- **HTTP-webhook tool executors:** let third-party apps register tools whose executors are their own HTTP endpoints.
- **Cedar/OPA policy engine:** replace the small declarative policy config with a full policy-as-code engine.

## Architecture

Mirage exposes an OpenAI-compatible `/v1/chat/completions` endpoint and runs the agent loop itself.

```
request
  → ProvenanceResolver           (messages → provenance map)
  → AgentOrchestrator loop:
       ├─ LLMBackend.complete(context)         → assistant turn (maybe tool_calls)
       ├─ for each tool_call:
       │      Gate.evaluate(tool, taint_state) → GateDecision
       │      OutcomeHandler.handle(decision):
       │          allow → ToolRegistry.execute → result tagged UNTRUSTED, appended to context
       │          deny  → skip execution, flag `action_gated`, record
       └─ loop until no tool_calls or max_iters
  → OpenAI-compatible response + `mirage` metadata block
every step → Ledger.append(...)   (SQLite, append-only)
```

Core property: the model's output can only *propose* actions; only Mirage executes them, and only through the Gate.

## Components

Each is an independently testable unit with one responsibility.

### ProvenanceResolver
- **Does:** maps each incoming message/segment to `TRUSTED` or `UNTRUSTED`, producing a provenance map.
- **Rule order:** explicit marker (authoritative) → role heuristic (`system`/`user` → trusted, `tool` → untrusted) → fail-closed default `UNTRUSTED` for unlabeled or unexpected shapes. The heuristic never upgrades a segment to `TRUSTED` against a marker.
- **Interface:** `resolve(messages) -> ProvenanceMap`. Pure function.
- **Depends on:** nothing.

### ToolRegistry
- **Does:** holds registered tools as `name → { privilege: READ_ONLY | PRIVILEGED, executor }`; executes an allowed tool call.
- **SP1 executors:** in-process callables — demo tools plus test fakes. (HTTP-webhook executors are a future extension.)
- **Interface:** `register(name, privilege, executor)`, `get(name)`, `execute(name, args) -> ToolResult`.
- **Depends on:** nothing.

### PolicyEngine / Gate
- **Does:** pure decision `(tool_privilege, taint_state) → GateDecision`.
- **Rule (D4):** `PRIVILEGED` + `taint_state.tainted` → `verdict=DENY`; `READ_ONLY` → `verdict=ALLOW`; `PRIVILEGED` + not tainted → `verdict=ALLOW`.
- **Policy source:** a small declarative config (tool→privilege map + rule). Cedar/OPA is a future extension.
- **Interface:** `evaluate(tool, taint_state) -> GateDecision { verdict, tool, reason, taint_source }`. Pure.
- **Depends on:** policy config.

### OutcomeHandler (interface)
- **Does:** turns a `GateDecision` into an effect.
- **SP1 implementations:** `AllowHandler` (execute via ToolRegistry, append result), `DenyHandler` (fail-closed: skip, mark `action_gated`, record reason + taint source).
- **SP2:** adds `ForkHandler` behind the same interface — no gate-logic changes.
- **Interface:** `handle(decision, ctx) -> HandlerEffect`.

### LLMBackend (interface)
- **Does:** produce the next assistant turn from context.
- **Implementations:** `real` (OpenAI-compatible endpoint / local Ollama, config-selected), `scripted` (canned tool-call sequences keyed to input; used by all tests and the deterministic demo).
- **Interface:** `complete(context) -> AssistantTurn`.

### AgentOrchestrator
- **Does:** wires the loop — call backend, route tool calls through Gate + OutcomeHandler, append results, enforce `max_iters`, assemble the final response and `mirage` metadata block.
- **Depends on:** ProvenanceResolver, LLMBackend, Gate, OutcomeHandler(s), ToolRegistry, Ledger.

### Ledger
- **Does:** append-only SQLite writer + read API. Records: request, provenance map, each `GateDecision`, tool executions, final response.
- **Role:** the "provenance ledger" and the substrate SP3's trajectory recorder and SP4's dashboard read from.
- **Interface:** `append(event)`, `read(session_id)`.

### HTTP API
- **Does:** FastAPI + Pydantic; OpenAI-compatible `/v1/chat/completions` plus Mirage extensions (per-message provenance markers; tool registration/config).
- **Depends on:** AgentOrchestrator.

## Data Model & Contracts

### Provenance marker (request extension)
Per-message optional field, e.g. `x-mirage-provenance: "trusted" | "untrusted"`. Absent → role heuristic → fail-closed `untrusted`. Documented contract: **any externally-sourced data (web pages, tool results, RAG documents, emails) placed anywhere in the request MUST be marked `untrusted`.** The heuristic is a convenience for plain chat only.

### `GateDecision`
```
GateDecision {
  verdict:      ALLOW | DENY
  tool:         string
  reason:       string          # human-readable policy reason
  taint_source: string | null   # which provenance segment tainted the turn
}
```

### `mirage` response metadata block
Attached to the OpenAI-compatible response:
```
mirage {
  action_gated:  bool
  gated_actions: [ { tool, reason, taint_source } ]
  session_id:    string
}
```

### Taint model
`taint_state.tainted` = *any `UNTRUSTED` segment present in the current turn's context at the moment of the tool call.* Untrusted tool results append back into context, so taint latches on for the remainder of the turn — the deliberate conservative posture (D4).

## Error Handling (fail-closed throughout)

| Condition | Behavior |
|-----------|----------|
| Unlabeled / unknown provenance | Treat as `UNTRUSTED` |
| Model calls an unregistered tool | Deny + record |
| `max_iters` exceeded | Stop, return partial turn with a `mirage` note |
| LLMBackend failure | 502-style structured error, recorded |
| Malformed request | Pydantic 4xx validation error |

## Testing Strategy

- **Scripted backend** drives all tests deterministically, network-free.
- **Unit:** ProvenanceResolver (marker/heuristic/fail-closed, no-upgrade-against-marker); Gate decision matrix (privilege × taint, all four cells); OutcomeHandlers (allow executes, deny drops + flags); Ledger writes/reads.
- **Integration (full loop, scripted backend):**
  - trusted privileged action → **allowed**
  - tainted privileged action → **gated** (dropped, `action_gated: true`, correct `taint_source`)
  - read-only tool under taint → **allowed**
  - `mirage` metadata + ledger events present and correct
- **Early injection fixtures:** ~5 injection payloads pulled forward from SP3 as scripted scenarios asserting the gate fires. Seed of the SP3 harness.

## Stack

FastAPI, Pydantic, stdlib `sqlite3` (or SQLModel), pytest, Docker Compose. Minimal dependencies. Cheap/local models fine behind the `real` backend.

## Extension Seams (for later sub-projects)

- **SP2 fork:** add `ForkHandler : OutcomeHandler`; the Gate and Orchestrator are untouched. The `mirage` metadata block already carries the gated-action signal the fork replaces with a fake-success illusion.
- **SP3 trajectories:** read the SQLite ledger; extend the injection-fixture set to 15+ techniques.
- **SP4 dashboard/attribution:** read the ledger; honeytoken store joins here.
