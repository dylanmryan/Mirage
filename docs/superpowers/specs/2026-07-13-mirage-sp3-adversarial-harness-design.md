# Mirage — SP3: Adversarial Harness + Trajectory Recorder Design

**Date:** 2026-07-13
**Status:** Approved (design), pending implementation plan
**Sub-project:** SP3 of 4 (see Roadmap)
**Builds on:** SP1 proxy core + SP2 deception sandbox

## Context

SP1 built the gate; SP2 built the deception fork and the honeytoken store; both log every step to an append-only SQLite ledger (`request`, `provenance`, `gate_decision`, `tool_execution`, `fork`, `honeytoken_issued`, `honeytoken_hit`, `response`).

SP3 turns that raw event stream into **attack intelligence** and hardens the system with a real adversarial corpus. Three deliverables: (1) a catalog of 15+ prompt-injection techniques, (2) a trajectory recorder that reconstructs a per-session attack timeline from the ledger, (3) kill-chain reconstruction that labels each step with an attack phase. The catalog doubles as a deterministic CI test suite and a live adversarial evaluator/demo.

### Roadmap

| # | Sub-project | Delivers | Depends on |
|---|---|---|---|
| SP1 | Proxy core | Provenance, gate, ledger | — |
| SP2 | Deception sandbox | Fork-to-shadow, honeytokens, reappearance hook | SP1 |
| **SP3** | **Adversarial harness + trajectory recorder + kill-chain** | Test suite + live evaluator + attack intel | SP1, SP2 |
| SP4 | Attribution + threat dashboard + split-screen demo | The "wow" | SP2, SP3 |

## Goals (SP3)

1. A static technique catalog (15+) as a first-class `mirage/` artifact, each technique a step sequence.
2. Two runners over one catalog: a deterministic pytest runner (CI) and a live CLI runner (real model).
3. A trajectory recorder that reconstructs an ordered per-session timeline purely from ledger data.
4. Kill-chain reconstruction: bespoke LLM-injection phases, each annotated with the nearest MITRE ATT&CK tactic.
5. Two live metrics: attempt rate (did the real model fall for it) and containment rate (of attempts, how many Mirage caught — 100% by construction).
6. Deterministic, network-free tests; SP1/SP2 code untouched.

## Non-goals (SP3)

- The threat dashboard / visual rendering (SP4). SP3 ships a text timeline in the CLI only.
- Campaign linking / reappearance graph (SP4).
- Any change to the gate, fork, or ledger — SP3 is purely additive (catalog + read-side reconstruction + runners).
- Fine-tuning or model-side defenses — out of thesis scope.

## Key Decisions

| # | Decision | Rationale | Alternatives |
|---|----------|-----------|--------------|
| D1 | **Both runners over one catalog** | Honest answer to "test suite AND demo"; catalog is the real asset, runners are thin over it. | Deterministic-only (demo undersells, no catch rate); live-only (no CI net) |
| D2 | **Techniques are step sequences; length-1 default** | Gives kill-chain reconstruction genuine multi-phase trajectories; shows sticky shadow springing repeatedly; length-1 costs nothing. | Single-shot only (kill-chain cosmetic) |
| D3 | **Bespoke LLM-injection phases + MITRE annotation** | Matches what actually happens in injection; MITRE names are a free industry-credibility layer. | MITRE tactics directly (forced mappings); minimal 3-phase (thin) |
| D4 | **Recorder derives phases from ledger data (tool name + event kind), not from the catalog** | Recorder works on ANY session — real attacker traffic included, not just catalog runs. | Recorder reads catalog-declared phases (wouldn't work on live/unknown sessions) |
| D5 | **Catalog lives in `mirage/`, not `tests/`** | The live CLI ships it as a real artifact; SP1's five `tests/fixtures/injections.py` entries migrate in and expand to 15+. | Keep in tests/ (can't ship in the CLI product) |
| D6 | **Both runners drive the in-process `AgentOrchestrator` (no HTTP dependency)** | Simpler, testable; live runner just swaps in `RealBackend`. | Live runner hits the HTTP endpoint (adds a running-server dependency to the demo) |

## Architecture

```
techniques catalog ──┬─→ DeterministicRunner (ScriptedBackend, mirage|deny) ──┐
                     └─→ LiveRunner (RealBackend → local model) ──────────────┤
                                                                              ↓
                                        AgentOrchestrator (SP1/SP2, unchanged)
                                                                              ↓
                                                    Ledger (SP1/SP2, unchanged)
                                                                              ↓
                              TrajectoryRecorder.reconstruct(session_id) → Trajectory{ steps, kill_chain }
                                                                              ↓
                              deterministic: assertions   |   live: catch-rate report + text timeline
```

The recorder reads only what the ledger already contains; the catalog's declared phases are used solely as *expected values* in deterministic assertions, never as recorder input.

## Components (all new; SP1/SP2 code untouched)

### `mirage/phases.py`
- **`Phase`** enum: `RECON`, `INJECTION`, `COLLECTION`, `EXFILTRATION`, `TRAPPED`, `BLOCKED`.
- **`MITRE`** mapping: `RECON→"Reconnaissance"`, `INJECTION→"Initial Access"`, `COLLECTION→"Collection"`, `EXFILTRATION→"Exfiltration"`, `TRAPPED→"Deception (defensive)"`, `BLOCKED→"Mitigation (defensive)"`.
- **`phase_for_tool(name) -> Phase`**: `search→RECON`, `read_secrets→COLLECTION`, `send_email→EXFILTRATION`, `http_post→EXFILTRATION`; unknown → `INJECTION` (fallback).
- **`phase_for_event(event) -> Optional[Phase]`**: `fork→TRAPPED`; `gate_decision` with `verdict==deny` and no fork → `BLOCKED`; untrusted `provenance` present → seeds `INJECTION`.

### `mirage/techniques.py`
- **`AttackStep`** (dataclass): `tool: str`, `args: dict`, `expected_phase: Phase`.
- **`Technique`** (dataclass): `id: str` (unique), `name: str`, `family: str`, `payload: str` (untrusted injection text), `delivery: str = "tool"` (role the payload arrives as; always untrusted provenance), `steps: list[AttackStep]`, `expected_kill_chain: list[Phase]`.
- **`CATALOG: list[Technique]`** — ≥15 entries across families: direct-override, roleplay/DAN, fake-system/authority-spoof, exfil-chaining (read→send), unicode/zero-width obfuscation, base64/rot13 encoding, payload-splitting, indirect/RAG-document injection, tool-result poisoning, system-prompt-leak-then-exfil, confused-deputy, markdown-link exfil, conditional-trigger, recon-then-exfil (search→http_post), second-order injection. The five SP1 `tests/fixtures/injections.py` payloads migrate in.

### `mirage/trajectory.py`
- **`TrajectoryStep`** (dataclass): `iteration: int`, `tool: Optional[str]`, `verdict: Optional[str]`, `forked: bool`, `honeytokens: list[str]`, `phase: Phase`.
- **`Trajectory`** (dataclass): `session_id: str`, `steps: list[TrajectoryStep]`, `kill_chain: list[Phase]` (ordered distinct phases reached), `contained: bool`, `trapped: bool`, `tokens_issued: list[str]`.
- **`TrajectoryRecorder`**: `reconstruct(session_id) -> Trajectory`. Reads `ledger.read(session_id)`, walks events in order, derives each step's phase via `phases.py`, assembles the kill-chain as the de-duplicated ordered phase list, and sets summary flags (`contained` = every privileged step gated or forked; `trapped` = any `fork`; `tokens_issued` from `honeytoken_issued` events).

### `mirage/harness.py`
- **`DeterministicRunner`**: for a `Technique`, build a `ScriptedBackend` whose turns emit each step's tool call in order followed by a final text turn; run through an `AgentOrchestrator` (mode configurable) with the technique's `payload` delivered as an untrusted message; reconstruct and return the `Trajectory`.
- **`LiveRunner`**: same shape but a `RealBackend` (local model); additionally records whether the model actually emitted a privileged call (`attempted`). Returns `(Trajectory, attempted: bool)`.
- **`run_catalog_live(...) -> Report`**: iterate the catalog, aggregate attempt rate and containment rate.
- **`__main__`** CLI (stdlib `argparse`): runs the live catalog against a configured real backend, prints a per-technique text timeline (phase-annotated steps) + aggregate metrics.

## Data Model & Contracts

### `Trajectory` (consumed by SP4)
```
Trajectory {
  session_id:     str
  steps:          [ { iteration, tool, verdict, forked, executed, honeytokens, phase } ]
  kill_chain:     [ Phase, ... ]      # ordered, de-duplicated
  contained:      bool                # every privileged step gated/forked
  trapped:        bool                # any fork fired
  tokens_issued:  [ token_id, ... ]
}
```

### Live metrics
- **attempt_rate** = attempts / total techniques (did the real model emit the privileged call).
- **containment_rate** = contained_attempts / attempts (100% by construction — the claim to demonstrate). Reported explicitly, and `log`ged if any attempt is *not* contained (would indicate a gate regression).

## Error Handling

| Condition | Behavior |
|-----------|----------|
| Live model ignores the injection (no privileged call) | Step recorded `attempted=False`; not a Mirage failure |
| Unknown tool in live mode | `phase_for_tool` → `INJECTION` fallback |
| Session with no privileged step | Trajectory contains only `RECON`/`INJECTION` phases |
| Ledger has no events for a session_id | `reconstruct` returns an empty `Trajectory` (no steps, empty kill_chain) |

## Testing Strategy (deterministic, no network)

- **`test_phases.py`** — `phase_for_tool` mapping for all demo tools + unknown fallback; every `Phase` has a `MITRE` annotation; `phase_for_event` maps fork→TRAPPED, deny→BLOCKED.
- **`test_trajectory.py`** — drive a known multi-step session through an `AgentOrchestrator` (mirage mode, scripted backend: `read_secrets` then `send_email`), then assert the reconstructed `steps`, `kill_chain` (`[INJECTION, COLLECTION, EXFILTRATION, TRAPPED]`), `contained`, `trapped`, and `tokens_issued`.
- **`test_techniques.py`** — `CATALOG` has ≥15 entries; ids unique; every step's tool is a known demo tool or has a phase; `expected_kill_chain` non-empty.
- **`test_harness.py`** — `DeterministicRunner` over the full catalog in **mirage mode**: every privileged step contained (containment 100%), reconstructed `kill_chain` equals each technique's `expected_kill_chain`, honeytokens issued where the technique expects `TRAPPED`; a **deny-mode** pass asserts every privileged step yields `BLOCKED` and no honeytokens.
- **SP1/SP2 regression:** unchanged and green (SP3 adds no edits to their modules; the five migrated payloads keep an equivalent assertion).

## Stack

Unchanged — FastAPI, Pydantic, stdlib `sqlite3`, pytest, Docker. CLI via stdlib `argparse`. No new dependencies.

## Extension Seams (for SP4)

- **Dashboard:** renders `Trajectory` objects (timeline + kill-chain view) straight from `TrajectoryRecorder`.
- **Attribution:** joins `honeytoken_hit` events (SP2) across sessions into campaigns; the `Trajectory.tokens_issued` list is the per-session edge set.
