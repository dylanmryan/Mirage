# Mirage — SP4: Attribution + Threat Dashboard Design

**Date:** 2026-07-13
**Status:** Approved (design), pending implementation plan
**Sub-project:** SP4 of 4 (final)
**Builds on:** SP1 proxy core + SP2 deception sandbox + SP3 harness/trajectory

## Context

SP1 gates, SP2 deceives + mints/stores honeytokens + emits `honeytoken_hit` on cross-session reappearance, SP3 reconstructs per-session trajectories/kill-chains and ships the adversarial harness. All of it lands in one SQLite DB (`events` table from the ledger, `honeytokens` table from SP2).

SP4 is the "wow" layer: **attribution** (link sessions into campaigns via bait reappearance) and a **server-rendered threat dashboard** with the split-screen demo. It is almost entirely read-side over data SP1–SP3 already produce.

### Roadmap

| # | Sub-project | Delivers | Depends on |
|---|---|---|---|
| SP1 | Proxy core | Provenance, gate, ledger | — |
| SP2 | Deception sandbox | Fork, honeytokens, reappearance hook | SP1 |
| SP3 | Harness + trajectory + kill-chain | Test suite + live evaluator + intel | SP1, SP2 |
| **SP4** | **Attribution + threat dashboard + split-screen demo** | The "wow" | SP2, SP3 |

## Goals (SP4)

1. Attribution: link sessions into campaigns using only `honeytoken_hit` events (provably-linked, no fuzzy edges).
2. A server-rendered dashboard (FastAPI + Jinja + HTMX, no build step) mounted on the existing app.
3. Views: threat feed/overview, per-session kill-chain timeline, campaigns list + reappearance graph (inline SVG).
4. A live `/demo` route that runs a canned attack via SP3 and renders the split-screen (attacker view | operator view).
5. Safe rendering of attacker-controlled content (autoescaping) — the operator's browser must never be XSS'd by captured attack data.
6. Deterministic, network-free tests; SP1–SP3 behavior unchanged.

## Non-goals (SP4)

- Heuristic/fuzzy attribution (shared payload family, timing) — undercuts the crisp "traceable bait" claim. Noted as a future "suspected links" view.
- A React/SPA frontend or any node/npm toolchain.
- Real-time websockets — HTMX polling covers the "live feed."
- Auth/multi-tenant dashboard access control — out of scope for the demo.

## Key Decisions

| # | Decision | Rationale | Alternatives |
|---|----------|-----------|--------------|
| D1 | **Server-rendered FastAPI + Jinja + HTMX; inline-SVG graph; vendored static assets** | Live feed + split-screen with zero frontend toolchain; one container; matches SP1–SP3 ethos. | React SPA (node build, CORS, second service); static export (no live drama) |
| D2 | **Token-reappearance-only attribution; campaign = connected component (union-find)** | Provably correct — a unique honeytoken resurfacing IS the actor link; no false edges; strongest form of the thesis. | +heuristics (false links dilute the claim); separate low-confidence view (future) |
| D3 | **Live `/demo` runs a canned attack in-process via SP3 `DeterministicRunner`** | Deterministic, works on a cold system, reproducible, reuses SP3, no ledger changes (runner captures full attacker-facing outputs). | Replay a stored session (needs traffic + widened fork summary); static artifact (not live) |
| D4 | **Add Jinja2 as a dependency for autoescaping** | The dashboard renders attacker-controlled strings (payloads, honeytoken values, fake outputs); autoescaping is a security requirement, not convenience. Hand-rolled f-string HTML is where stored-XSS hides. | Manual `html.escape` everywhere (error-prone in a security tool) |
| D5 | **Two additive read-only methods on `ledger.py`; everything else new files** | The ledger is the natural home for cross-session queries; read-only, no behavior change. | A separate module re-querying the schema (duplicates DB knowledge) |
| D6 | **Vendor HTMX/CSS as static files served by `StaticFiles`** | Offline/self-contained container; no CDN dependency (matches the security-tool posture). | CDN `<script>` (external dependency, breaks offline/CSP) |

## Architecture

```
mirage.sqlite  (events + honeytokens, written by SP1–SP3)
   │
   ├─ Ledger.session_ids() / events_by_kind()   (additive, read-only)
   ├─ TrajectoryRecorder (SP3, reused)           per-session kill-chain
   │
   ├─ insights.py
   │     list_sessions(ledger) -> [SessionSummary]
   │     campaigns(ledger)     -> [Campaign]      (union-find over honeytoken_hit)
   │     graph(ledger)         -> {nodes, edges}  (reappearance graph)
   │
   └─ dashboard.py  (FastAPI APIRouter + Jinja templates + vendored HTMX/CSS)
         GET /dashboard               overview + live threat feed (HTMX poll)
         GET /dashboard/feed          HTMX partial (recent sessions/events)
         GET /dashboard/sessions/{id} per-session kill-chain timeline
         GET /dashboard/campaigns     campaigns + inline-SVG reappearance graph
         GET /demo                    live canned attack -> split-screen
```

`create_app(orchestrator, db_path=None)` mounts the dashboard router + static files when `db_path` is set; `main.py` passes `MIRAGE_DB_PATH`.

## Components

### `mirage/ledger.py` (additive, read-only)
- `session_ids() -> list[str]` — distinct session ids in insertion order.
- `events_by_kind(kind: str) -> list[tuple[str, dict]]` — `(session_id, payload)` for all events of a kind, ordered by id. Used for `honeytoken_hit` aggregation.
No changes to `append`/`read`/schema.

### `mirage/insights.py` (new)
- **`SessionSummary`** (dataclass): `session_id, mode, action_gated, forked, kill_chain: list[Phase], tokens_issued: list[str]`. Built by reconstructing each session with the SP3 `TrajectoryRecorder` and reading its `response` event's `mirage` block.
- **`Campaign`** (dataclass): `id: int, sessions: list[str], token_ids: list[str], hit_count: int`.
- **`list_sessions(ledger) -> list[SessionSummary]`**.
- **`campaigns(ledger) -> list[Campaign]`** — union-find: for each `honeytoken_hit` event, `union(payload["issued_session"], payload["current_session"])`; group sessions by root; emit components with ≥2 sessions (bait-proven campaigns), each carrying its token_ids and hit count.
- **`graph(ledger) -> dict`** — `{"nodes": [session_id, ...], "edges": [{"from": issued_session, "to": current_session, "token_id": ...}, ...]}` from `honeytoken_hit` events; nodes include all sessions touched by hits.

### `mirage/dashboard.py` (new)
FastAPI `APIRouter` (prefix none; explicit paths) + `Jinja2Templates`. Routes:
- `GET /dashboard` — counts (sessions, gated, forked, tokens, campaigns) + recent-sessions feed; feed auto-refreshes via HTMX polling `/dashboard/feed`.
- `GET /dashboard/feed` — HTMX partial: recent `SessionSummary` rows.
- `GET /dashboard/sessions/{session_id}` — the session's kill-chain timeline (phases with MITRE labels), gated/forked steps, issued honeytokens; 404 template if unknown.
- `GET /dashboard/campaigns` — campaign cards + an inline-SVG reappearance graph rendered from `graph(ledger)`.
- `GET /demo` — runs `DeterministicRunner("mirage").run(technique)` (default `data_exfil`, selectable via `?technique=`), capturing the attacker-facing transcript (fake outputs + success response) and the operator-facing trajectory; renders a two-pane split-screen.

Templates live in `mirage/templates/`; static assets (vendored `htmx.min.js`, `dashboard.css`) in `mirage/static/`, served via `StaticFiles`. All dynamic text rendered through Jinja autoescaping.

### `mirage/app.py` (additive edit)
`create_app(orchestrator, db_path: Optional[str] = None)`. When `db_path` is provided, construct a read `Ledger(db_path)`, include the dashboard router, and mount `StaticFiles`. When `None` (existing tests), behavior is unchanged — no dashboard.

### `mirage/main.py` (additive edit)
Pass `db_path=MIRAGE_DB_PATH` into `create_app` so the dashboard reads the same ledger the proxy writes.

## Data Model & Contracts

### `SessionSummary`
```
{ session_id, mode, action_gated, forked, kill_chain: [Phase], tokens_issued: [token_id] }
```

### `Campaign`
```
{ id, sessions: [session_id], token_ids: [token_id], hit_count }
```

### `graph`
```
{ nodes: [session_id, ...],
  edges: [ { from: issued_session, to: current_session, token_id }, ... ] }
```

### `/demo` split-screen view model
```
{ technique_id,
  attacker: { transcript: [ {role, content} ], final_response },   # what the attacker's agent saw
  operator: { trajectory: Trajectory, tokens: [token_id] } }       # the truth
```

## Error Handling

| Condition | Behavior |
|-----------|----------|
| Empty DB / no sessions | Dashboard renders an empty-state ("no sessions yet"), no crash |
| Unknown `session_id` | 404 template |
| `/demo` on a cold system | Works — runs its own attack in-process, needs no prior traffic |
| Attacker-controlled strings (payloads, tokens, fake outputs) | Rendered through Jinja autoescaping (no XSS) |
| No honeytoken_hit events | `campaigns` returns `[]`; graph has nodes, no edges |

## Testing Strategy (deterministic, no network)

- **`test_insights.py`** — seed a shared DB by running orchestrator/harness sessions into it:
  - `list_sessions` returns summaries with correct `forked`/`kill_chain`.
  - **Union-find correctness**: session A mints a token, a later session B's untrusted request contains that token (triggering `honeytoken_hit`) → `campaigns` yields one campaign `{A, B}`; an unrelated session C is not in it.
  - `graph` has a node per session and an edge A→B labeled with the token.
- **`test_dashboard.py`** (`TestClient`, `create_app(..., db_path=seeded)`):
  - `GET /dashboard` → 200, lists seeded session ids and counts.
  - `GET /dashboard/sessions/{id}` → shows the kill-chain phases + MITRE labels.
  - `GET /dashboard/campaigns` → shows the linked campaign and an `<svg>` graph.
  - `GET /demo` → 200, both panes present; a honeytoken value and `TRAPPED` appear; the attacker "success" is visible.
  - **XSS guard**: a technique/payload containing `<script>` renders escaped (`&lt;script&gt;`), proving autoescaping.
- **SP1–SP3 regression**: `create_app` with no `db_path` behaves exactly as before; ledger edits are read-only; full suite green.

## Stack

FastAPI + **Jinja2** (new dependency) + vendored HTMX/CSS static assets + stdlib `sqlite3`, pytest, Docker. Same single-container deploy; `pyproject.toml` gains `jinja2`.

## Project completion

SP4 closes the roadmap: SP1 (correct core) → SP2 (deception) → SP3 (adversarial intel) → SP4 (attribution + dashboard + demo). The README's lead thesis (impossibility theorem → defense-to-deception) is now demonstrable end to end via `/demo`.
