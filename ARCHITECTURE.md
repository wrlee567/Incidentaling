# Incidentaling — Interactive SIEM/SOAR Incident Response Simulator

A learning-focused, full-stack simulation of a Security Operations Center pipeline:
**EDR telemetry ingestion → SIEM correlation/storage → SOAR automated response.**

Built primarily in **Python (FastAPI)** — where the system-design value lives — with a
**thin Next.js frontend** for the live dashboard and the React Flow playbook editor.

> This is a *simulator*. Production-grade infrastructure (ClickHouse, Temporal, Kafka,
> multi-tenant auth, real sharding) is **mocked** in-process, with code comments
> explaining how each mock maps to the real system and how it would scale.

---

## Stack (Option A)

| Layer | Technology | Why |
|---|---|---|
| Backend core | Python 3.12 + FastAPI (async) | Push/pull ingestion, WebSockets, the language we want to understand deeply |
| Columnar store | In-process mock (numpy typed arrays) | Models ClickHouse columnar behavior, dtypes, TTL, partitioning |
| Orchestration | Python state machine + SQLite event history | Temporal-style durability, replay, idempotency |
| Frontend | Next.js 16 / React 19 / Tailwind v4 / React Flow | Dashboard, live charts, visual DAG editor |
| Packaging | docker-compose | One-command end-to-end demo |

The frontend is intentionally thin and replaceable; the backend is fully usable on its own.

---

## Repository layout

```
incidentaling/
  backend/                 # Python 3.12, FastAPI — the core
    app/
      models/              # pydantic schemas (strict typing)
      store/               # mock ClickHouse columnar engine
      ingestion/           # hybrid push + pull APIs
      simulation/          # telemetry generator (4624/4688/netflow)
      correlation/         # SIEM detection rules -> alerts
      orchestration/       # state-machine workflow engine
      playbooks/           # ransomware + brute-force DAGs
      api/                 # REST + WebSocket routes
    tests/
  frontend/                # Next.js 16 — dashboard, charts, React Flow editor
  docker-compose.yml
  README.md
  ARCHITECTURE.md
```

---

## Subsystems

### 1. Telemetry ingestion — hybrid push/pull (`app/ingestion/`)
- `POST /ingest/push` — low-latency path for **high-severity EDR alerts**; immediately
  hands off to detection/orchestration.
- Pull path — agents write to per-agent buffers; `GET /ingest/pull` lets the server
  **batch-poll** routine logs at a controlled rate.
- Code comments explain the trade-off: push = freshness but "thundering herd" risk;
  pull = backpressure control but polling latency.

### 2. Mock columnar store (`app/store/`)
- Column-oriented in-memory store (typed `numpy` arrays) modeling ClickHouse.
- **Precision dtypes** (`uint8` vs `uint64`), **no nullable columns** (sentinel defaults),
  **static schema**, columnar scans that read only queried columns.
- **TTL** expiry + **time-based partitioning** (per-day buckets; prune by time range).

### 3. Simulation engine (`app/simulation/`)
- Generates realistic **Windows Event Logs**: 4624 (logon; Kerberos vs NTLM field quirks)
  and 4688 (process creation), plus **TCP/IP netflows**.
- Difficulty levels: noisy brute-force → multi-vector APT. Drives scenarios by flooding
  the ingestion APIs.

### 4. SIEM correlation (`app/correlation/`)
- Rules linking a 4688 `ProcessID` to the originating 4624 logon session ("who ran what").
- Detections: brute-force bursts, lateral movement over SMB, ransomware behavior.
- Raises **alerts** that trigger SOAR playbooks.

### 5. Orchestration engine — Temporal-style (`app/orchestration/`)
- SQLite-backed **event history** → durable, replayable; resume from last checkpoint
  after a simulated worker crash.
- A **single parent workflow** loops over a **DAG** (no per-step workflow spawning);
  supports sequential and parallel branches.
- **Idempotent** activities: at-least-once retries converge to the same state via
  idempotency keys. Simulated "localized transfer queues" per shard.

### 6. Playbooks — dynamic DAGs (`app/playbooks/`)
- **Ransomware containment**: isolate endpoint → block C2 → kill process → segregate →
  compute **Time-to-Contain**.
- **Brute-force mitigation**: lock account → block IP → force password reset →
  review for exfil → enforce MFA.
- Staged-recovery scoring: penalize unsafe "restore-all-to-prod" designs.

### 7. Frontend (`frontend/`)
- Dark-mode dashboard: live telemetry charts (WebSocket), paginated incident table with
  editable status, and a **React Flow** DAG editor that serializes to the backend's
  playbook JSON.

---

## Build order (each phase independently runnable & tested)

1. Models + mock columnar store (+ tests)
2. Ingestion APIs (push/pull)
3. Simulation engine → feeds ingestion
4. Correlation/detection → alerts
5. Orchestration engine + 2 playbooks (+ crash/replay & idempotency tests)
6. Frontend dashboard + React Flow editor
7. docker-compose, README, end-to-end demo script

---

## Explicitly out of scope (documented as "system evolution")
Real ClickHouse/Temporal/Kafka, multi-tenant auth & isolation, true horizontal sharding,
ML anomaly detection. Each is mocked with notes on the production migration path.
