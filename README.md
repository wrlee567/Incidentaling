# Incidentaling

An interactive **SIEM / EDR / SOAR incident-response simulator** — a self-contained
Security Operations Center pipeline you can run, attack, and defend on your laptop.

It models the full lifecycle: **EDR telemetry → hybrid ingestion → columnar SIEM
storage → correlation/detection → automated SOAR containment** — and is built to double
as a system-design study vehicle (see [`ARCHITECTURE.md`](./ARCHITECTURE.md)).

```
 EDR agents          Ingestion            SIEM                Correlation        SOAR
 (simulated)   push/pull APIs   columnar store (mock CH)   detection rules   durable engine
   4624  ───►  /ingest/push ─►  logon  table  ─────────►  ransomware rule ─►  playbook DAG
   4688  ───►  /ingest/spool    process table              brute-force rule    (Temporal-style)
 netflow ───►  /ingest/pull  ─►  netflow table  ─────────► C2 beacon rule  ─►  contain + measure
```

## Stack
- **Backend (the core):** Python 3.11+ / FastAPI. Async ingestion, in-process mock of a
  ClickHouse columnar store, and a Temporal-style durable workflow engine.
- **Frontend (thin):** Next.js / React / Tailwind — dashboard, live charts, and a
  React Flow visual playbook (DAG) editor. *(see `frontend/`)*

## Quick start (backend)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python demo.py            # in-process end-to-end demo (no server)
pytest                    # full test suite
uvicorn app.api.main:app --reload   # http://localhost:8000/docs
```

### Drive it over HTTP
```bash
curl -X POST "localhost:8000/simulate?scenario=ransomware"   # inject an attack
curl -X POST localhost:8000/detect                            # SIEM raises alerts
curl -X POST localhost:8000/soar/respond                      # SOAR contains it
curl localhost:8000/soar/environment                          # see what was contained
```

## What each subsystem demonstrates

| Subsystem | Module | Design idea you can defend in an interview |
|---|---|---|
| Hybrid ingestion | `app/ingestion`, `app/api/ingestion_routes.py` | Push for critical (freshness) vs pull/batch for routine (backpressure, no thundering herd) |
| Columnar store | `app/store/columnar.py` | Column layout, precision dtypes (UInt8 vs UInt64), no NULLs, low-cardinality dict encoding, time partitioning + TTL |
| Simulation | `app/simulation` | Authentic 4624/4688/netflow telemetry; Kerberos vs NTLM field quirks; signal buried in noise |
| Correlation | `app/correlation/detector.py` | Joining 4688 ProcessID ↔ 4624 session; idempotent (deterministic) alert ids |
| Orchestration | `app/orchestration` | Durable event-sourced state machine, replay/resume after crash, at-least-once + **idempotent** activities, single parent loop over a **DAG** |
| Playbooks | `app/playbooks` | Ransomware containment & brute-force mitigation as dependency graphs; time-to-contain metric |

## Testing
`pytest` covers the store, ingestion API, simulation+detection, the orchestration engine
(including a **crash-and-resume idempotency** test), and the full simulate→detect→respond
HTTP flow.

## Not built (documented as system evolution)
Real ClickHouse/Temporal/Kafka, multi-tenant isolation, true sharding, ML anomaly
detection — each is mocked in-process with comments on the production migration path.
