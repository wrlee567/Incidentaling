# Incidentaling — Frontend

Thin Next.js (App Router) dashboard for the SIEM/SOAR simulator.

- **SOC Dashboard** (`/`): live stats, telemetry-by-source chart, alerts table, and the
  SOAR containment state. Buttons inject attack scenarios and drive detect → respond.
- **Playbook Editor** (`/playbooks`): a React Flow visual DAG editor that serializes to
  the backend's `WorkflowDefinition` shape.

## Run

```bash
cp .env.local.example .env.local   # point NEXT_PUBLIC_API_BASE at the backend
npm install
npm run dev                        # http://localhost:3000
```

The backend must be running (default `http://localhost:8000`):

```bash
cd ../backend && uvicorn app.api.main:app --reload
```
