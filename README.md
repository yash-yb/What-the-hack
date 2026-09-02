# What the Hack — AI-based Network Attack Forecasting

**SIH 2026 · Problem statement SIH26153 · National Technical Research Organisation (NTRO)**
**Theme: Blockchain & Cybersecurity · Category: Software · Team Cogitate**

An explainable early-warning system that forecasts likely cyber attacks from network-traffic
behaviour **before they fully materialise**. It groups recent traffic into short windows,
extracts behavioural features, predicts the risk of an attack in the next 1–5 minutes, and
presents ranked, human-readable reasons and recommended actions to a security analyst.

This is forecasting, not detection: the model is trained with future-shifted labels, so the
features of window `t` predict whether an attack starts or escalates in `(t, t + horizon]`.
See `docs/research/forecasting_formulation.md`.

## Status

| Area | Done | Next |
| --- | --- | --- |
| Backend | FastAPI scaffold, PostgreSQL schema + Alembic migrations, JWT auth + RBAC, CSV ingestion, 60-second traffic windows, Docker | Feature extraction, inference adapter with rule-based fallback, alerts API, audit trail |
| ML | Forecasting formulation, CICIDS2017 acquisition/normalisation tool, contract test suite, sample replay CSV | Feature-schema contract JSON (R3), windowing + labels, XGBoost baseline, evaluation report |
| Frontend | Next.js scaffold with API client and backend health card | Login, dashboard, alerts list, alert detail, upload/admin pages |
| Deployment | `docker-compose.yml` for db + backend + frontend, CI workflow | Demo seed data, backup demo build |

## Repository layout

```text
.
├── frontend/        Next.js analyst dashboard (app/, components/, lib/, public/)
├── backend/         FastAPI API: app/{api,core,db,models,schemas,services}, alembic/, tests/
├── ai/              ML workspace: datasets/, preprocessing/, feature_engineering/, training/,
│                    evaluation/, inference/, models/, notebooks/
├── database/        Schema snapshots, seed notes, migration rules (Alembic lives in backend/)
├── tests/           ml/ (contract + invariant tests), backend/, integration/, frontend/
├── docs/            architecture/, api/, research/, demo/, devlog/, diagrams/
├── deployment/      docker/, compose/, scripts/ (bootstrap_backend.sh, run_tests.sh)
├── sample_data/     sample_flows_mini.csv — deterministic 3-phase replay sample
├── .github/         CI workflow, PR and issue templates
├── docker-compose.yml
├── .env.example
├── CONTRIBUTING.md
└── LICENSE
```

## Quick start

### Option A — everything in Docker

```bash
cp .env.example .env            # set JWT_SECRET_KEY
docker compose up --build
```

| Service | URL |
| --- | --- |
| Frontend | http://localhost:3000 |
| Backend API docs | http://localhost:8000/docs |
| Health check | http://localhost:8000/api/v1/health |
| PostgreSQL | localhost:5432 (`what_the_hack` / `what_the_hack`) |

`docker compose down` stops the stack and keeps the database volume. Only use
`docker compose down -v` when you intend to delete local data.

### Option B — local development

```bash
docker compose up -d db                      # PostgreSQL only
./deployment/scripts/bootstrap_backend.sh    # venv, deps, migrations, demo users
cd backend && PYTHONPATH=. .venv/bin/uvicorn app.main:app --reload
```

In a second terminal:

```bash
cd frontend && cp .env.example .env.local && npm install && npm run dev
```

Demo accounts are created by `backend/scripts/seed_demo_users.py` (roles `admin`,
`analyst`, `viewer`). Change the passwords before any deployment.

### Try the pipeline

Follow `docs/devlog/day-4-ingestion.md` to log in and upload
`sample_data/sample_flows_mini.csv`, then `docs/devlog/day-5-windows-and-docker.md` to
build and inspect the traffic windows.

## Tests

```bash
./deployment/scripts/run_tests.sh            # pytest over backend/tests and tests/
./deployment/scripts/run_tests.sh backend/tests
./deployment/scripts/run_tests.sh tests/ml
cd frontend && npm run build
```

The ML contract suite requires `docs/api/feature_schema_contract.json` (Deliverable R3),
which has not been committed yet; those tests fail until it lands.

## Architecture

```text
Traffic source / dataset → Ingestion API → raw_flows → Window builder → traffic_windows
   → Feature extraction → window_features → Forecasting model (XGBoost, rule fallback)
   → predictions → Alert engine + explanations → alerts → Dashboard APIs → Next.js dashboard
   → Analyst acknowledges → alert_events, audit_logs
```

| Layer | Choice |
| --- | --- |
| Frontend | Next.js, React, Tailwind CSS |
| Backend | FastAPI, SQLAlchemy 2, Alembic, Pydantic |
| Database | PostgreSQL 16 |
| ML | XGBoost / LightGBM baseline, Random Forest comparison, SHAP explanations |
| Auth | JWT + role-based access control (`admin`, `analyst`, `viewer`) |
| Deployment | Docker Compose; CPU-only, no paid APIs |

Details: `docs/architecture/`, `docs/api/api-contracts.md`, `docs/architecture/database-schema.md`.

## Roadmap

- **MVP**: login, CSV upload/replay, windowing, feature extraction, one forecasting model,
  risk score, dashboard with alerts, one alert detail page with explanation.
- **Strong**: near-real-time replay, attack-type classification, SHAP panel, threshold
  tuning, host analytics, alert status workflow, model comparison, audit logs.
- **Winning**: true next-window labels, lead-time visualisation, detection-vs-forecasting
  comparison, uncertainty handling, attack progression timeline, recommendations,
  multi-dataset benchmarking.
- **Future (not for SIH)**: real enterprise traffic, automated firewall rules, multi-tenant
  SOC, distributed streaming, federated learning, adversarially robust sequence models.

## Security

JWT auth with Argon2 password hashing, RBAC on every protected route, Pydantic validation,
upload size and type limits, CORS locked to the frontend origin, no secrets in the repo.
This is a prototype: production hardening (HTTPS, rate limiting, secret rotation) is
documented as future work.

## Datasets and honesty

Public benchmarks only: CICIDS2017 (primary), UNSW-NB15, CTU-13, NSL-KDD as a baseline.
Synthetic replay data is used for demo visualisation only, never as evaluation evidence.
Reported metrics come from held-out data under the purge-embargo split; production accuracy
depends on environment-specific retraining.

## Team and ownership

See `CONTRIBUTING.md` for branch strategy (`main` stable, `dev` integration, feature
branches), commit conventions, PR checklist, labels, and the ownership/backup matrix.

## License

MIT — see `LICENSE`.
