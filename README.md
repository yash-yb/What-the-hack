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
| Backend | FastAPI scaffold, PostgreSQL schema + Alembic migrations, JWT auth + RBAC, CSV ingestion, 60-second traffic windows, Pydantic inference schemas, Docker | Feature extraction, inference adapter (timeout + fallback), predictions and alerts API, audit trail |
| ML | Forecasting formulation, CICIDS2017 tool, feature-schema contract v1 (37 features), rule-based fallback via `ai.inference.forecast`, contract test suite, sample replay CSV | Window feature extraction, forecasting labels, XGBoost baseline, evaluation report |
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

`tests/ml/test_tier5_adversarial_coverage.py` is ML work in progress and is skipped in CI
until it collects.

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

## How to contribute (team guide)

### Who owns what

| Member | Name | Owns | Works mostly in |
| --- | --- | --- | --- |
| 1 | Durgesh | Team lead: scope, architecture, integration decisions, final PPT story | `docs/`, reviews everywhere |
| 2 | Adarsh | Frontend: login, dashboard, alerts list, alert detail, upload and admin pages | `frontend/`, `tests/frontend/` |
| 3 | Shreya | Backend: APIs, auth, ingestion, windows, predictions, alerts, migrations | `backend/`, `database/`, `tests/backend/` |
| 4 | Yash Bhanushali | AI/ML and data: datasets, features, forecasting labels, model, evaluation, inference | `ai/`, `tests/ml/`, `docs/research/` |
| 5 | Kshitij | UI/UX, QA, documentation: wireframes, test cases, bug reports, user guide, demo notes | `docs/`, `tests/integration/`, `frontend/` (with Adarsh) |
| 6 | Arnav | DevOps, integration, research, presentation: Docker, deployment, demo build, backup video | `deployment/`, `docker-compose.yml`, `.github/` |

Backups so nothing lives with one person: Durgesh and Arnav can both run the full stack;
Shreya and Yash both understand the inference contract; Adarsh and Kshitij both know the
demo flow.

### First-time setup

```bash
git clone https://github.com/DurgeshLabs/What-the-hack.git
cd What-the-hack
git checkout dev
```

Then follow **Quick start** above for your area. Backend and ML people need Python 3.12
and PostgreSQL (Docker), frontend people need Node 20.

### Daily workflow

1. **Pick a task.** Take an issue from the GitHub project board (Backlog -> This Week -> In
   Progress -> Blocked -> Review -> Ready for Integration -> Done). If there is no issue,
   create one with the *Feature / task* template and label it `frontend`, `backend`, `ml`,
   `docs`, or `demo`.
2. **Branch from `dev`.**
   ```bash
   git checkout dev && git pull
   git checkout -b feature/<area>-<topic>      # e.g. feature/frontend-alert-detail, feature/ml-xgboost-baseline
   ```
   Use `fix/<topic>` for bug fixes and `docs/<topic>` for documentation-only changes.
3. **Work in your folder.** Keep changes inside the area you own. If you must touch
   another area (for example the backend needs a new field from ML), open an issue and
   tag the owner first.
4. **Commit small, with a prefix.** `feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
   `chore:`. Example: `feat: add alert detail API`.
5. **Run the checks before pushing.**
   ```bash
   ./deployment/scripts/run_tests.sh            # Python: backend + ML
   cd frontend && npm run build                 # frontend type-check and build
   ```
6. **Open a pull request against `dev`.** Fill in the template: what changed, screenshots
   for UI, test status, known limitations. Link the issue with `Closes #<number>`.
7. **Get one review.** At least one teammate approves before merging. Reviewers check that
   the contract docs still match the code and that nothing hard-codes secrets or paths.
8. **Merge and delete the branch.** `dev` is integrated end to end every two or three days;
   `main` is fast-forwarded from `dev` only after the full demo flow works.

### Rules that keep the demo safe

- Never commit `.env`, datasets, model binaries, or `node_modules`. `.gitignore` already
  blocks them; check `git status` before committing.
- Never edit an Alembic migration that has reached a shared database. Add a new one.
- Never change `docs/api/feature_schema_contract.json` by hand. Edit
  `ai/inference/contract.py`, regenerate, bump the version, and update
  `backend/app/schemas/inference.py` in the same PR.
- Never push directly to `main`.
- Every new API route, parser, feature calculator, or screen ships with a test.
- If you are blocked for more than half a day, move the card to *Blocked* and say so in
  the standup: what you finished, what you are doing today, what is blocking you.

### Where to look first

| I want to... | Read |
| --- | --- |
| Understand the product and its boundaries | `docs/architecture/day-1-scope.md` |
| See the database tables | `docs/architecture/database-schema.md` |
| Call or extend the REST API | `docs/api/api-contracts.md` |
| Integrate with the ML model | `docs/api/ml-inference-contract.md` |
| Run the pipeline end to end | `docs/devlog/day-4-ingestion.md`, `docs/devlog/day-5-windows-and-docker.md` |
| Prepare the demo | `docs/demo/demo-script.md` |
| Branch, commit, and PR rules in full | `CONTRIBUTING.md` |

## Team and ownership

See `CONTRIBUTING.md` for branch strategy (`main` stable, `dev` integration, feature
branches), commit conventions, PR checklist, labels, and the ownership/backup matrix.

## License

MIT — see `LICENSE`.
