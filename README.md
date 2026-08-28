# What the Hack

An explainable early-warning system for SIH26153: **AI-based Network Attack Forecasting from Network Traffic Data**.

The MVP forecasts the risk of an attack in a future window from recent network-traffic behaviour. It does not present a current-traffic classifier as a forecasting solution.

## Day 1 foundation

The backend scaffold and the agreed contracts are in [`backend/`](backend/) and [`docs/`](docs/):

- `docs/day-1-scope.md` - MVP decisions, ownership checkpoints, and non-goals.
- `docs/database-schema.md` - ERD, table definitions, indexes, and forecasting semantics.
- `docs/api-contracts.md` - initial frontend and ML integration contracts.

## Backend quick start

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000/docs` or call `GET /api/v1/health`.

## Team decisions to confirm

1. The ML feature schema and model response contract with Yash.
2. The dashboard alert response shape with the frontend owner.
3. The exact CSV columns for the first replay dataset.
