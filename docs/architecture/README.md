# Architecture

- `day-1-scope.md` — product statement, locked MVP, non-goals, ownership checkpoints.
- `database-schema.md` — ERD, 13 tables, indexes, and the forecasting invariant.

## End-to-end workflow

```text
Traffic source / dataset (CSV replay, PCAP later)
        ↓  POST /api/v1/ingestion/upload
Ingestion API + parser  →  raw_flows
        ↓  background task / POST /api/v1/windows/build
Flow builder + window aggregator  →  traffic_windows
        ↓
Feature extraction engine  →  window_features
        ↓  inference adapter (InferenceRequest → InferenceResponse)
Forecasting model (XGBoost baseline, rule-based fallback)  →  predictions
        ↓
Alert engine + explanations + recommendations  →  alerts, alert_events
        ↓  GET /api/v1/alerts, /alerts/{id}
Next.js dashboard  →  analyst acknowledges  →  audit_logs
```

## Stack

| Layer | Choice | Reason |
| --- | --- | --- |
| Frontend | Next.js (React, Tailwind) | Fast dashboards, easy charts, familiar to the team |
| Backend | FastAPI + SQLAlchemy + Alembic | Python-native ML integration, typed contracts |
| Database | PostgreSQL 16 | Relational alerts, windows, model metadata, time queries |
| Queue/cache | Redis (optional, post-MVP) | Background jobs, replay state |
| ML | XGBoost/LightGBM baseline, SHAP explanations | CPU-friendly, explainable, strong on tabular features |
| Auth | JWT + RBAC (`admin`, `analyst`, `viewer`) | Simple and sufficient for the prototype |
| Deployment | Docker Compose | Reproducible judge demo |
