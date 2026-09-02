# Day 1 - Problem framing and scope lock

## Product statement

What the Hack is an early-warning system that uses recent network-traffic behaviour to forecast the likelihood, likely category, and confidence of an attack in a **future short time window**.

It is not an intrusion detector that merely labels the traffic currently being observed. The model will be trained and evaluated with future-shifted labels so that an observation window predicts a later target window.

## Locked MVP

| Area | Decision |
| --- | --- |
| Ingestion | CSV network-flow upload and deterministic replay are the primary demo path. Raw PCAP and live capture are deferred. |
| Windowing | Start with fixed 60-second windows. Sliding windows are an enhancement once the baseline is working. |
| Forecast | Risk for the next 1-5 minutes, expressed as a 0-100 score and `low`, `medium`, or `high` level. |
| Attack type | Optional when model confidence supports it; do not block an alert on a missing type. |
| Model | CPU-friendly tree baseline first (XGBoost, LightGBM, or Random Forest), with a rule-based fallback. |
| Explainability | Ranked, human-readable feature reasons; SHAP is optional for the first end-to-end path. |
| Roles | `admin`, `analyst`, `viewer` only. |
| Application shape | One FastAPI monolith, PostgreSQL, and a frontend dashboard. No microservices for the MVP. |

## Explicit non-goals

- Automated blocking or response execution.
- Production-scale streaming infrastructure.
- Multiple ingestion formats before CSV replay is reliable.
- Deep-learning models before an explainable baseline works.
- Extra app roles or multi-tenant administration.

## Ownership checkpoints

### ML - Yash

Freeze these before implementation of `window_features` and the inference adapter:

1. Input feature names, types, units, missing-value policy, and schema version.
2. Window duration, forecast horizon, and future-label shift.
3. Output fields: `risk_score`, `risk_level`, `predicted_attack_type`, `confidence_score`, `explanations`, and model version.
4. Behaviour for low confidence, unknown traffic, and a failed model call.

### Frontend - dashboard owner

Confirm the list/detail response shapes in `api-contracts.md`, including empty, loading, and error states. The frontend should rely on `risk_score`, `risk_level`, `created_at`, and `status` rather than a display order implied by database IDs.

### Backend - Shreya

- Own the relational schema, migrations, auth/RBAC, ingestion, alert API, and audit trail.
- Preserve the forecasting distinction in the `predictions` schema through explicit target-window fields.
- Provide a stable rule-based inference fallback so UI work is never blocked by the trained model.

## Day 1 acceptance criteria

- [x] Forecasting formulation, MVP boundaries, and roles are documented.
- [x] Backend package structure and dependency list exist.
- [x] Database ERD and relationship/index decisions are documented.
- [x] Initial frontend and ML contracts are documented.
- [ ] Yash and the frontend owner confirm the feature and response contracts.

