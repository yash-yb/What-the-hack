# Day 1 API contracts

All public endpoints are under `/api/v1`. Responses use ISO-8601 UTC timestamps and UUID IDs. Protected routes will use `Authorization: Bearer <token>` from Day 3 onward.

## Authentication (Day 3)

`POST /api/v1/auth/login` accepts `{ "email": "analyst@what-the-hack.local", "password": "..." }` and returns:

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<JWT>",
  "token_type": "bearer",
  "expires_at": "2026-08-30T12:30:00Z",
  "user": {"id": "uuid", "email": "analyst@what-the-hack.local", "display_name": "Demo Analyst", "role": "analyst"}
}
```

Send `Authorization: Bearer <access_token>` on protected calls. Access tokens last 30 minutes by default; refresh tokens last 7 days and are rotated by `POST /api/v1/auth/refresh` with `{ "refresh_token": "<JWT>" }`. `POST /api/v1/auth/logout` revokes the supplied access token. A missing/invalid token returns `401`; an authenticated role without permission returns `403`.

For the local demo, run `cd backend && PYTHONPATH=. python scripts/seed_demo_users.py` after `alembic upgrade head`. This creates the three role accounts shown above; change those passwords before any deployment.

## CSV ingestion (Day 4)

`POST /api/v1/ingestion/upload` accepts an admin-authenticated multipart request with `file` (a UTF-8 `.csv`) and optional `source_name`. The maximum size is 50 MB by default. Required CSV headers are `timestamp`, `src_ip`, `dst_ip`, `protocol`, `packets`, and `bytes`; invalid rows are skipped and counted. Missing required headers, empty files, invalid encoding, unsupported file types, and oversized files receive clear 4xx responses.

The `201` response and `GET /api/v1/ingestion/{job_id}/status` return the persisted job with status and accepted/skipped row counts. Uploading is admin-only; all authenticated roles can read a job's status.

## Traffic windows (Day 5)

After each successful CSV upload, a lightweight FastAPI background task builds that source's fixed 60-second windows. `POST /api/v1/windows/build` is the admin-only manual/backfill endpoint and accepts exactly one of `traffic_source_id` or `ingestion_job_id`. Each stored window reports the count of distinct network five-tuples (`flow_count`), packets, and bytes. Repeating the request refreshes the same windows instead of duplicating them.

`GET /api/v1/windows?traffic_source_id=<uuid>` lets any authenticated role inspect the resulting windows in chronological order.

## Roles

| Role | Allowed MVP actions |
| --- | --- |
| `admin` | Manage users and configuration; upload datasets; view and update alerts; view audit data. |
| `analyst` | View alerts/details; acknowledge, investigate, and resolve alerts; upload only if explicitly enabled. |
| `viewer` | Read dashboard summaries and alert details only. |

## Dashboard alert response

`GET /api/v1/alerts` will return alerts in descending operational priority: risk/severity, then recency.

```json
{
  "items": [
    {
      "id": "uuid",
      "status": "open",
      "severity": "high",
      "title": "High risk of brute-force activity",
      "summary": "Failed connection attempts increased in the observed window.",
      "risk_score": 86.4,
      "risk_level": "high",
      "predicted_attack_type": "brute_force",
      "confidence_score": 0.82,
      "forecast_window_start": "2026-08-28T10:01:00Z",
      "forecast_window_end": "2026-08-28T10:06:00Z",
      "target_host": {"ip_address": "10.0.0.24", "hostname": null},
      "created_at": "2026-08-28T10:01:05Z"
    }
  ],
  "next_cursor": null
}
```

## Alert detail response

`GET /api/v1/alerts/{alert_id}` adds evidence and actions without changing the list-card fields.

```json
{
  "id": "uuid",
  "status": "open",
  "risk_score": 86.4,
  "risk_level": "high",
  "predicted_attack_type": "brute_force",
  "confidence_score": 0.82,
  "forecast_window_start": "2026-08-28T10:01:00Z",
  "forecast_window_end": "2026-08-28T10:06:00Z",
  "explanations": [
    {"feature": "failed_connection_ratio", "message": "Failed connections increased 4.2x.", "importance": 0.71}
  ],
  "recommended_actions": ["Review failed-login activity", "Enable temporary account lockout"],
  "target_host": {"ip_address": "10.0.0.24", "hostname": null},
  "created_at": "2026-08-28T10:01:05Z",
  "updated_at": "2026-08-28T10:01:05Z"
}
```

## ML inference adapter contract

The eventual internal inference call accepts a versioned feature vector and returns a forecast. The backend owns validation and persistence; the ML component must not write directly to application tables.

```json
{
  "observation_window": {
    "id": "uuid",
    "start": "2026-08-28T10:00:00Z",
    "end": "2026-08-28T10:01:00Z"
  },
  "forecast_horizon_seconds": 300,
  "feature_schema_version": "v1",
  "features": {
    "flow_count": 142,
    "failed_connection_ratio": 0.38
  }
}
```

```json
{
  "model_name": "baseline-forecast",
  "model_version": "v1",
  "risk_score": 86.4,
  "risk_level": "high",
  "predicted_attack_type": "brute_force",
  "confidence_score": 0.82,
  "is_uncertain": false,
  "is_ood": false,
  "explanations": [
    {"feature": "failed_connection_ratio", "importance": 0.71, "message": "Failed connections increased 4.2x."}
  ]
}
```

If the model is unavailable, the backend returns a validated rule-based result with `is_fallback: true`. If the feature schema version does not match, it fails closed and records an audit event; it must not silently guess column meanings.
