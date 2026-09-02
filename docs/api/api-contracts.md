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

Send `Authorization: Bearer <access_token>` on protected calls. Access tokens last 30 minutes by default; refresh tokens last 7 days and are rotated by `POST /api/v1/auth/refresh` with `{ "refresh_token": "<JWT>" }`. Each access token carries the id of its paired refresh token, and `POST /api/v1/auth/logout` revokes both, so a logged-out session cannot be resumed with the old refresh token. A missing/invalid token returns `401`; an authenticated role without permission returns `403`.

For the local demo, run `cd backend && PYTHONPATH=. python scripts/seed_demo_users.py` after `alembic upgrade head`. This creates the three role accounts shown above; change those passwords before any deployment.

## CSV ingestion (Day 4)

`POST /api/v1/ingestion/upload` accepts an admin-authenticated multipart request with `file` (a UTF-8 `.csv`) and optional `source_name`. The maximum size is 50 MB by default. Required CSV headers are `timestamp`, `src_ip`, `dst_ip`, `protocol`, `packets`, and `bytes`; invalid rows are skipped and counted. `protocol` is normalised to `TCP`, `UDP`, `ICMP`, or `OTHER` (IANA numbers accepted); `flags` must be `NONE` or a comma-separated list of `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWE`; `failed_conn_info` follows the RawFlow contract (`CLEAN`, `SYN_NO_ACK`, `RST_ABORT`, `ZERO_WIN`, `NA`). Rows that break those rules are skipped. Missing required headers, empty files, invalid encoding, unsupported file types, and oversized files receive clear 4xx responses. Uploading a file whose content was already ingested into the same source returns `409` with the existing job id, because windows aggregate every flow of a source and a repeat would double every count.

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

Frozen in `docs/api/ml-inference-contract.md` and `docs/api/feature_schema_contract.json`
(feature schema `v1`). Summary:

- The backend builds the 37-feature `WindowFeatures` vector per window, validates it with
  `app.schemas.inference.InferenceRequest`, and calls `ai.inference.forecast(request)` in
  process with a 2-second deadline.
- The response carries `risk_score` (0 to 100), `risk_level` (`low`, `medium`, `high`,
  `critical`), `predicted_attack_type`, `forecast_horizon_sec` (default 300), `confidence_score`,
  `explanation_json` (summary plus ranked `top_features`), `is_fallback`, `is_uncertain`, `is_ood`.
- The backend owns persistence: `predictions` gets one row per response with explicit
  `forecast_window_start` and `forecast_window_end`; the ML component never writes to
  application tables.
- Schema mismatch and invalid features fail closed (422 plus an audit event). Model
  unavailable, timeout, or a model exception fall back to `ai.inference.rule_based_forecast`
  with `is_fallback: true`.

The public alert responses above expose `explanations` as the `top_features` list and
`recommended_actions` from `explanation_json.mitigation_recommendation` plus the
attack-type rule table.
