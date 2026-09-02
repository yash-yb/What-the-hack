# ML inference contract (feature schema v1)

Answers to the backend's contract questions. The machine-readable version is
`docs/api/feature_schema_contract.json`, generated from `ai/inference/contract.py`
(single source of truth). The backend mirror is `backend/app/schemas/inference.py`.
Change the Python, regenerate the JSON, bump the contract version, and update both.

| Decision | Value |
| --- | --- |
| Feature schema version | `v1` (contract file version `1.0.0`) |
| Number of features | 37, all required, no extra keys |
| Default forecast horizon | **300 s**. Allowed: 60, 120, 300 |
| Observation window | 60 s (macro profile). Backend MVP uses fixed windows, stride 60 s; training uses stride 10 s |
| Risk score | float, 0 to 100 |
| Risk levels | `low` < 20, `medium` 20 to 49.9, `high` 50 to 74.9, `critical` >= 75 |
| Default alert threshold | 50 (risk score at or above it sets `alert_triggered`) |
| Confidence | float, 0 to 1. Below **0.55** is a low-confidence forecast |
| How to call | In-process Python: `ai.inference.forecast(request) -> response`. No separate service in the MVP |
| Timeout | Backend waits 2 s, then uses the rule-based fallback |

## 1. Feature list

Every feature is computed per observation window from `raw_flows`. Ratios are in `[0, 1]`,
entropies in bits, durations in milliseconds, rates per second.

| # | Feature | Type | Unit / range | Missing rule |
| --- | --- | --- | --- | --- |
| 1 | `flow_count` | int | flows, >= 1 | window with 0 flows is rejected |
| 2 | `packet_count` | int | packets | always defined |
| 3 | `byte_count` | int | bytes | always defined |
| 4 | `avg_packets_per_flow` | float | packets/flow | 0 if denominator 0 |
| 5 | `avg_bytes_per_flow` | float | bytes/flow | 0 if denominator 0 |
| 6 | `avg_duration_ms` | float | ms | 0 if denominator 0 |
| 7 | `packet_length_mean` | float | bytes | 0 if denominator 0 |
| 8 | `packet_length_std` | float | bytes | 0 if denominator 0 |
| 9 | `unique_src_ips` | int | hosts | always defined |
| 10 | `unique_dst_ips` | int | hosts | always defined |
| 11 | `unique_src_ports` | int | 0 to 65536 | always defined |
| 12 | `unique_dst_ports` | int | 0 to 65536 | always defined |
| 13 | `src_ip_entropy` | float | bits, 0 to 32 | 0 if denominator 0 |
| 14 | `dst_port_entropy` | float | bits, 0 to 16 | 0 if denominator 0 |
| 15 | `protocol_tcp_ratio` | float | ratio | 0 if denominator 0 |
| 16 | `protocol_udp_ratio` | float | ratio | 0 if denominator 0 |
| 17 | `protocol_icmp_ratio` | float | ratio | 0 if denominator 0 |
| 18 | `syn_ratio` | float | ratio | 0 if denominator 0 |
| 19 | `ack_ratio` | float | ratio | 0 if denominator 0 |
| 20 | `fin_ratio` | float | ratio | 0 if denominator 0 |
| 21 | `rst_ratio` | float | ratio | 0 if denominator 0 |
| 22 | `syn_ack_ratio` | float | >= 0, SYN flows / (ACK flows + 1) | always defined |
| 23 | `failed_conn_ratio` | float | ratio | 0 if denominator 0 |
| 24 | `short_flow_ratio` | float | ratio, flows < 100 ms | 0 if denominator 0 |
| 25 | `inbound_outbound_ratio` | float | >= 0 | 0 if denominator 0 |
| 26 | `retry_rate` | float | ratio | 0 if denominator 0 |
| 27 | `packet_rate_per_sec` | float | packets/s | always defined |
| 28 | `byte_rate_per_sec` | float | bytes/s | always defined |
| 29 | `flow_rate_per_sec` | float | flows/s | always defined |
| 30 | `packet_burst_score` | float | multiplier vs mean of previous 3 windows | 1.0 until 3 prior windows exist |
| 31 | `syn_burst_score` | float | multiplier vs mean of previous 3 windows | 1.0 until 3 prior windows exist |
| 32 | `delta_packet_rate` | float | packets/s, any sign | 0 for the first window |
| 33 | `delta_byte_rate` | float | bytes/s, any sign | 0 for the first window |
| 34 | `delta_syn_ratio` | float | -1 to 1 | 0 for the first window |
| 35 | `delta_failed_conn_ratio` | float | -1 to 1 | 0 for the first window |
| 36 | `delta_unique_dst_ports` | int | -65536 to 65536 | 0 for the first window |
| 37 | `delta_packet_burst_score` | float | any sign | 0 for the first window |

Exact formulas are in the `description` of each property in the JSON contract and in
`docs/research/forecasting_formulation.md` section 5.

## 2. Missing-data rules

1. A window with zero flows is never sent to the model. The backend stores
   `window_features.is_complete = false` and lists the reason in `missing_fields_json`.
2. Ratios and averages with a zero denominator are `0.0`.
3. Delta features are `0.0` for the first window of a source. Burst scores are `1.0`
   until three earlier windows exist.
4. Flags for non-TCP flows count as no flags. `failed_conn_info = NA` counts as not failed.
5. Anything still missing, non-numeric, NaN, or infinite after those rules is an
   `INVALID_FEATURES` error. No mean or median imputation in v1.

## 3. Model output

```json
{
  "window_id": "win-20260828-0001",
  "timestamp": "2026-08-28T18:01:00Z",
  "risk_score": 84.5,
  "risk_level": "critical",
  "predicted_attack_type": "DDoS_LOIC",
  "forecast_horizon_sec": 300,
  "confidence_score": 0.92,
  "explanation_json": {
    "summary": "Critical risk of DDoS activity in the next 300 seconds: SYN burst score 8.0x the recent average.",
    "top_features": [
      {"feature": "syn_burst_score", "contribution": 0.42, "description": "SYN burst score 8.0x the recent average: SYN flood build-up.", "feature_value": 8.0, "baseline_value": 1.0}
    ],
    "mitigation_recommendation": "Enable TCP SYN cookies, pre-stage upstream rate limiting, and inspect source concentration for a block list.",
    "model_version": "xgboost-forecaster-v1.0.0",
    "method": "treeshap",
    "inference_latency_ms": 12.4
  },
  "alert_triggered": true,
  "stage_progression": "S3_ACTIVE_PEAK",
  "is_fallback": false,
  "is_uncertain": false,
  "is_ood": false,
  "model_name": "xgboost-forecaster",
  "model_version": "xgboost-forecaster-v1.0.0",
  "feature_schema_version": "v1"
}
```

- `timestamp` is the observation window end `t`. The forecast covers `(t, t + horizon]`.
  The backend stores that as `forecast_window_start` and `forecast_window_end`.
- `predicted_attack_type` is one of the 14 canonical CICIDS2017 labels (`PortScan`,
  `DoS_Hulk`, `DoS_GoldenEye`, `DoS_Slowloris`, `DoS_Slowhttptest`, `Heartbleed`,
  `DDoS_LOIC`, `FTP_Patator`, `SSH_Patator`, `Botnet`, `Web_BruteForce`, `Web_XSS`,
  `Web_SqlInjection`, `Infiltration`), a coarse family when the model cannot be more
  specific (`Reconnaissance`, `BruteForce`, `DoS`, `DDoS`, `WebAttack`, `Botnet_C2`,
  `Infiltration`), `BENIGN` when risk is below 20, or `UNKNOWN` when out-of-distribution.
- `explanation_json.top_features` holds 1 to 10 items ranked by `contribution`
  (SHAP value or normalised rule weight), each with a one-sentence analyst-readable
  `description` and, when available, the observed and baseline values.
- Alert severity in `alerts.severity` follows `risk_level` one to one. When
  `is_uncertain` is true the severity is capped at `high`.

## 4. How to call the model

In-process Python, same monolith, no network hop:

```python
from ai.inference import forecast, InferenceError

try:
    response = forecast(request_dict)     # dict in, dict out, both contract-validated
except InferenceError as exc:             # exc.code: FEATURE_SCHEMA_MISMATCH | INVALID_FEATURES
    ...
```

- The backend validates with `app.schemas.inference.InferenceRequest` before calling and
  with `InferenceResponse` after, then persists into `predictions`.
- The backend runs the call with a 2-second deadline. Timeout or any exception other
  than `InferenceError` switches to `ai.inference.rule_based_forecast` and marks the
  result `is_fallback = true`.
- Run the backend with the repository root on `PYTHONPATH` (the Docker image does this;
  locally use `PYTHONPATH=..:.` from `backend/`).
- `POST /internal/predict` with the same bodies is reserved for the strong version, when
  inference moves to its own container. It is not exposed in the MVP.
- The rule-based fallback has no ML dependencies. The trained model will add `xgboost`
  (and optionally `shap`) to `backend/requirements.txt` when it ships.

## 5. Failure behaviour

| Situation | Rule | What the caller gets |
| --- | --- | --- |
| Low confidence | `confidence_score < 0.55` | Normal response with `is_uncertain: true`; summary starts with "Uncertain forecast."; alert still created from `risk_score`, severity capped at `high` |
| Out-of-distribution | 3 or more features with a z-score above 6 against the training statistics stored in `model_versions.metrics_json` | `is_ood: true`, `predicted_attack_type: "UNKNOWN"`, `confidence_score <= 0.3`, summary "Pattern unseen, investigate manually." |
| Schema mismatch | `feature_schema_version != "v1"` | `InferenceError(FEATURE_SCHEMA_MISMATCH)`. Backend returns 422, writes an audit event, stores nothing, does not fall back |
| Invalid features | missing, extra, non-numeric, NaN/inf, or out of bounds; or `flow_count = 0` | `InferenceError(INVALID_FEATURES)` with `details.violations` per feature. Same handling as above |
| No model artifact | `MODEL_UNAVAILABLE` | Fallback response, `is_fallback: true`, `fallback_reason: "MODEL_UNAVAILABLE"` |
| Timeout | more than 2 s | Fallback response, `fallback_reason: "INFERENCE_TIMEOUT"` |
| Model exception | anything else | Fallback response, `fallback_reason: "INTERNAL_ERROR"`, trace logged |

Error body (HTTP 422 from the backend, or `InferenceError.to_dict()` in Python):

```json
{"error_code": "INVALID_FEATURES", "message": "One or more features violate the contract", "details": {"violations": {"syn_ratio": "above maximum 1"}}}
```

## 6. Rule-based fallback

`ai/inference/fallback.py` scores three precursor families from the research doc
(reconnaissance, brute force, volumetric DDoS) with fixed thresholds, returns the same
response shape, and is what the dashboard shows until the XGBoost model lands. It is a
reference implementation, not a claim of accuracy, and always sets `is_fallback: true`.

## 7. Verifying

```bash
./deployment/scripts/run_tests.sh tests/ml backend/tests           # contract + fallback + schema tests
python3 ai/feature_engineering/validate_feature_schema.py            # standalone validator
python3 ai/feature_engineering/build_feature_schema_contract.py      # regenerate the JSON
```
