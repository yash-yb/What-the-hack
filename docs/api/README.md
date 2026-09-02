# docs/api

- `api-contracts.md` — REST endpoints, roles, dashboard/alert response shapes, and the
  internal ML inference adapter contract.
- `feature_schema_contract.json` — **Deliverable R3 (not yet committed).** Draft-07 JSON
  Schema with `RawFlow`, `TrafficWindow`, `WindowFeatures`, `InferenceRequest`,
  `InferenceResponse`, the 85-column CICIDS2017 mapping, and windowing parameters.
  `tests/ml/` and `ai/feature_engineering/validate_feature_schema.py` expect it at this path.
