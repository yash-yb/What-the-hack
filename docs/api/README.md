# docs/api

- `api-contracts.md` — REST endpoints, roles, dashboard/alert response shapes.
- `ml-inference-contract.md` — the ML <-> backend contract in plain language: feature
  list, types and units, missing-data rules, horizon, output format, how to call, failure
  behaviour.
- `feature_schema_contract.json` — Deliverable R3. Draft-07 JSON Schema generated from
  `ai/inference/contract.py` by `ai/feature_engineering/build_feature_schema_contract.py`.
  Do not edit by hand; regenerate and commit.
