# ai/ — machine learning workspace

Owner: AI/ML engineer (Yash). Everything here is offline tooling; the backend calls the
inference module through the adapter contract in `docs/api/api-contracts.md`.

| Folder | Purpose | Status |
| --- | --- | --- |
| `datasets/` | Dataset download, checksum verification, synthetic generator, CICIDS2017 → `raw_flows` mapping (`download_cicids2017.py`). | Done (Day 1) |
| `preprocessing/` | Cleaning, label mapping, time sorting, train/validation/test split with the purge embargo. | Planned |
| `feature_engineering/` | Contract generator (`build_feature_schema_contract.py`), schema validator (`validate_feature_schema.py`); window feature calculators to come. | Contract done |
| `training/` | Training scripts for the XGBoost/LightGBM baseline and the Random Forest comparison. | Planned |
| `evaluation/` | Metrics reports: precision/recall/F1, ROC-AUC, PR-AUC, confusion matrix, lead time. | Planned |
| `inference/` | `forecast()` entry point, contract source of truth (`contract.py`), rule-based fallback (`fallback.py`). The trained model plugs in here. | Fallback done |
| `models/` | Trained artifacts and their metadata. Binary artifacts are git-ignored; commit only small metadata JSON. | Empty |
| `notebooks/` | Exploration notebooks. Keep outputs stripped before committing. | Empty |

## Forecasting rule

Every model here must be trained with future-shifted labels: features from window `t`
predict whether an attack starts or escalates in `(t, t + horizon]`. A model that labels the
current window is detection, not forecasting, and does not belong in `training/`.
See `docs/research/forecasting_formulation.md`.

## Running the dataset tool

```bash
python3 ai/datasets/download_cicids2017.py --help
python3 ai/datasets/download_cicids2017.py --offline-mock --out-dir ./ai/datasets/data
```

Raw downloads go under `ai/datasets/data/` (git-ignored).
