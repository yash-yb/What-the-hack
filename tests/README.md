# tests/

| Folder | Contents | How to run |
| --- | --- | --- |
| `ml/` | Contract, invariant, and adversarial tests for the ML deliverables. | `pytest tests/ml` |
| `backend/` | API-level tests that exercise the backend over HTTP. Pure unit tests stay in `backend/tests/`. | `pytest tests/backend` |
| `integration/` | End-to-end flows: upload → windows → forecast → alert → acknowledge. | `pytest tests/integration` |
| `frontend/` | Frontend component and page tests. | `cd frontend && npm test` |

From the repository root, `pytest` picks up both `tests/` and `backend/tests/`
(configured in `pyproject.toml`).
