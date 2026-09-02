# Day 4 — CSV ingestion verification

## Run locally

From the repository root, make sure PostgreSQL is running, then prepare the backend:

```bash
docker compose up -d db
cd backend
cp .env.example .env
.venv/bin/alembic upgrade head
PYTHONPATH=. .venv/bin/python scripts/seed_demo_users.py
PYTHONPATH=. .venv/bin/uvicorn app.main:app --reload
```

In another terminal, log in with the seeded admin account and copy the returned `access_token`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  --data '{"email":"admin@what-the-hack.local","password":"AdminPass123!"}'
```

Use that token to upload the provided sample CSV. The response is the ingestion job; save its `id`.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingestion/upload \
  -H 'Authorization: Bearer <access_token>' \
  -F 'source_name=local-demo' \
  -F 'file=@sample_data/sample_flows_mini.csv;type=text/csv'
```

Check the persisted job with:

```bash
curl http://127.0.0.1:8000/api/v1/ingestion/<job_id>/status \
  -H 'Authorization: Bearer <access_token>'
```

Expected result for `sample_flows_mini.csv`: `status` is `completed`, `total_rows` and `accepted_rows` are `120`, and `skipped_rows` is `0`.

Use `http://127.0.0.1:8000/docs` to exercise the same endpoints interactively.
