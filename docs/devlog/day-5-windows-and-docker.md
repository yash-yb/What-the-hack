# Day 5 — Traffic windows and Docker

## What Day 5 adds

Raw CSV rows are grouped into fixed 60-second windows after a successful upload. Each window contains the number of distinct network flows (source IP, destination IP, source port, destination port, and protocol), total packets, and total bytes. The manual `POST /api/v1/windows/build` endpoint can also rebuild a source; it updates existing windows rather than duplicating them.

## Run the backend with Docker

From the repository root:

```bash
JWT_SECRET_KEY='replace-with-a-long-random-secret' docker compose up --build
```

Docker starts PostgreSQL as `db` and the backend as `backend`. The backend's database host is `db`, not `localhost`: `localhost` inside a container points back to that same container.

Check both services:

```bash
docker compose ps
curl http://localhost:8000/api/v1/health
```

The interactive API page is at `http://localhost:8000/docs`.

## Verify the window builder

Log in as the seeded admin, upload the sample CSV as documented in `docs/devlog/day-4-ingestion.md`, then call `POST /api/v1/windows/build` with the upload response's `traffic_source_id`. Use `GET /api/v1/windows?traffic_source_id=<id>` to see the minute-by-minute summaries.
