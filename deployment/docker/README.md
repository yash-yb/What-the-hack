# Service images

| Service | Dockerfile | Base | Notes |
| --- | --- | --- | --- |
| backend | `backend/Dockerfile` | `python:3.10-slim` | Runs `alembic upgrade head` then uvicorn (command set in `docker-compose.yml`). |
| frontend | `frontend/Dockerfile` | `node:20-alpine` | Builds the Next.js app and serves it with `npm start`. |
| db | `postgres:16-alpine` | — | Data persisted in the `postgres_data` volume. |
