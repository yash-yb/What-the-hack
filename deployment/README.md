# deployment/

| Folder | Purpose |
| --- | --- |
| `docker/` | Notes on the service images. The Dockerfiles themselves live next to the code they build (`backend/Dockerfile`, `frontend/Dockerfile`) so their build context stays small. |
| `compose/` | Compose override files (for example a `docker-compose.prod.yml`). The default `docker-compose.yml` is at the repository root. |
| `scripts/` | Helper scripts for local bootstrap, testing, and demo resets. |

## One-command demo stack

```bash
cp .env.example .env          # edit JWT_SECRET_KEY
docker compose up --build
```

Services: `db` (PostgreSQL 16), `backend` (FastAPI on :8000), `frontend` (Next.js on :3000).
