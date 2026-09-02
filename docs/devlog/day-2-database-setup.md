# Day 2 - Local PostgreSQL and migrations

## What is included

- PostgreSQL 16 in `docker-compose.yml`, stored in the named `postgres_data` volume.
- SQLAlchemy models for all 13 v1 tables.
- A single initial Alembic revision: `20260829_0001`.
- Required query indexes and database-level checks for risk/confidence values and time ranges.

## First-time setup

The commands below use the Docker Desktop convention, `docker compose`. On this development machine the Homebrew/Colima setup exposes the equivalent command as `docker-compose`; substitute it consistently if `docker compose version` is unavailable.

From the repository root:

```bash
docker compose up -d db
docker compose ps
```

Wait for the `db` service to report `healthy`. Then, from `backend/`:

```bash
cp .env.example .env
.venv/bin/alembic upgrade head
.venv/bin/alembic current
```

The migration must be used for every shared database. Do not call `Base.metadata.create_all()` from application code.

## Useful commands

```bash
# Database logs and a shell
docker compose logs -f db
docker compose exec db psql -U what_the_hack -d what_the_hack

# Migration lifecycle
cd backend
.venv/bin/alembic history
.venv/bin/alembic current
.venv/bin/alembic upgrade head
.venv/bin/alembic downgrade -1
```

## Collaboration rules

1. Never edit `20260829_0001_initial_schema.py` after it reaches a shared database.
2. Every later schema change gets a new Alembic revision and is reviewed with its matching model change.
3. Run `alembic upgrade head` after pulling database changes.
4. Never use `docker compose down -v` against any database that contains data the team needs.
