# database/migrations

Migrations are managed by Alembic in `backend/alembic/`. Rules:

1. Never edit a revision after it has reached a shared database.
2. Every schema change is a new revision reviewed with its model change.
3. Run `alembic upgrade head` after pulling database changes.

See `docs/devlog/day-2-database-setup.md`.
