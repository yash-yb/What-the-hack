# Alembic migrations

Day 2 initializes Alembic against PostgreSQL and adds the first schema migration. Keep every database change in a migration; do not rely on `create_all()` for shared environments.

