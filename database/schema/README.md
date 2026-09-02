# database/schema

Plain-SQL snapshots of the schema, for judges or reviewers who want to read the DDL without
running Alembic. Regenerate after a migration with:

```bash
docker compose exec db pg_dump -U what_the_hack -d what_the_hack --schema-only > database/schema/schema.sql
```
