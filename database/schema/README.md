# database/schema

`schema.sql` is the PostgreSQL DDL for all 13 tables, generated from the SQLAlchemy models
so judges and reviewers can read it without running Alembic. Regenerate after any model
change:

```bash
cd backend && PYTHONPATH=. .venv/bin/python ../database/schema/export_schema.py
```

Schema changes themselves always go through an Alembic revision; this file is a snapshot.
