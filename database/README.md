# database/

PostgreSQL is the system of record. The authoritative artifacts are:

| What | Where | Why it lives there |
| --- | --- | --- |
| Schema design (ERD, tables, indexes) | `docs/architecture/database-schema.md` | Documentation |
| SQLAlchemy models | `backend/app/models/` | The backend owns the ORM |
| Alembic migrations | `backend/alembic/versions/` | Migrations import the backend models |
| Seed script (demo users) | `backend/scripts/seed_demo_users.py` | Uses the backend session and password hashing |

The `schema/`, `seed/`, and `migrations/` folders here hold plain-SQL exports, extra seed
fixtures, and notes that do not depend on the backend package. Do not duplicate the Alembic
migrations here.
