"""
Seed idempotent local-demo accounts after running `alembic upgrade head`.

Passwords come from DEMO_ADMIN_PASSWORD, DEMO_ANALYST_PASSWORD, and DEMO_VIEWER_PASSWORD.
The built-in defaults are only accepted when ENVIRONMENT is development; anywhere else the
script refuses to run until all three variables are set.
"""

import os
import sys

from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.network import Role, RoleName, User

DEMO_USERS = (
    (RoleName.ADMIN, "admin@what-the-hack.local", "DEMO_ADMIN_PASSWORD", "AdminPass123!", "Demo Admin"),
    (RoleName.ANALYST, "analyst@what-the-hack.local", "DEMO_ANALYST_PASSWORD", "AnalystPass123!", "Demo Analyst"),
    (RoleName.VIEWER, "viewer@what-the-hack.local", "DEMO_VIEWER_PASSWORD", "ViewerPass123!", "Demo Viewer"),
)


def resolve_password(env_name: str, default: str) -> str:
    value = os.environ.get(env_name)
    if value:
        return value
    if settings.is_development:
        return default
    print(f"Refusing to seed the built-in demo password: set {env_name} (ENVIRONMENT={settings.environment}).", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    with SessionLocal() as db:
        roles: dict[RoleName, Role] = {}
        for name in RoleName:
            role = db.scalar(select(Role).where(Role.name == name))
            if role is None:
                role = Role(name=name, description=f"{name.value.title()} role")
                db.add(role)
                db.flush()
            roles[name] = role
        created = 0
        for role_name, email, env_name, default, display_name in DEMO_USERS:
            if db.scalar(select(User).where(User.email == email)) is None:
                password = resolve_password(env_name, default)
                db.add(User(role_id=roles[role_name].id, email=email, password_hash=hash_password(password), display_name=display_name))
                created += 1
        db.commit()
    print(f"Demo users are ready ({created} created).")
    if settings.is_development and not any(os.environ.get(u[2]) for u in DEMO_USERS):
        print("Using the built-in demo passwords. Change them before any shared deployment.")


if __name__ == "__main__":
    main()
