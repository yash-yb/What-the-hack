"""Seed idempotent local-demo accounts after running `alembic upgrade head`."""

from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.network import Role, RoleName, User

DEMO_USERS = (
    (RoleName.ADMIN, "admin@what-the-hack.local", "AdminPass123!", "Demo Admin"),
    (RoleName.ANALYST, "analyst@what-the-hack.local", "AnalystPass123!", "Demo Analyst"),
    (RoleName.VIEWER, "viewer@what-the-hack.local", "ViewerPass123!", "Demo Viewer"),
)


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
        for role_name, email, password, display_name in DEMO_USERS:
            if db.scalar(select(User).where(User.email == email)) is None:
                db.add(User(role_id=roles[role_name].id, email=email, password_hash=hash_password(password), display_name=display_name))
        db.commit()
    print("Demo users are ready.")


if __name__ == "__main__":
    main()
