"""
HTTP-level test harness: the real FastAPI app on an in-memory SQLite database.

The models use portable types (Uuid, JSON with a JSONB variant), so `create_all` works on
SQLite; PostgreSQL-only behaviour still needs the Alembic migrations against a real database.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 - register tables
from app.api.v1.routes import auth as auth_routes
from app.api.v1.routes import ingestion as ingestion_routes
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app as fastapi_app
from app.models.network import Role, RoleName, User

SAMPLE_CSV = Path(__file__).resolve().parents[2] / "sample_data" / "sample_flows_mini.csv"

DEMO_PASSWORDS = {
    "admin@what-the-hack.local": "AdminPass123!",
    "analyst@what-the-hack.local": "AnalystPass123!",
    "viewer@what-the-hack.local": "ViewerPass123!",
}


@pytest.fixture()
def engine():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def session_factory(engine):
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


@pytest.fixture()
def seeded_users(session_factory) -> dict[str, str]:
    with session_factory() as db:
        roles = {}
        for name in RoleName:
            role = Role(name=name, description=name.value)
            db.add(role)
            db.flush()
            roles[name] = role
        for email, password in DEMO_PASSWORDS.items():
            role_name = RoleName(email.split("@")[0])
            db.add(User(role_id=roles[role_name].id, email=email, password_hash=hash_password(password), display_name=email))
        db.commit()
    return DEMO_PASSWORDS


@pytest.fixture()
def client(session_factory, monkeypatch) -> Iterator[TestClient]:
    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    fastapi_app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.services.windows.SessionLocal", session_factory)
    auth_routes.login_limiter.reset()
    ingestion_routes.upload_limiter.reset()
    with TestClient(fastapi_app) as test_client:
        yield test_client
    fastapi_app.dependency_overrides.clear()


def login(client: TestClient, email: str, password: str) -> dict:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
