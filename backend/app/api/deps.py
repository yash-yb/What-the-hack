import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db.session import get_db
from app.models.network import RevokedToken, Role, RoleName, User

bearer_scheme = HTTPBearer(auto_error=False)


def credentials_exception() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme), db: Session = Depends(get_db)
) -> User:
    if credentials is None:
        raise credentials_exception()
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise ValueError("Not an access token")
        user_id = uuid.UUID(payload["sub"])
        token_id = uuid.UUID(payload["jti"])
    except (KeyError, ValueError):
        raise credentials_exception() from None

    revoked = db.scalar(select(RevokedToken).where(RevokedToken.token_id == token_id, RevokedToken.expires_at > datetime.now(timezone.utc)))
    if revoked is not None:
        raise credentials_exception()

    user = db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active:
        raise credentials_exception()
    return user


def get_user_role(user: User, db: Session) -> RoleName:
    role = db.scalar(select(Role.name).where(Role.id == user.role_id))
    if role is None:
        raise credentials_exception()
    return role


def require_roles(*allowed_roles: RoleName) -> Callable:
    def dependency(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if get_user_role(user, db) not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


require_admin = require_roles(RoleName.ADMIN)
require_analyst = require_roles(RoleName.ADMIN, RoleName.ANALYST)
require_viewer = require_roles(RoleName.ADMIN, RoleName.ANALYST, RoleName.VIEWER)
