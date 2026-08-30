import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import bearer_scheme, credentials_exception, get_current_user, get_user_role, require_admin, require_viewer
from app.core.security import create_access_token, create_refresh_token, decode_token, verify_password
from app.db.session import get_db
from app.models.network import AuditLog, RevokedToken, Role, User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth")


def user_response(user: User, role: str) -> UserResponse:
    return UserResponse(id=str(user.id), email=user.email, display_name=user.display_name, role=role)


def issue_tokens(user: User, role: str) -> TokenResponse:
    access_token, _, access_expires_at = create_access_token(subject=str(user.id), role=role)
    refresh_token, _, _ = create_refresh_token(subject=str(user.id), role=role)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, expires_at=access_expires_at, user=user_response(user, role))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    role = get_user_role(user, db).value
    user.last_login_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_user_id=user.id, action="auth.login", resource_type="user", resource_id=user.id))
    db.commit()
    return issue_tokens(user, role)


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        claims = decode_token(payload.refresh_token)
        if claims.get("type") != "refresh":
            raise ValueError("Not a refresh token")
        user_id, token_id = uuid.UUID(claims["sub"]), uuid.UUID(claims["jti"])
        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    except (KeyError, ValueError, TypeError):
        raise credentials_exception() from None

    if db.scalar(select(RevokedToken).where(RevokedToken.token_id == token_id)) is not None:
        raise credentials_exception()
    user = db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active:
        raise credentials_exception()
    db.add(RevokedToken(token_id=token_id, expires_at=expires_at))
    db.add(AuditLog(actor_user_id=user.id, action="auth.refresh", resource_type="user", resource_id=user.id))
    db.commit()
    return issue_tokens(user, get_user_role(user, db).value)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    if credentials is None:
        raise credentials_exception()
    try:
        claims = decode_token(credentials.credentials)
        token_id = uuid.UUID(claims["jti"])
        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    except (KeyError, ValueError, TypeError):
        raise credentials_exception() from None
    db.add(RevokedToken(token_id=token_id, expires_at=expires_at))
    db.add(AuditLog(actor_user_id=user.id, action="auth.logout", resource_type="user", resource_id=user.id))
    db.commit()
    return response


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(require_viewer), db: Session = Depends(get_db)) -> UserResponse:
    return user_response(user, get_user_role(user, db).value)


@router.get("/admin-check", response_model=UserResponse)
def admin_check(user: User = Depends(require_admin), db: Session = Depends(get_db)) -> UserResponse:
    return user_response(user, get_user_role(user, db).value)
