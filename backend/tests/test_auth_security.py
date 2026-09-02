from app.core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from app.schemas.auth import LoginRequest


def test_login_request_normalizes_email() -> None:
    assert LoginRequest(email="  ADMIN@WHAT-THE-HACK.LOCAL ", password="password1").email == "admin@what-the-hack.local"


def test_password_hash_is_verified() -> None:
    assert verify_password("password1", hash_password("password1"))


def test_tokens_are_typed_and_decode() -> None:
    access_token, _, _ = create_access_token(subject="11111111-1111-1111-1111-111111111111", role="viewer")
    refresh_token, _, _ = create_refresh_token(subject="11111111-1111-1111-1111-111111111111", role="viewer")
    assert decode_token(access_token)["type"] == "access"
    assert decode_token(refresh_token)["type"] == "refresh"


def test_access_token_is_linked_to_its_refresh_token() -> None:
    subject = "11111111-1111-1111-1111-111111111111"
    _, refresh_id, _ = create_refresh_token(subject=subject, role="analyst")
    access_token, _, _ = create_access_token(subject=subject, role="analyst", refresh_token_id=refresh_id)
    assert decode_token(access_token)["refresh_jti"] == refresh_id


def test_access_token_without_pair_has_no_refresh_claim() -> None:
    access_token, _, _ = create_access_token(subject="11111111-1111-1111-1111-111111111111", role="viewer")
    assert "refresh_jti" not in decode_token(access_token)
