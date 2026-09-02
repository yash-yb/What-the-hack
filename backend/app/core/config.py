from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_JWT_SECRET = "development-only-change-me-use-env-secret"
MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    app_name: str = "What the Hack API"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql+psycopg://what_the_hack:what_the_hack@localhost:5432/what_the_hack"
    jwt_secret_key: str = DEFAULT_JWT_SECRET
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    traffic_window_seconds: int = 60
    frontend_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    max_upload_size_mb: int = 50
    rate_limit_enabled: bool = True
    login_rate_limit_per_minute: int = 10
    upload_rate_limit_per_minute: int = 10

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def is_development(self) -> bool:
        return self.environment.lower() in {"development", "dev", "local", "test"}

    @property
    def uses_default_jwt_secret(self) -> bool:
        return self.jwt_secret_key == DEFAULT_JWT_SECRET

    @model_validator(mode="after")
    def refuse_weak_secret_outside_development(self) -> "Settings":
        if not self.is_development and (self.uses_default_jwt_secret or len(self.jwt_secret_key) < MIN_JWT_SECRET_LENGTH):
            raise ValueError(
                f"JWT_SECRET_KEY must be a random value of at least {MIN_JWT_SECRET_LENGTH} characters when "
                f"ENVIRONMENT is '{self.environment}'. Generate one with: python3 -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
