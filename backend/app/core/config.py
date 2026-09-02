from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "What the Hack API"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql+psycopg://what_the_hack:what_the_hack@localhost:5432/what_the_hack"
    jwt_secret_key: str = "development-only-change-me-use-env-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    traffic_window_seconds: int = 60
    frontend_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    max_upload_size_mb: int = 50

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
