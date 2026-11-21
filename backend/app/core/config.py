from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Attack Surface Intelligence (AGH)"
    api_v1_prefix: str = "/api/v1"

    database_url: str = "postgresql+psycopg://asi_user:changeme_strong_db_password@postgres:5432/asi_db"
    redis_url: str = "redis://:changeme_strong_redis_password@redis:6379/0"
    redis_job_queue: str = "asi:scan:chunks"

    # Base64-encoded 32-byte AES-256 key
    encryption_master_key: str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    allow_weak_encryption_key: bool = False
    allow_dev_role_header: bool = True
    scanner_internal_token: str = "changeme_internal_scanner_token"

    jwt_secret_key: str = "changeme_generate_random_jwt_secret_min_32_chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480


settings = Settings()
