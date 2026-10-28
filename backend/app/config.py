from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # These defaults are for local development only. Configure secrets and paths in the
    # repository-root .env file (see .env.example) before sharing or deploying an instance.
    database_url: str = "sqlite:///./chainofcustody.db"
    storage_dir: Path = Path("./storage")
    max_upload_bytes: int = 50 * 1024 * 1024
    jwt_secret: str = "development-only-change-me"
    jwt_expire_minutes: int = 480
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "change-this-before-deployment"
    frontend_origin: str = "http://localhost:5173"
    blockchain_rpc_url: str = "http://127.0.0.1:8545"
    fingerprint_reveal_code: str = ""
    model_config = SettingsConfigDict(env_file="../.env", extra="ignore")


settings = Settings()
