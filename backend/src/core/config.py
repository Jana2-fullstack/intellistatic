from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    app_name: str = "IntelliStatic"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"
    database_url: str = f"sqlite:///{PROJECT_ROOT / 'intellistatic.db'}"
    model_dir: Path = PROJECT_ROOT / "ml_training" / "models"
    binary_model_file: str = "lgbm_binary.txt"
    multiclass_model_file: str = "lgbm_multiclass.txt"
    scaler_file: str = "scaler.pkl"
    max_upload_mb: int = Field(default=100, ge=1)
    allowed_extensions: str = ".exe,.dll,.sys,.bin"
    yara_rules_dir: Path = PROJECT_ROOT / "yara_rules"
    cors_origins: str = "http://localhost:8501,http://localhost:3000"
    api_key: str | None = None
    shap_enabled: bool = True

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=("settings_",),
    )

    @property
    def extension_allowlist(self) -> set[str]:
        return {ext.strip().lower() for ext in self.allowed_extensions.split(",") if ext.strip()}

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def normalized_database_url(self) -> str:
        if self.database_url.startswith("postgresql://"):
            return self.database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return self.database_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
