from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    environment: str = Field(default="development", alias="ROUTES_ENV")
    database_url: str = Field(alias="DATABASE_URL")
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")

    session_ttl_hours: int = Field(default=72, alias="SESSION_TTL_HOURS")
    cookie_secure: bool = Field(default=False, alias="COOKIE_SECURE")
    allowed_origins: str = Field(default="http://localhost:3000", alias="ALLOWED_ORIGINS")

    sandbox_manager_url: str = Field(default="http://sandbox-manager:8100", alias="SANDBOX_MANAGER_URL")
    sandbox_manager_token: str = Field(default="", alias="SANDBOX_MANAGER_TOKEN")

    uploads_dir: str = Field(default="/data/uploads", alias="UPLOADS_DIR")
    max_upload_bytes: int = Field(default=100 * 1024 * 1024, alias="MAX_UPLOAD_BYTES")

    # Development-only: hostnames allowed even though they resolve privately
    # (used for the bundled sample site). Must stay empty for real use.
    dev_allow_hosts: str = Field(default="", alias="GATEWAY_DEV_ALLOW_HOSTS")

    assessment_history_limit: int = Field(default=5, alias="ASSESSMENT_HISTORY_LIMIT")
    login_rate_limit: int = Field(default=10, alias="LOGIN_RATE_LIMIT_PER_15MIN")

    local_llm_endpoint: str = Field(default="http://ollama:11434", alias="LOCAL_LLM_ENDPOINT")
    local_llm_model: str = Field(default="mistral-nemo", alias="LOCAL_LLM_MODEL")
    big_llm_endpoint: str = Field(default="", alias="BIG_LLM_ENDPOINT")
    big_llm_api_key: str = Field(default="", alias="BIG_LLM_API_KEY")
    big_llm_model: str = Field(default="", alias="BIG_LLM_MODEL")
    max_remediation_iters: int = Field(default=3, alias="MAX_ITERS")
    remediation_token_budget: int = Field(default=8000, alias="REMEDIATION_TOKEN_BUDGET")

    @property
    def origins(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def dev_hosts(self) -> frozenset[str]:
        return frozenset(h.strip().lower() for h in self.dev_allow_hosts.split(",") if h.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
