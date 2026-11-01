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

    # LLM A: reads the redacted report+snapshot, writes LLM B's prompt and the
    # testbench. Default: Groq's free tier (OpenAI-compatible).
    llm_a_endpoint: str = Field(default="https://api.groq.com/openai/v1/chat/completions", alias="LLM_A_ENDPOINT")
    llm_a_api_key: str = Field(default="", alias="LLM_A_API_KEY")
    llm_a_model: str = Field(default="llama-3.3-70b-versatile", alias="LLM_A_MODEL")
    # LLM B: a different model from A, writes the fixed code. Default:
    # OpenRouter's free tier, a coder-tuned model (OpenAI-compatible).
    llm_b_endpoint: str = Field(default="https://openrouter.ai/api/v1/chat/completions", alias="LLM_B_ENDPOINT")
    llm_b_api_key: str = Field(default="", alias="LLM_B_API_KEY")
    llm_b_model: str = Field(default="qwen/qwen-2.5-coder-32b-instruct:free", alias="LLM_B_MODEL")

    # "live": always call out. "record": call out and save the response.
    # "replay": never call out, read from the cache, error clearly on a miss.
    llm_cache_mode: str = Field(default="live", alias="LLM_CACHE_MODE")
    llm_cache_dir: str = Field(default="/tmp/llm_cache", alias="LLM_CACHE_DIR")

    # "fake": FakeSandboxRunner (canned results, no real execution). "real":
    # RealSandboxRunner (HTTP to sandbox_manager) - not yet functional until
    # sandbox_manager's owner adds a matching run kind. Switching is this one
    # flag, never a code change.
    sandbox_runner_kind: str = Field(default="fake", alias="SANDBOX_RUNNER_KIND")

    batch_size: int = Field(default=8, alias="BATCH_SIZE")
    llm_concurrency: int = Field(default=4, alias="LLM_CONCURRENCY")
    # Patch attempts per batch: 1 initial patch + 2 corrections. The database
    # refuses more than the run's recorded limit (and never more than 10).
    max_rounds: int = Field(default=3, ge=1, le=10, alias="MAX_ROUNDS")
    stagnation_rounds: int = Field(default=2, alias="STAGNATION_ROUNDS")
    remediation_token_budget: int = Field(default=8000, alias="REMEDIATION_TOKEN_BUDGET")

    # Private artifact store for remediation records too large or too
    # sensitive for database rows (redacted context, model input/output,
    # patches, testbenches, sandbox logs). Shared by api and worker-remediate.
    artifacts_dir: str = Field(default="/data/artifacts", alias="ARTIFACTS_DIR")
    remediation_artifact_retention_days: int = Field(default=30, ge=1, alias="REMEDIATION_ARTIFACT_RETENTION_DAYS")
    # Model prompts/responses are kept only when this is on (default): they
    # are needed to reproduce and audit a run, and contain redacted code only.
    remediation_retain_model_io: bool = Field(default=True, alias="REMEDIATION_RETAIN_MODEL_IO")
    # A worker holds a lease on the run it advances; a run whose lease
    # expired (crashed worker) is resumed at most this many times.
    remediation_lease_seconds: int = Field(default=900, ge=60, alias="REMEDIATION_LEASE_SECONDS")
    remediation_max_recoveries: int = Field(default=2, ge=0, alias="REMEDIATION_MAX_RECOVERIES")

    @property
    def origins(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def dev_hosts(self) -> frozenset[str]:
        return frozenset(h.strip().lower() for h in self.dev_allow_hosts.split(",") if h.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
