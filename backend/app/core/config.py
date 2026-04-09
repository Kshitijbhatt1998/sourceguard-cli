from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ENV: str = "dev"
    DATABASE_URL: str
    API_KEY_HEADER: str = "x-api-key"
    RATE_LIMIT: str = "10/minute"
    SECRET_KEY: str
    GITHUB_WEBHOOK_SECRET: str = ""

    class Config:
        env_file = ".env"

    @property
    def is_prod(self) -> bool:
        return self.ENV == "prod"

settings = Settings()

# Validation for production safety
if settings.is_prod and "sqlite" in settings.DATABASE_URL:
    raise ValueError("CRITICAL: Production must use a robust database like PostgreSQL, not SQLite.")
