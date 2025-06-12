import os
from pydantic_settings import BaseSettings, SettingsConfigDict

# ─── Point to your .env file next to this module ───────────────────────
DOTENV_PATH = os.path.join(os.path.dirname(__file__), ".env")

class Settings(BaseSettings):
    # --- Server ---
    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8000

    # --- Redis ---
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_USERNAME: str
    REDIS_PASSWORD: str

    # --- SMTP (Gmail App-Password) ---
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASS: str
    EMAIL_FROM: str

    # --- App / JWT ---
    BASE_URL: str
    JWT_SECRET: str
    TOKEN_TTL: int
    ACCESS_TTL: int

    # --- Password reset ---
    PASSWORD_RESET_SECRET: str
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int

    # Tell Pydantic to load from that file
    model_config = SettingsConfigDict(env_file=DOTENV_PATH)

# Instantiate your settings once and for all
settings = Settings()
