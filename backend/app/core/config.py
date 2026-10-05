from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    VT_API_KEY: str = ""
    API_URL: str = "https://www.virustotal.com/api/v3"
    ALLOWED_ORIGINS: Union[str, List[str]] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    MIN_FILE_SIZE: int = 512  # 512 bytes
    MAX_FILE_SIZE: int = 32 * 1024 * 1024  # 32 MB
    DEFAULT_POLL_INTERVAL_SECONDS: int = 15

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


settings = Settings()
