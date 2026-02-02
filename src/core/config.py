from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_ignore_empty=True,
        extra="ignore",
    )
    PROJECT_NAME: str


settings = Settings()


if __name__ == "__main__":
    print("BASE_DIR:", BASE_DIR)
    print("ENV FILE EXIST:", (BASE_DIR / ".env").exists())
