from pydantic_settings import BaseSettings, SettingsConfigDict, AnyUrl
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent

def _parse_multiformat_cors(v: Any) -> list[str] | str:
    if isinstance(v, str) and v.startswith("["):
        return [i.strip() for i in v.split(",")]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_ignore_empty=True,
        extra="ignore",
    )
    
    _backend_cors_origin: Annotated[list[AnyUrl] | str, BeforeValidator(parse_cors)] = []

    PROJECT_NAME: str


settings = Settings()


if __name__ == "__main__":
    print("BASE_DIR:", BASE_DIR)
    print("ENV FILE EXIST:", (BASE_DIR / ".env").exists())
