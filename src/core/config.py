"""
Provide the configuration for the API
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyUrl, computed_field
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
    #===============================
    # cors related settings
    #==============================
    _backend_cors_origin: Annotated[
        list[AnyUrl] | str, BeforeValidator(parse_cors)
    ] = []

    @computed_field
    @property
    def all_cors_origins(self) -> list[str]:
        return [
            str(origin).rstrip("/") for origin in self._backend_cors_origin
        ] #FRONT END HOST can be added here

    PROJECT_NAME: str

settings = Settings()

if __name__ == "__main__":
    # sanity checks
    print("BASE_DIR:", BASE_DIR)
    print("ENV FILE EXIST:", (BASE_DIR / ".env").exists())
