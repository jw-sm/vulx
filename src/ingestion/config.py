from dotenv import load_dotenv

load_dotenv()

import os
from pathlib import Path


class Config:
    """Configuration for CVE ingestion parser"""

    # ==================================
    # Database settings
    # ==================================
    DB_NAME = os.getenv("CVE_DB_NAME", "vulx")
    DB_USER = os.getenv("CVE_DB_USER")
    DB_PASSWORD = os.getenv("CVE_DB_PASSWORD")
    DB_HOST = os.getenv("CVE_DB_HOST", "localhost")
    DB_PORT = os.getenv("CVE_DB_PORT", "5432")

    # CVE data repository path
    CVE_REPO_PATH = os.getenv(
        "CVE_REPO_PATH", str(Path.cwd().parent / "cvelistV5" / "cves")
    )

    @classmethod
    def get_db_connection_string(cls):
        return (
            f"dbname={cls.DB_NAME} "
            f"user={cls.DB_USER} "
            f"password={cls.DB_PASSWORD} "
            f"host={cls.DB_HOST} "
            f"port={cls.DB_PORT}"
        )

    @classmethod
    def validate(cls):
        """Check that the required configs are present"""

        errors = []

        if not cls.DB_PASSWORD:
            errors.append("DB_PASSWORD is not set")

        if not Path(cls.CVE_REPO_PATH).exists():
            errors.append(f"Repository path does not exist: {cls.CVE_REPO_PATH}")

        if errors:
            raise ValueError(
                "Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
            )


if __name__ == "__main__":
    print(Config.get_db_connection_string())
