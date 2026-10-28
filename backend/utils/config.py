import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Settings:
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    # resolve() so Windows gets a drive-qualified path; git rejects "\tmp\..."
    TEMP_DIR: Path = Path(os.getenv("TEMP_DIR", "/tmp/security_scans")).resolve()
    # Finished scans are persisted here so results survive restarts
    DB_PATH: Path = Path(
        os.getenv("DB_PATH", Path(__file__).resolve().parent.parent / "data" / "scans.db")
    ).resolve()
    MAX_REPO_SIZE_MB: int = int(os.getenv("MAX_REPO_SIZE_MB", "500"))
    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "600"))

    def __init__(self) -> None:
        self.TEMP_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
