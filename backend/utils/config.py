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
    # Post-fix validation: fix attempts per validation (default 3, hard cap 5). The loop
    # also stops early when an attempt makes no progress; see GET /api/validation-stats
    # for per-attempt success rates before raising this.
    FIX_ATTEMPTS_CAP: int = 5
    FIX_MAX_ATTEMPTS: int = min(max(int(os.getenv("FIX_MAX_ATTEMPTS", "3")), 1), 5)
    # Opt-in: project test command run in the sandbox copy (e.g. "python -m pytest -q").
    # Off by default because it executes the scanned repository's code on this host.
    VALIDATION_TEST_COMMAND: str = os.getenv("VALIDATION_TEST_COMMAND", "")
    VALIDATION_TEST_TIMEOUT: int = int(os.getenv("VALIDATION_TEST_TIMEOUT", "300"))
    VALIDATION_KEEP_WORKSPACE: bool = os.getenv("VALIDATION_KEEP_WORKSPACE", "").lower() in ("1", "true", "yes")

    def __init__(self) -> None:
        self.TEMP_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
