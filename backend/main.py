import asyncio
import logging
import shutil
import subprocess
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from routers.chains import router as chains_router
from routers.scan import router as scan_router
from services import validation_history

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Connect now, so attempts a previous process left RUNNING are marked ERROR before new ones start.
    # Without MongoDB the scanner still works; fix validation answers 503 with setup instructions.
    try:
        await asyncio.to_thread(validation_history.connect)
    except validation_history.HistoryUnavailable as e:
        logging.getLogger(__name__).error("Fix validation is unavailable: %s", e)
    yield


app = FastAPI(
    title="AI Security Scanner",
    description="Automated security analysis with AI-enhanced vulnerability reports",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter


@app.exception_handler(validation_history.HistoryUnavailable)
async def history_unavailable(_: Request, exc: validation_history.HistoryUnavailable) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(chains_router)


@app.get("/health")
async def health_check() -> dict[str, object]:
    semgrep_path = shutil.which("semgrep")

    # Get semgrep version
    version = "unknown"
    version_err = ""
    try:
        proc = await asyncio.to_thread(
            subprocess.run, ["semgrep", "--version"], capture_output=True
        )
        version = proc.stdout.decode().strip() or proc.stderr.decode().strip()
        if proc.returncode != 0:
            version_err = f"rc={proc.returncode}"
    except Exception as e:
        version_err = str(e)

    return {
        "status": "healthy",
        "semgrep_installed": semgrep_path is not None,
        "semgrep_path": semgrep_path or "not found",
        "semgrep_version": version,
        "semgrep_version_error": version_err,
    }
