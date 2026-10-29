"""Runtime-error checker as a web page: one Python process, no Docker, no job queue.

    GET  /            the results page (static/index.html)
    POST /api/check   {"repo_url": "https://github.com/owner/repo"} -> report (see checker.check)
    GET  /health

A check clones the repository (depth 1) into a temporary folder, reads it with
checker.py and deletes it again, all inside the request: nothing keeps running in
the background between requests. The scanned code is never executed.

Settings (environment):  HOST (127.0.0.1), PORT (8100), RUNTIME_MAX_REPO_MB (200),
RUNTIME_MAX_CONCURRENT (2), RUNTIME_TEMP_DIR (system temp), RUNTIME_ALLOW_ORIGIN (unset: same origin only)

Usage:  python server.py      then open http://127.0.0.1:8100
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import checker

logger = logging.getLogger("runtime")

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8100"))
MAX_REPO_MB = int(os.getenv("RUNTIME_MAX_REPO_MB", "200"))
MAX_CONCURRENT = max(int(os.getenv("RUNTIME_MAX_CONCURRENT", "2")), 1)
TEMP_DIR = os.getenv("RUNTIME_TEMP_DIR") or None
ALLOW_ORIGIN = os.getenv("RUNTIME_ALLOW_ORIGIN", "")
CLONE_TIMEOUT_SECONDS = 120
MAX_BODY_BYTES = 10_000
STATIC = Path(__file__).resolve().parent / "static"
GITHUB_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


class CheckError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status


def normalize_repo_url(url: str) -> str:
    m = GITHUB_URL.match((url or "").strip())
    if not m or m.group(2) in (".", ".."):
        raise CheckError(HTTPStatus.BAD_REQUEST, "Enter a public GitHub repository URL, like https://github.com/owner/repo")
    return f"https://github.com/{m.group(1)}/{m.group(2)}"


def _remove(path: Path) -> None:
    def make_writable(func, p, _exc):  # git marks pack files read-only on Windows
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable)
    else:
        shutil.rmtree(path, onerror=make_writable)


def _size_mb(path: Path) -> float:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) / 1_048_576


def check_repository(repo_url: str) -> dict[str, Any]:
    url = normalize_repo_url(repo_url)
    if not _slots.acquire(blocking=False):
        raise CheckError(HTTPStatus.TOO_MANY_REQUESTS, "The checker is busy with other repositories; try again shortly.")
    workdir = Path(tempfile.mkdtemp(prefix="runtime-check-", dir=TEMP_DIR))
    try:
        repo = workdir / "repo"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
        try:
            proc = subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--", url, str(repo)],
                                  capture_output=True, timeout=CLONE_TIMEOUT_SECONDS, env=env)
        except FileNotFoundError:
            raise CheckError(HTTPStatus.INTERNAL_SERVER_ERROR, "git is not installed on the server.")
        except subprocess.TimeoutExpired:
            raise CheckError(HTTPStatus.GATEWAY_TIMEOUT, f"Cloning took longer than {CLONE_TIMEOUT_SECONDS}s.")
        if proc.returncode != 0:
            logger.info("Clone of %s failed: %s", url, proc.stderr.decode(errors="replace")[-500:])
            raise CheckError(HTTPStatus.BAD_REQUEST, "Could not clone the repository. Is it public and spelled correctly?")
        size = _size_mb(repo)
        if size > MAX_REPO_MB:
            raise CheckError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                             f"The repository is {size:.0f} MB; the limit is {MAX_REPO_MB} MB.")
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True).stdout.decode().strip()
        report = checker.check(repo)
        return {"repo_url": url, "repo_name": url.removeprefix("https://github.com/"), "commit": commit, **report}
    finally:
        _slots.release()
        _remove(workdir)


class Handler(BaseHTTPRequestHandler):
    server_version = "RuntimeChecker/1.0"

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if ALLOW_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOW_ORIGIN)
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, data: Any) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def do_OPTIONS(self) -> None:  # CORS preflight, when RUNTIME_ALLOW_ORIGIN is set
        self._send(HTTPStatus.NO_CONTENT, b"", "text/plain")

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(HTTPStatus.OK, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok", "node": bool(shutil.which("node"))})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})

    def do_POST(self) -> None:
        if self.path != "/api/check":
            self._json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                raise CheckError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body too large.")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise CheckError(HTTPStatus.BAD_REQUEST, "Send JSON: {\"repo_url\": \"https://github.com/owner/repo\"}")
            self._json(HTTPStatus.OK, check_repository(str(body.get("repo_url", ""))))
        except CheckError as e:
            self._json(e.status, {"detail": str(e)})
        except Exception:
            logger.exception("Check failed")
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"detail": "The check failed unexpectedly; see the server log."})

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s %s", self.address_string(), fmt % args)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    logger.info("Runtime-error checker on http://%s:%d", HOST, PORT)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
