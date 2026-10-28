"""Isolation helpers for fix validation.

Fixes are applied to throwaway copies under TEMP_DIR, never to the original
checkout or a user's repository. Subprocesses (Semgrep, an opt-in project test
command) get a minimal environment without API keys or tokens.

What this does NOT provide: network isolation or OS-level sandboxing. Project
tests run with the backend's user privileges, which is why running them is
off by default (VALIDATION_TEST_COMMAND). Use a container for untrusted code.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

# Enough for Python, Node and Semgrep to start; nothing that carries credentials
SAFE_ENV_KEYS = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "LANG", "LC_ALL",
)
IGNORED_DIRS = (".git", "node_modules", "__pycache__", ".venv", "venv")
COPY_IGNORE = shutil.ignore_patterns(*IGNORED_DIRS)


def restricted_env(**extra: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra)
    return env


def ensure_within(root: Path, rel: str) -> Path:
    """Resolve rel under root, refusing absolute paths and '..' escapes."""
    root = root.resolve()
    target = (root / rel).resolve()
    if rel.startswith(("/", "\\")) or ":" in rel or root not in target.parents:
        raise ValueError(f"Path escapes the workspace: {rel}")
    return target


def copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, ignore=COPY_IGNORE)


def tree_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".git" not in path.relative_to(root).parts:
            out[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def code_hash(root: Path) -> str:
    """SHA-256 identifying a code snapshot: sorted relative paths and file contents.

    Independent of where the tree lives and of file creation order. Skips the same
    directories copy_tree leaves out, so a checkout and its sandbox copy hash alike.
    """
    h = hashlib.sha256()
    files = [p for p in root.rglob("*")
             if p.is_file() and not set(p.relative_to(root).parts) & set(IGNORED_DIRS)]
    for rel, path in sorted((p.relative_to(root).as_posix(), p) for p in files):
        # length-prefixed so (path, content) boundaries are unambiguous
        name, data = rel.encode("utf-8"), path.read_bytes()
        h.update(len(name).to_bytes(8, "big") + name + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


def run_command(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    """Run a command in cwd with the restricted environment; returns (exit code, combined output)."""
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=restricted_env(), capture_output=True, timeout=timeout)
    except FileNotFoundError as e:
        return 127, f"Command not found: {e}"
    except subprocess.TimeoutExpired:
        return 124, f"Timed out after {timeout}s"
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    return proc.returncode, out[-4000:]
