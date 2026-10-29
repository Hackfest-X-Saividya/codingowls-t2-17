# Runtime error check

Finds code that will **crash when it runs**, by reading the source. The scanned repository's
code is never executed or imported, and there is no Docker per scan: one small Python process
serves the page and checks repositories inside the request, then deletes the clone.

This folder is self-contained and independent of `backend/` and `frontend/`.

## What it finds

| Language | Error | Example |
|---|---|---|
| Python | `SyntaxError` | the file cannot be imported at all |
| Python | `NameError` / `UnboundLocalError` | a misspelt variable, a local read before it is assigned |
| Python | `ModuleNotFoundError` / `ImportError` | `from .models import Usr`, `from app.servcies import x` (in-repo and relative imports) |
| Python | `TypeError` | `create_user(name)` when the function needs `name, email`; wrong keyword names |
| Python | format strings | `"%s %s" % (a,)`, `"{name}".format(user=x)` |
| JavaScript | `SyntaxError` | `.js` / `.mjs` / `.cjs` files that do not parse (JSX and Flow files are skipped) |

To keep false alarms down, it does **not** report:

- Third-party imports. Whether a package is installed is only known where the code runs.
- Errors that are expected: inside `pytest.raises` / `assertRaises`, or a `try` that catches them.
- Lines marked `# noqa` or `# type: ignore`.
- Type hints that Python never evaluates.
- `docs/`, `docs_src/`, test fixtures (`fixtures/`, `testdata/`, `tests/**/data/`) and dependency folders.

Errors that depend on data, configuration or library versions only show up when the code actually runs.

## Run locally

```bash
cd runtime
python -m venv venv
venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
pip install -r requirements-dev.txt

python server.py                 # page at http://127.0.0.1:8100
python checker.py path/to/folder # same check on a local folder, printed in the terminal
python checker.py . --fail-on high   # exit code 1 for CI when a high-severity problem is found
python -m pytest -q tests
```

Needs Python 3.10+ and git; Node.js is optional (JavaScript files are skipped without it).
Use the newest Python you can: files using syntax newer than the checker's Python are
reported as syntax errors (the report says which version parsed them).

## API

| Method | Path | |
|---|---|---|
| `GET` | `/` | the results page |
| `POST` | `/api/check` | `{"repo_url": "https://github.com/owner/repo"}` → report with `summary`, `problems`, `warnings` |
| `GET` | `/health` | health check |

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `8100` | Where the server listens (the Dockerfile sets `0.0.0.0:8080`) |
| `RUNTIME_MAX_REPO_MB` | `200` | Larger repositories are rejected |
| `RUNTIME_MAX_CONCURRENT` | `2` | Checks at the same time; more get "busy, try again" |
| `RUNTIME_TEMP_DIR` | system temp | Where repositories are cloned for the length of a check |
| `RUNTIME_ALLOW_ORIGIN` | (unset) | Set to the dashboard's URL to let another site call `/api/check` |

## Deploy

The Dockerfile here only packages the app for the host; checks still run in-process.

**Railway**: New service → Deploy from GitHub repo → this repository. In the service settings, set
**Root Directory** to `/runtime` and **Config File Path** to `/runtime/railway.toml`, then
**Generate Domain** under Networking. The service sleeps when idle and wakes on the next request.

**Fly.io**: change `app` in `fly.toml`, then from this folder:

```bash
fly auth login
fly apps create <your-app-name>
fly deploy
```

Machines stop when idle (`min_machines_running = 0`) and start on the next request.
