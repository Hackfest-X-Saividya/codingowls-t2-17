# AI Security Scanner for VS Code

Scan your workspace for **vulnerable code**, **vulnerable dependencies** and **hardcoded secrets**,
and work through every finding from an interactive sidebar, without leaving the editor.

It runs the same pipeline as the web app (`backend/cli.py`): static code analysis, OSV.dev
dependency checks, secret detection and optional AI explanations and fixes.

## Features

**Findings sidebar** (shield icon in the Activity Bar)
- Every finding in one list, grouped by **Severity**, **File** or **Type** (Code / Dependencies / Secrets)
- Critical and high groups open automatically; counts on every group and a badge on the icon
- Summary line at the top: `35 findings · 1 critical · 6 high · 2 min ago`
- **Filter** by severity and type, **search** by title, file, rule or package
- Inline buttons on each finding: **Apply fix** and **Ignore**; right-click for diff, copy and references
- Click a finding to jump to the exact line (briefly highlighted)

**Finding Details panel** (below the list)
- Severity, type and location, plus the explanation, attack scenario and business impact
- Vulnerable code next to the suggested fix
- Buttons: Apply fix · Show diff · Open · Ignore/Restore · Copy

**In the editor**
- Squiggles and **Problems** panel entries (critical/high = error, medium = warning, low = info)
- Lightbulb quick fixes: *Apply suggested fix*, *Show details*, *Ignore*
- Status bar: `🛡 1 critical`; click it to open the sidebar

**Fixes you can trust**
- Code fixes are applied only if the vulnerable code is still there; otherwise you get a diff instead
- Dependency fixes upgrade to the version that fixes **all** of the package's advisories at once:
  - `requirements.txt`: the pinned version is edited (`flask==0.12.2` → `flask==3.1.3`)
  - `package-lock.json` / `yarn.lock`: lockfiles are never hand-edited; **npm / yarn runs** in a terminal
    task and updates `package.json`, the lockfile and `node_modules` together. A package pulled in by other
    packages gets an `overrides` (npm) / `resolutions` (yarn) entry in `package.json`. You confirm first.
  - `poetry.lock`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, `go.mod`: the right command is typed
    into a terminal for you to run
- Every fix is one normal edit: **Ctrl+Z** undoes it
- Secret findings show the steps to take (rotate, move to env vars, purge history); they are never auto-edited

**Keeps up with your edits**
- Findings move with the code as you add or remove lines above them
- Ignored findings are remembered across scans; the last scan is restored when you reopen VS Code
- Optional *scan on save*

## Requirements

The extension drives the project's Python scanner, so it needs:

1. The backend set up (see the README in the repository root):
   ```bash
   cd backend
   python -m venv venv
   venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
   pip install -r requirements.txt semgrep
   ```
2. Optional, for AI explanations and code fixes: `GROQ_API_KEY` in `backend/.env`.

When this repository is open, `backend/cli.py` and `backend/venv` are found automatically.
To scan **another project**, set `aiSecurity.scannerPath` to the full path of `backend/cli.py`.

## Install

**From the packaged file**
```bash
cd vscode-extension
npm install
npm run package          # → ai-security-scanner-0.1.0.vsix
```
Then in VS Code: **Extensions** → `⋯` → **Install from VSIX…** → pick the file.

**For development**: open the `vscode-extension` folder in VS Code and press **F5**. A second
window opens on the repository with the extension loaded.

## Usage

1. Click the **shield** in the Activity Bar → **Scan Workspace** (or *Security Scanner: Scan Workspace*
   from the Command Palette, or right-click a folder in the Explorer → *Scan Folder with Security Scanner*).
2. Browse the findings. Use the toolbar to **group**, **filter** or **search**.
3. Click a finding to open the code and see its details; **Apply fix**, **Ignore** or **Show diff**.
4. Save and re-scan to confirm the fixes.

## Settings

| Setting | Default | Description |
|---|---|---|
| `aiSecurity.scannerPath` | auto | Path to `backend/cli.py` |
| `aiSecurity.pythonPath` | auto | Python with the backend requirements (default: `venv` next to `cli.py`, then `python`) |
| `aiSecurity.useAI` | `true` | AI explanations and code fixes (needs `GROQ_API_KEY`); turn off for faster scans |
| `aiSecurity.scanOnSave` | `false` | Re-scan after saving a file |
| `aiSecurity.scanTimeoutSeconds` | `900` | Stop scans that take longer |
| `aiSecurity.minSeverity` | `low` | Lowest severity shown as squiggles / in Problems (the sidebar always lists all) |
| `aiSecurity.groupBy` | `severity` | Default grouping |
| `aiSecurity.confirmPackageManager` | `true` | Ask before running npm/yarn to upgrade a package |

## Development

```
src/
├── extension.ts              commands, wiring
├── scannerService.ts         runs cli.py, cancel/timeout, error messages
├── findingsStore.ts          single source of truth (results, filters, ignored, line tracking)
├── tree/                     Findings sidebar (TreeDataProvider)
├── details/                  Finding Details webview
├── diagnostics.ts            squiggles + Problems panel
├── fixProvider.ts            apply fix, diff preview, lightbulb actions
├── statusBar.ts
└── core/                     pure logic, no vscode import (unit-tested)
    ├── report.ts             parse/validate CLI JSON, stable finding keys
    ├── grouping.ts           group / filter / sort / summary
    ├── fixes.ts              compute code and dependency fixes safely
    ├── packageManagers.ts    npm / yarn / pip / poetry / go … upgrade plans
    └── lineTracking.ts       move findings as the file is edited
```

| Command | What it does |
|---|---|
| `npm run build` / `npm run watch` | Bundle with esbuild into `dist/` |
| `npm run typecheck` | TypeScript checks |
| `npm test` | Unit tests for `src/core` (Node test runner) |
| `npm run test:integration` | Real VS Code instance: scans `test/fixtures/vulnapp` with the backend and checks the sidebar, diagnostics, fixes, ignore and diff |
| `npm run package` | Build the `.vsix` |

`test/fixtures/vulnapp` is a deliberately vulnerable sample app (SQL injection, command injection, an
example AWS key and outdated packages) for demos and tests. Don't deploy it.
