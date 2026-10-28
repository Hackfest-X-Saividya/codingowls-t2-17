import { ChildProcess, spawn, spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { parseReport } from "./core/report";
import { ScanReport } from "./core/types";

export interface ScanOutcome {
  report: ScanReport;
  root: string;
  usedAI: boolean;
}

export class ScanCancelled extends Error {
  constructor() {
    super("Scan cancelled");
  }
}

/** A failure with a message for the user and optional fix-it buttons. */
export class ScanError extends Error {
  constructor(message: string, readonly actions: { title: string; command: string; args?: unknown[] }[] = []) {
    super(message);
  }
}

const OPEN_SETTINGS = { title: "Open Settings", command: "aiSecurity.openSettings" };
const SHOW_OUTPUT = { title: "Show Output", command: "aiSecurity.showOutput" };
const LOCATE_SCANNER = { title: "Locate cli.py…", command: "aiSecurity.locateScanner" };
const REMEMBERED_SCANNER = "aiSecurity.lastScannerPath";

/** Runs `python backend/cli.py scan <folder> --json <tmp>` and parses the result. */
export class ScannerService {
  private current: ChildProcess | undefined;
  private cancelled = false;

  constructor(private readonly output: vscode.OutputChannel, private readonly globalState: vscode.Memento) {}

  get isScanning() {
    return this.current !== undefined;
  }

  cancel() {
    if (!this.current) return;
    this.cancelled = true;
    killTree(this.current);
  }

  async scan(root: string, token?: vscode.CancellationToken): Promise<ScanOutcome> {
    if (this.current) throw new ScanError("A scan is already running.");
    const cfg = vscode.workspace.getConfiguration("aiSecurity");
    const scannerPath = resolveScannerPath(cfg.get<string>("scannerPath", ""), this.globalState.get<string>(REMEMBERED_SCANNER));
    const pythonPath = resolvePythonPath(cfg.get<string>("pythonPath", ""), scannerPath);
    const usedAI = cfg.get<boolean>("useAI", true);
    const timeoutMs = Math.max(30, cfg.get<number>("scanTimeoutSeconds", 900)) * 1000;

    const tmp = path.join(os.tmpdir(), `ai-security-scan-${process.pid}-${Date.now()}.json`);
    const args = [scannerPath, "scan", root, "--json", tmp, ...(usedAI ? [] : ["--no-ai"])];

    // Put the interpreter's folder (venv/Scripts or venv/bin) first on PATH so the venv's
    // `semgrep` executable is found, and force UTF-8 so Windows consoles don't break output.
    const pathKey = Object.keys(process.env).find((k) => k.toUpperCase() === "PATH") ?? "PATH";
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PYTHONUTF8: "1",
      PYTHONIOENCODING: "utf-8",
      [pathKey]: [path.dirname(pythonPath), process.env[pathKey] ?? ""].join(path.delimiter),
    };

    this.output.appendLine(`\n[${new Date().toLocaleTimeString()}] Scanning ${root}${usedAI ? "" : " (AI off)"}`);
    this.output.appendLine(`> ${pythonPath} ${args.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ")}`);

    this.cancelled = false;
    let stderr = "";
    const exitCode = await new Promise<number | null>((resolve, reject) => {
      const child = spawn(pythonPath, args, { cwd: path.dirname(scannerPath), env, windowsHide: true });
      this.current = child;
      const timer = setTimeout(() => {
        this.output.appendLine(`Timed out after ${timeoutMs / 1000}s, stopping.`);
        stderr += "\n__TIMEOUT__";
        killTree(child);
      }, timeoutMs);
      const sub = token?.onCancellationRequested(() => this.cancel());

      child.stdout?.on("data", (d: Buffer) => this.output.append(d.toString("utf8")));
      child.stderr?.on("data", (d: Buffer) => {
        const s = d.toString("utf8");
        stderr += s;
        this.output.append(s);
      });
      child.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        sub?.dispose();
        this.current = undefined;
        if (err.code === "ENOENT") {
          reject(new ScanError(`Python was not found at "${pythonPath}". Set "aiSecurity.pythonPath" to an interpreter with the backend requirements installed.`, [OPEN_SETTINGS]));
        } else reject(err);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        sub?.dispose();
        this.current = undefined;
        resolve(code);
      });
    });

    try {
      if (this.cancelled) throw new ScanCancelled();
      if (stderr.includes("__TIMEOUT__")) {
        throw new ScanError(`The scan took longer than ${timeoutMs / 1000}s. Turn off AI explanations or raise "aiSecurity.scanTimeoutSeconds".`, [OPEN_SETTINGS]);
      }
      if (!fs.existsSync(tmp)) {
        const missing = stderr.match(/No module named '([^']+)'/);
        if (missing) {
          throw new ScanError(
            `The Python interpreter is missing "${missing[1]}". Install the backend requirements: ${pythonPath} -m pip install -r backend/requirements.txt`,
            [OPEN_SETTINGS, SHOW_OUTPUT],
          );
        }
        throw new ScanError(`The scanner exited with code ${exitCode} without producing results. See the output for details.`, [SHOW_OUTPUT]);
      }
      const report = parseReport(JSON.parse(fs.readFileSync(tmp, "utf8")));
      this.output.appendLine(`Done: ${report.vulnerabilities.length} findings.`);
      void this.globalState.update(REMEMBERED_SCANNER, scannerPath);
      return { report, root, usedAI };
    } finally {
      fs.rm(tmp, { force: true }, () => undefined);
    }
  }
}

function killTree(child: ChildProcess) {
  if (child.pid === undefined) return;
  if (process.platform === "win32") {
    // child.kill() would leave Semgrep (a grandchild process) running on Windows.
    spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true });
  } else {
    child.kill("SIGTERM");
  }
}

/** Folders checked for backend/cli.py: each workspace folder, its children and its parents. */
function autoDetectCandidates(): string[] {
  const out: string[] = [];
  for (const f of vscode.workspace.workspaceFolders ?? []) {
    const ws = f.uri.fsPath;
    out.push(path.join(ws, "backend", "cli.py"), path.join(ws, "cli.py"));
    try {
      for (const child of fs.readdirSync(ws, { withFileTypes: true })) {
        if (child.isDirectory() && !child.name.startsWith(".") && child.name !== "node_modules") {
          out.push(path.join(ws, child.name, "backend", "cli.py"));
        }
      }
    } catch {
      // unreadable folder: skip
    }
    let dir = ws;
    for (let i = 0; i < 4; i++) {
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
      out.push(path.join(dir, "backend", "cli.py"));
    }
  }
  return out;
}

/**
 * Finds the scanner CLI: the setting if given, else auto-detection around the workspace, else the
 * last location that worked (so scanning other projects keeps working after one successful scan).
 */
export function resolveScannerPath(configured: string, remembered?: string): string {
  const p = configured.trim();
  if (p) {
    const candidates = path.isAbsolute(p) ? [p] : (vscode.workspace.workspaceFolders ?? []).map((f) => path.join(f.uri.fsPath, p));
    const found = candidates.find((c) => fs.existsSync(c));
    if (!found) throw new ScanError(`The scanner CLI was not found at "${configured}".`, [LOCATE_SCANNER, OPEN_SETTINGS]);
    return path.resolve(found);
  }
  const found = [...autoDetectCandidates(), ...(remembered ? [remembered] : [])].find((c) => fs.existsSync(c));
  if (!found) {
    throw new ScanError(
      "Could not find the scanner CLI (backend/cli.py) for this workspace. Click “Locate cli.py…” and pick it from your ai-security-scanner folder; it is remembered for every project.",
      [LOCATE_SCANNER, OPEN_SETTINGS],
    );
  }
  return path.resolve(found);
}

/** Uses the setting if given, otherwise the venv next to cli.py, otherwise python on PATH. */
export function resolvePythonPath(configured: string, scannerPath: string): string {
  if (configured.trim()) return configured.trim();
  const dir = path.dirname(scannerPath);
  const win = process.platform === "win32";
  for (const venv of ["venv", ".venv", path.join("..", ".venv"), path.join("..", "venv")]) {
    const p = path.join(dir, venv, win ? "Scripts" : "bin", win ? "python.exe" : "python");
    if (fs.existsSync(p)) return path.resolve(p);
  }
  return win ? "python" : "python3";
}
