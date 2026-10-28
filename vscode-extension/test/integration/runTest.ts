// Runs the integration suite inside a real (downloaded, isolated) VS Code instance against a copy
// of test/fixtures/vulnapp. Needs the backend venv (Python + requirements + Semgrep) and network
// access for the OSV dependency check. Usage: npm run test:integration
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runTests } from "@vscode/test-electron";

async function main() {
  const extensionDevelopmentPath = path.resolve(__dirname, "..", "..", "..");
  const extensionTestsPath = path.resolve(__dirname, "suite");
  const repoRoot = path.resolve(extensionDevelopmentPath, "..");

  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ai-security-it-"));
  for (const f of ["app.py", "requirements.txt"]) {
    fs.copyFileSync(path.join(extensionDevelopmentPath, "test", "fixtures", "vulnapp", f), path.join(workspace, f));
  }
  // npm project (lockfile v3) with a direct (lodash) and a transitive (qs, via express) vulnerable package
  fs.mkdirSync(path.join(workspace, "web"));
  for (const f of ["package.json", "package-lock.json"]) {
    fs.copyFileSync(path.join(extensionDevelopmentPath, "test", "fixtures", "npmapp", f), path.join(workspace, "web", f));
  }
  fs.mkdirSync(path.join(workspace, ".vscode"));
  fs.writeFileSync(
    path.join(workspace, ".vscode", "settings.json"),
    JSON.stringify(
      {
        "aiSecurity.scannerPath": path.join(repoRoot, "backend", "cli.py"),
        "aiSecurity.useAI": false,
        "aiSecurity.confirmPackageManager": false,
      },
      null,
      2,
    ),
  );

  try {
    await runTests({
      extensionDevelopmentPath,
      extensionTestsPath,
      launchArgs: [workspace, "--disable-extensions", "--disable-workspace-trust"],
    });
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
