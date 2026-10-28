import ScanForm from "@/components/ScanForm";
import RecentScans from "@/components/RecentScans";

export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-24">
      <div className="text-center mb-12 max-w-3xl">
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-slate-100 text-balance">
          AI-Enhanced Security
          <br />
          Vulnerability Scanner
        </h1>
        <p className="mt-6 text-lg text-slate-400 max-w-2xl mx-auto text-balance">
          Paste a GitHub repository URL to check its code, dependencies and secrets. Get AI-generated
          explanations, attack scenarios, and fix suggestions for every vulnerability found.
        </p>
      </div>

      <ScanForm />

      <RecentScans />

      <section className="mt-40 max-w-5xl w-full">
        <h2 className="text-3xl font-semibold text-slate-100">Overview</h2>
        <p className="mt-5 text-lg text-slate-400 leading-relaxed">
          This scanner turns a GitHub repository into a fast, readable security report. It combines{" "}
          <strong className="font-semibold text-slate-100">static code analysis</strong>,{" "}
          <strong className="font-semibold text-slate-100">dependency checks against OSV.dev</strong>,{" "}
          <strong className="font-semibold text-slate-100">secret detection</strong> and{" "}
          <strong className="font-semibold text-slate-100">AI risk explanation</strong> so teams can
          move from finding issues to fixing them. Results export as SARIF for GitHub code scanning,
          and the same scanner runs in CI to block risky pull requests.
        </p>

        <div className="mt-10">
          <h3 className="text-xl font-semibold text-slate-100">How It Works</h3>
          <div className="mt-4 flex flex-wrap items-center gap-2 text-sm sm:text-base">
            {[
              "GitHub URL",
              "Clone (depth=1)",
              "Static Analysis",
              "Dependency Check (OSV)",
              "Secret Scan",
              "AI Enhance (parallel)",
              "Prioritized Results",
            ].map((step, index, arr) => (
              <div key={step} className="flex items-center gap-2">
                <span className="px-3 py-1.5 rounded-full bg-slate-800 text-slate-200 font-medium">
                  {step}
                </span>
                {index < arr.length - 1 && (
                  <span className="text-slate-500 font-semibold" aria-hidden="true">
                    →
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="mt-10">
          <h3 className="text-xl font-semibold text-slate-100">Architecture</h3>
          <pre className="mt-4 overflow-x-auto rounded-xl bg-slate-800 p-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
{`Frontend (Next.js) -> POST /api/scan
                     -> poll GET /api/scan/{id}/status
                     -> GET /api/scan/{id}/results

Backend (FastAPI):
RepoManager -> CodeAnalyzer -> SARIFParser -> AIEnhancer (parallel)`}
          </pre>
        </div>

        <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-8">
          <div>
            <h3 className="text-xl font-semibold text-slate-100">Security Focus</h3>
            <ul className="mt-3 space-y-2 text-slate-400">
              <li>
                <strong className="text-slate-100">Injection Risks:</strong> SQL/command injection
                patterns are treated as high-priority.
              </li>
              <li>
                <strong className="text-slate-100">Input Validation:</strong> Detects unsafe handling
                of user-controlled data.
              </li>
              <li>
                <strong className="text-slate-100">Auth + Access:</strong> Flags weak authorization
                and privilege mistakes.
              </li>
              <li>
                <strong className="text-slate-100">Secrets Hygiene:</strong> Highlights exposed
                credentials and sensitive data paths.
              </li>
            </ul>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-slate-100">What You Get</h3>
            <ul className="mt-3 space-y-2 text-slate-400">
              <li>
                <strong className="text-slate-100">Live Progress:</strong> Polling status from
                <code className="text-slate-100">POST /api/scan</code> to completion.
              </li>
              <li>
                <strong className="text-slate-100">Severity Summary:</strong> Critical, high, medium,
                low breakdown.
              </li>
              <li>
                <strong className="text-slate-100">Attack Context:</strong> Realistic exploitation
                paths and business impact.
              </li>
              <li>
                <strong className="text-slate-100">Fix Guidance:</strong> Safer code suggestions with
                diffs for faster remediation.
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-8">
          <div>
            <h3 className="text-xl font-semibold text-slate-100">API Flow</h3>
            <ol className="mt-3 space-y-2 text-slate-400 list-decimal list-inside">
              <li>
                <strong className="text-slate-100">Start:</strong>{" "}
                <code className="text-slate-100">POST /api/scan</code> returns a scan ID.
              </li>
              <li>
                <strong className="text-slate-100">Track:</strong>{" "}
                <code className="text-slate-100">GET /api/scan/{`{id}`}/status</code> reports steps
                and progress.
              </li>
              <li>
                <strong className="text-slate-100">Collect:</strong>{" "}
                <code className="text-slate-100">GET /api/scan/{`{id}`}/results</code> returns
                enriched vulnerabilities.
              </li>
            </ol>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-slate-100">Design Decisions</h3>
            <ul className="mt-3 space-y-2 text-slate-400">
              <li>
                <strong className="text-slate-100">Parallel AI:</strong> findings are enhanced
                concurrently for lower latency.
              </li>
              <li>
                <strong className="text-slate-100">Shallow clone:</strong> faster scans using{" "}
                <code className="text-slate-100">depth=1</code>.
              </li>
              <li>
                <strong className="text-slate-100">Fallback mode:</strong> scanner still works
                without an Anthropic API key.
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-10">
          <h3 className="text-xl font-semibold text-slate-100">Security Controls</h3>
          <div className="mt-3 flex flex-wrap gap-2 text-sm">
            {[
              "GitHub URL validation (SSRF defense)",
              "Path validation (traversal defense)",
              "Repo size limits",
              "Scan timeout controls",
              "Rate limiting",
              "Temp file cleanup",
            ].map((control) => (
              <span
                key={control}
                className="px-3 py-1.5 rounded-full bg-slate-800 text-slate-300 font-medium"
              >
                {control}
              </span>
            ))}
          </div>
        </div>

        <div className="mt-10">
          <h3 className="text-xl font-semibold text-slate-100">Supported Languages</h3>
          <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-400">
            <p>
              <strong className="text-slate-100">Python:</strong> p/python, p/flask, p/django,
              p/owasp-top-ten
            </p>
            <p>
              <strong className="text-slate-100">JavaScript:</strong> p/javascript, p/nodejs,
              p/owasp-top-ten
            </p>
            <p>
              <strong className="text-slate-100">Java:</strong> p/java, p/owasp-top-ten
            </p>
            <p>
              <strong className="text-slate-100">Go:</strong> p/golang, p/owasp-top-ten
            </p>
            <p>
              <strong className="text-slate-100">Ruby:</strong> p/ruby, p/owasp-top-ten
            </p>
            <p>
              <strong className="text-slate-100">PHP:</strong> p/php, p/owasp-top-ten
            </p>
            <p>
              <strong className="text-slate-100">Other:</strong> p/owasp-top-ten, p/security-audit
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
