import ScanForm from "@/components/ScanForm";
import RecentScans from "@/components/RecentScans";
import BrandStar from "@/components/BrandStar";

const STEPS = [
  "GitHub URL",
  "Clone (depth=1)",
  "Static Analysis",
  "Dependency Check (OSV)",
  "Secret Scan",
  "AI Enhance (parallel)",
  "Prioritized Results",
];

const CONTROLS = [
  "GitHub URL validation (SSRF defense)",
  "Path validation (traversal defense)",
  "Repo size limits",
  "Scan timeout controls",
  "Rate limiting",
  "Temp file cleanup",
];

const LANGUAGES = [
  { name: "Python", rules: "p/python, p/flask, p/django, p/owasp-top-ten" },
  { name: "JavaScript", rules: "p/javascript, p/nodejs, p/owasp-top-ten" },
  { name: "Java", rules: "p/java, p/owasp-top-ten" },
  { name: "Go", rules: "p/golang, p/owasp-top-ten" },
  { name: "Ruby", rules: "p/ruby, p/owasp-top-ten" },
  { name: "PHP", rules: "p/php, p/owasp-top-ten" },
  { name: "Other", rules: "p/owasp-top-ten, p/security-audit" },
];

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="flex items-center gap-2 text-lg font-semibold text-white">
      <BrandStar className="w-4 h-4 text-indigo-500" />
      {children}
    </h3>
  );
}

function Item({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <li>
      <strong className="font-medium text-white">{term}</strong> {children}
    </li>
  );
}

export default function Home() {
  return (
    <div className="overflow-x-hidden">
      {/* Hero */}
      <section className="relative px-4 pt-20 sm:pt-28 pb-24">
        <div className="hero-glow pointer-events-none absolute inset-x-0 bottom-0 h-[75%]" aria-hidden="true" />

        <div className="relative flex flex-col items-center text-center max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-slate-900/80 py-1 pl-1 pr-4 text-xs sm:text-sm text-slate-300">
            <span className="rounded-full bg-indigo-600 px-2.5 py-0.5 font-medium text-snow">New</span>
            Attack chains and fix validation
          </div>

          <h1 className="mt-6 text-4xl sm:text-6xl lg:text-7xl font-semibold tracking-tight text-white text-balance leading-[1.05]">
            AI-Enhanced Security
            <br />
            <span className="bg-gradient-to-b from-white to-indigo-200 bg-clip-text text-transparent">
              Vulnerability Scanner
            </span>
          </h1>
          <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-2xl text-balance">
            Paste a GitHub repository URL to check its code, dependencies and secrets. Get AI-generated
            explanations, attack scenarios, and fix suggestions for every vulnerability found.
          </p>

          <div className="mt-10 w-full">
            <ScanForm />
          </div>
        </div>

        <div id="recent" className="relative mx-auto max-w-3xl scroll-mt-24">
          <RecentScans />
        </div>
      </section>

      {/* Overview */}
      <section id="overview" className="max-w-6xl mx-auto px-4 sm:px-6 py-20 scroll-mt-16">
        <div className="max-w-3xl">
          <p className="text-sm font-medium text-indigo-300">Overview</p>
          <h2 className="mt-2 text-3xl sm:text-4xl font-semibold tracking-tight text-white">
            From findings to fixes, in one report
          </h2>
          <p className="mt-5 text-lg text-slate-400 leading-relaxed">
            This scanner turns a GitHub repository into a fast, readable security report. It combines{" "}
            <strong className="font-medium text-white">static code analysis</strong>,{" "}
            <strong className="font-medium text-white">dependency checks against OSV.dev</strong>,{" "}
            <strong className="font-medium text-white">secret detection</strong> and{" "}
            <strong className="font-medium text-white">AI risk explanation</strong> so teams can move from
            finding issues to fixing them. Results export as SARIF for GitHub code scanning, and the same
            scanner runs in CI to block risky pull requests.
          </p>
        </div>

        <div className="panel mt-12 p-6">
          <SectionTitle>How it works</SectionTitle>
          <ol className="mt-5 flex flex-wrap items-center gap-2 text-sm">
            {STEPS.map((step, index) => (
              <li key={step} className="flex items-center gap-2">
                <span className="flex items-center gap-2 rounded-full border border-white/10 bg-black py-1.5 pl-1.5 pr-3.5 text-slate-200">
                  <span className="w-6 h-6 rounded-full bg-indigo-600 text-snow text-xs font-semibold flex items-center justify-center">
                    {index + 1}
                  </span>
                  {step}
                </span>
                {index < STEPS.length - 1 && (
                  <span className="text-slate-600" aria-hidden="true">
                    →
                  </span>
                )}
              </li>
            ))}
          </ol>

          <h4 className="mt-8 text-sm font-medium text-slate-400">Architecture</h4>
          <pre className="mt-3 overflow-x-auto rounded-xl border border-white/5 bg-black p-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
{`Frontend (Next.js) -> POST /api/scan
                     -> poll GET /api/scan/{id}/status
                     -> GET /api/scan/{id}/results

Backend (FastAPI):
RepoManager -> CodeAnalyzer -> SARIFParser -> AIEnhancer (parallel)`}
          </pre>
        </div>

        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="panel p-6">
            <SectionTitle>Security focus</SectionTitle>
            <ul className="mt-4 space-y-3 text-slate-400">
              <Item term="Injection risks:">SQL/command injection patterns are treated as high-priority.</Item>
              <Item term="Input validation:">Detects unsafe handling of user-controlled data.</Item>
              <Item term="Auth + access:">Flags weak authorization and privilege mistakes.</Item>
              <Item term="Secrets hygiene:">Highlights exposed credentials and sensitive data paths.</Item>
            </ul>
          </div>

          <div className="panel p-6">
            <SectionTitle>What you get</SectionTitle>
            <ul className="mt-4 space-y-3 text-slate-400">
              <Item term="Live progress:">
                Polling status from <code className="text-indigo-200">POST /api/scan</code> to completion.
              </Item>
              <Item term="Severity summary:">Critical, high, medium, low breakdown.</Item>
              <Item term="Attack context:">Realistic exploitation paths and business impact.</Item>
              <Item term="Fix guidance:">Safer code suggestions with diffs for faster remediation.</Item>
            </ul>
          </div>

          <div className="panel p-6">
            <SectionTitle>API flow</SectionTitle>
            <ol className="mt-4 space-y-3 text-slate-400 list-decimal list-inside">
              <li>
                <strong className="font-medium text-white">Start:</strong>{" "}
                <code className="text-indigo-200">POST /api/scan</code> returns a scan ID.
              </li>
              <li>
                <strong className="font-medium text-white">Track:</strong>{" "}
                <code className="text-indigo-200">GET /api/scan/{`{id}`}/status</code> reports steps and progress.
              </li>
              <li>
                <strong className="font-medium text-white">Collect:</strong>{" "}
                <code className="text-indigo-200">GET /api/scan/{`{id}`}/results</code> returns enriched
                vulnerabilities.
              </li>
            </ol>
          </div>

          <div className="panel p-6">
            <SectionTitle>Design decisions</SectionTitle>
            <ul className="mt-4 space-y-3 text-slate-400">
              <Item term="Parallel AI:">findings are enhanced concurrently for lower latency.</Item>
              <Item term="Shallow clone:">
                faster scans using <code className="text-indigo-200">depth=1</code>.
              </Item>
              <Item term="Fallback mode:">scanner still works without a Groq API key.</Item>
            </ul>
          </div>
        </div>

        <div className="panel mt-6 p-6">
          <SectionTitle>Security controls</SectionTitle>
          <div className="mt-4 flex flex-wrap gap-2 text-sm">
            {CONTROLS.map((control) => (
              <span key={control} className="rounded-full border border-white/10 bg-black px-3.5 py-1.5 text-slate-300">
                {control}
              </span>
            ))}
          </div>
        </div>

        <div id="languages" className="mt-16 scroll-mt-24">
          <SectionTitle>Supported languages</SectionTitle>
          <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {LANGUAGES.map(({ name, rules }) => (
              <div key={name} className="panel p-4">
                <p className="font-medium text-white">{name}</p>
                <p className="mt-1 font-mono text-xs text-slate-400">{rules}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="border-t border-white/5 py-8 text-center text-sm text-slate-500">
        AI Security Scanner · CodingOwls (T2-17), HackFest 2026
      </footer>
    </div>
  );
}
