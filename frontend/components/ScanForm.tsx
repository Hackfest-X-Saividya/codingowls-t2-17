"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { startScan } from "@/lib/api";

const EXAMPLE_REPOS = [
  "https://github.com/appsecco/dvna",
  "https://github.com/incredibleindishell/SSRF_Vulnerable_Lab",
  "https://github.com/kiwicom/xssable",
  "https://github.com/snoopysecurity/dvws-node",
  "https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game",
];

export default function ScanForm() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const isValidUrl = (u: string) => /^https:\/\/github\.com\/[\w.\-]+\/[\w.\-]+\/?$/.test(u.trim());

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a GitHub repository URL");
      return;
    }
    if (!isValidUrl(trimmed)) {
      setError("Please enter a valid GitHub repository URL (https://github.com/owner/repo)");
      return;
    }

    setLoading(true);
    try {
      const result = await startScan(trimmed);
      router.push(`/results/${result.scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
      <div className="flex items-center gap-2 rounded-full border border-white/10 bg-slate-900/90 p-1.5 pl-5 shadow-[0_0_40px_rgba(104,28,197,0.25)] focus-within:border-indigo-500 transition-colors">
        <svg className="w-5 h-5 text-slate-500 shrink-0" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 .5a12 12 0 00-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.9 1.3 1.9 1.3 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.3-3.2-.1-.3-.6-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 016 0C17.3 4.7 18.3 5 18.3 5c.7 1.7.2 2.9.1 3.2.8.8 1.3 1.9 1.3 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0012 .5z" />
        </svg>
        <input
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setError("");
          }}
          placeholder="https://github.com/username/repo"
          aria-label="GitHub repository URL"
          disabled={loading}
          className="flex-1 min-w-0 bg-transparent py-2 text-slate-100 placeholder-slate-500 focus:outline-none disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-4 sm:px-6 py-2.5 bg-white text-black font-semibold rounded-full hover:bg-slate-200 transition-colors disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2 shrink-0"
        >
          {loading ? (
            <>
              <div className="w-4 h-4 rounded-full border-2 border-black border-t-transparent animate-spin" />
              Starting...
            </>
          ) : (
            <>
              <span className="sm:hidden">Scan</span>
              <span className="hidden sm:inline">Scan repository</span>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 12h14m-6-6l6 6-6 6" />
              </svg>
            </>
          )}
        </button>
      </div>

      <div className="mt-5">
        <p className="text-sm text-slate-500 mb-2">Try an example repo:</p>
        <div className="flex flex-wrap justify-center gap-2">
          {EXAMPLE_REPOS.map((exampleUrl) => (
            <button
              key={exampleUrl}
              type="button"
              disabled={loading}
              onClick={() => {
                setUrl(exampleUrl);
                setError("");
              }}
              className="px-3 py-1.5 text-sm bg-slate-900/80 border border-white/10 text-slate-300 rounded-full hover:border-indigo-500/60 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {exampleUrl.replace("https://github.com/", "")}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <p className="mt-3 text-sm text-red-400 flex items-center justify-center gap-1.5">
          <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          {error}
        </p>
      )}
    </form>
  );
}
