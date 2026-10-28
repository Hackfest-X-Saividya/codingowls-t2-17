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
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1">
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setError("");
            }}
            placeholder="https://github.com/username/repo"
            disabled={loading}
            className="w-full px-4 py-3 bg-white border border-gray-300 rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:border-gray-400 transition-all disabled:opacity-50"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-3 bg-gray-900 text-white font-medium rounded-xl hover:bg-gray-800 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shrink-0"
        >
          {loading ? (
            <>
              <div className="w-4 h-4 rounded-full border-2 border-white border-t-transparent animate-spin" />
              Starting...
            </>
          ) : (
            <>
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              Scan Repository
            </>
          )}
        </button>
      </div>

      <div className="mt-4">
        <p className="text-sm text-gray-500 mb-2">Try an example repo:</p>
        <div className="flex flex-wrap gap-2">
          {EXAMPLE_REPOS.map((exampleUrl) => (
            <button
              key={exampleUrl}
              type="button"
              disabled={loading}
              onClick={() => {
                setUrl(exampleUrl);
                setError("");
              }}
              className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 rounded-full hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {exampleUrl.replace("https://github.com/", "")}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <p className="mt-3 text-sm text-red-600 flex items-center gap-1.5">
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
