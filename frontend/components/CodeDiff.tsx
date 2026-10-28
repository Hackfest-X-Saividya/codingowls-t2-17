"use client";

import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

interface CodeDiffProps {
  vulnerableCode: string;
  fixedCode: string;
  language?: string;
}

export default function CodeDiff({ vulnerableCode, fixedCode, language = "python" }: CodeDiffProps) {
  const [view, setView] = useState<"side-by-side" | "vulnerable" | "fixed">("side-by-side");
  const [copied, setCopied] = useState(false);

  const langMap: Record<string, string> = {
    python: "python",
    javascript: "javascript",
    java: "java",
    csharp: "csharp",
    go: "go",
    ruby: "ruby",
    php: "php",
    cpp: "cpp",
  };

  const syntaxLang = langMap[language] || "text";

  const copyFixed = () => {
    navigator.clipboard.writeText(fixedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const codeStyle = {
    ...oneDark,
    'pre[class*="language-"]': {
      ...oneDark['pre[class*="language-"]'],
      background: "transparent",
      margin: 0,
      padding: "1rem",
      fontSize: "0.8125rem",
    },
    'code[class*="language-"]': {
      ...oneDark['code[class*="language-"]'],
      background: "transparent",
    },
  };

  return (
    <div className="mt-4">
      <div className="flex items-center gap-2 mb-3">
        <div className="flex bg-slate-800 rounded-lg p-0.5">
          {(["side-by-side", "vulnerable", "fixed"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                view === v ? "bg-slate-900 text-slate-100 shadow-sm" : "text-slate-400 hover:text-slate-300"
              }`}
            >
              {v === "side-by-side" ? "Side by Side" : v === "vulnerable" ? "Vulnerable" : "Fixed"}
            </button>
          ))}
        </div>
        <button
          onClick={copyFixed}
          className="ml-auto px-3 py-1.5 text-xs font-medium bg-slate-800 text-slate-300 rounded-lg hover:bg-slate-700 transition-colors"
        >
          {copied ? "Copied!" : "Copy Fix"}
        </button>
      </div>

      {view === "side-by-side" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="rounded-lg overflow-hidden border border-red-500/30 bg-red-500/5">
            <div className="px-3 py-1.5 bg-red-500/10 text-red-300 text-xs font-medium border-b border-red-500/30">
              Vulnerable Code
            </div>
            <SyntaxHighlighter language={syntaxLang} style={codeStyle} showLineNumbers wrapLongLines>
              {vulnerableCode || "(not available)"}
            </SyntaxHighlighter>
          </div>
          <div className="rounded-lg overflow-hidden border border-green-500/30 bg-green-500/5">
            <div className="px-3 py-1.5 bg-green-500/10 text-green-300 text-xs font-medium border-b border-green-500/30">
              Fixed Code
            </div>
            <SyntaxHighlighter language={syntaxLang} style={codeStyle} showLineNumbers wrapLongLines>
              {fixedCode || "(not available)"}
            </SyntaxHighlighter>
          </div>
        </div>
      ) : (
        <div
          className={`rounded-lg overflow-hidden border ${
            view === "vulnerable" ? "border-red-500/30 bg-red-500/5" : "border-green-500/30 bg-green-500/5"
          }`}
        >
          <div
            className={`px-3 py-1.5 text-xs font-medium border-b ${
              view === "vulnerable"
                ? "bg-red-500/10 text-red-300 border-red-500/30"
                : "bg-green-500/10 text-green-300 border-green-500/30"
            }`}
          >
            {view === "vulnerable" ? "Vulnerable Code" : "Fixed Code"}
          </div>
          <SyntaxHighlighter language={syntaxLang} style={codeStyle} showLineNumbers wrapLongLines>
            {(view === "vulnerable" ? vulnerableCode : fixedCode) || "(not available)"}
          </SyntaxHighlighter>
        </div>
      )}
    </div>
  );
}
