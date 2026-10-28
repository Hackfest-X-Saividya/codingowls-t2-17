"use client";

import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneLight } from "react-syntax-highlighter/dist/esm/styles/prism";

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
    ...oneLight,
    'pre[class*="language-"]': {
      ...oneLight['pre[class*="language-"]'],
      background: "transparent",
      margin: 0,
      padding: "1rem",
      fontSize: "0.8125rem",
    },
    'code[class*="language-"]': {
      ...oneLight['code[class*="language-"]'],
      background: "transparent",
    },
  };

  return (
    <div className="mt-4">
      <div className="flex items-center gap-2 mb-3">
        <div className="flex bg-gray-100 rounded-lg p-0.5">
          {(["side-by-side", "vulnerable", "fixed"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                view === v ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
              }`}
            >
              {v === "side-by-side" ? "Side by Side" : v === "vulnerable" ? "Vulnerable" : "Fixed"}
            </button>
          ))}
        </div>
        <button
          onClick={copyFixed}
          className="ml-auto px-3 py-1.5 text-xs font-medium bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors"
        >
          {copied ? "Copied!" : "Copy Fix"}
        </button>
      </div>

      {view === "side-by-side" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="rounded-lg overflow-hidden border border-red-200 bg-red-50/50">
            <div className="px-3 py-1.5 bg-red-50 text-red-700 text-xs font-medium border-b border-red-200">
              Vulnerable Code
            </div>
            <SyntaxHighlighter language={syntaxLang} style={codeStyle} showLineNumbers wrapLongLines>
              {vulnerableCode || "(not available)"}
            </SyntaxHighlighter>
          </div>
          <div className="rounded-lg overflow-hidden border border-green-200 bg-green-50/50">
            <div className="px-3 py-1.5 bg-green-50 text-green-700 text-xs font-medium border-b border-green-200">
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
            view === "vulnerable" ? "border-red-200 bg-red-50/50" : "border-green-200 bg-green-50/50"
          }`}
        >
          <div
            className={`px-3 py-1.5 text-xs font-medium border-b ${
              view === "vulnerable"
                ? "bg-red-50 text-red-700 border-red-200"
                : "bg-green-50 text-green-700 border-green-200"
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
