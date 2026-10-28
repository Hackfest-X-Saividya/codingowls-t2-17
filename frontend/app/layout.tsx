import type { Metadata } from "next";
import localFont from "next/font/local";
import { Analytics } from "@vercel/analytics/react";
import "./globals.css";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
  weight: "100 900",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "AI Security Scanner",
  description: "AI-enhanced static security analysis for GitHub repositories",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased bg-[#FAF8F5] text-gray-800`}>
        <div className="fixed top-6 right-6 z-50">
          <a
            href="https://github.com/3-rt/ai-security-scanner"
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-500 hover:text-gray-700 transition-colors text-sm"
          >
            GitHub
          </a>
        </div>
        <main className="min-h-screen">{children}</main>
        <Analytics />
      </body>
    </html>
  );
}
