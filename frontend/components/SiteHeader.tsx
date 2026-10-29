import BrandStar from "@/components/BrandStar";
import ThemeToggle from "@/components/ThemeToggle";

const NAV = [
  { href: "/", label: "Home" },
  { href: "/#recent", label: "Recent scans" },
  { href: "/#overview", label: "How it works" },
  { href: "/#languages", label: "Languages" },
];

export default function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 bg-black/70 backdrop-blur-md border-b border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        <a href="/" className="flex items-center gap-2 text-white font-semibold tracking-tight">
          <span className="w-8 h-8 rounded-full bg-indigo-600 flex items-center justify-center shadow-[0_0_20px_rgba(104,28,197,0.6)]">
            <BrandStar className="w-4 h-4 text-snow" />
          </span>
          <span className="hidden sm:inline">AI Security Scanner</span>
        </a>

        <nav className="hidden md:flex items-center gap-1 rounded-full border border-white/10 bg-slate-900/80 p-1 text-sm">
          {NAV.map(({ href, label }) => (
            <a
              key={href}
              href={href}
              className="px-4 py-1.5 rounded-full text-slate-300 hover:text-white hover:bg-white/5 transition-colors"
            >
              {label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <ThemeToggle />
          <a
            href="/"
            className="px-5 py-2 rounded-full bg-white text-black text-sm font-semibold hover:bg-slate-200 transition-colors"
          >
            New scan
          </a>
        </div>
      </div>
    </header>
  );
}
