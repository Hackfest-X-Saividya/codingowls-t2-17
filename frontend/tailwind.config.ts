import type { Config } from "tailwindcss";

// Theme: black background, #151515 panels, white text and one purple accent (#681CC5), plus a
// light mode. The components use `slate` for neutrals and `indigo` / `violet` for the accent, so
// every colour scale they use reads a CSS variable from app/theme-colors.css; switching
// <html data-theme="light"> swaps the variables and the whole UI follows without class changes.
const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
const FAMILIES = ["slate", "indigo", "violet", "red", "orange", "amber", "green", "blue", "rose"];

const themed = (name: string) => `rgb(var(--c-${name}) / <alpha-value>)`;
const scale = (family: string) => Object.fromEntries(SHADES.map((s) => [s, themed(`${family}-${s}`)]));

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        ...Object.fromEntries(FAMILIES.map((f) => [f, scale(f)])),
        // `white` / `black` are the strongest ink and the page colour, so they swap in light mode too
        white: themed("white"),
        black: themed("black"),
        // Text on the purple accent: white in both themes
        snow: "#ffffff",
      },
      fontFamily: {
        sans: ['"SF Pro Display"', "-apple-system", "BlinkMacSystemFont", "var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
