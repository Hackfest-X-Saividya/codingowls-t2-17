# AI Security Scanner — Frontend

Next.js 14 frontend for the AI Security Scanner. Provides the scan submission form, real-time progress tracking, and vulnerability results display.

## Setup

```bash
npm install
cp .env.local.example .env.local
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Environment Variables

| Variable             | Default                                              | Description            |
|----------------------|------------------------------------------------------|------------------------|
| `NEXT_PUBLIC_API_URL`| `https://ai-security-scanner-production.up.railway.app` | Backend API base URL |

## Project Structure

```
app/
  page.tsx                    — Landing page with scan form and project overview
  layout.tsx                  — Root layout with Geist fonts, Vercel Analytics
  results/[scanId]/page.tsx   — Results page with filtering, search, report export
  globals.css                 — Tailwind base styles

components/
  ScanForm.tsx                — GitHub URL input with example repo buttons
  ProgressTracker.tsx         — Real-time scan progress (2s polling, ETA, step timers)
  VulnerabilityCard.tsx       — Expandable card: explanation, attack, impact, code diff
  CodeDiff.tsx                — Side-by-side vulnerable/fixed code with syntax highlighting
  SummaryStats.tsx            — Severity breakdown cards (critical/high/medium/low)
  SeverityBadge.tsx           — Colored severity pill

lib/
  api.ts                      — API client (startScan, getScanStatus, getScanResults)
```

## Scripts

| Command         | Description              |
|-----------------|--------------------------|
| `npm run dev`   | Start dev server         |
| `npm run build` | Production build         |
| `npm run start` | Start production server  |
| `npm run lint`  | Run ESLint               |

## Deployment

Deploys on [Vercel](https://vercel.com). Set `NEXT_PUBLIC_API_URL` to your backend URL in Vercel's environment variables.
