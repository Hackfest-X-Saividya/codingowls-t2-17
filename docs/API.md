# API Documentation

Base URL: `https://ai-security-scanner-production.up.railway.app` (production) or `http://localhost:8000` (local)

## Health Check

```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "semgrep_installed": true,
  "semgrep_path": "/usr/local/bin/semgrep"
}
```

---

## Start a Scan

```
POST /api/scan
```

**Request Body:**
```json
{
  "repo_url": "https://github.com/owner/repo"
}
```

**Response (200):**
```json
{
  "scan_id": "abc123def456",
  "status": "started",
  "message": "Scan initiated successfully"
}
```

**Errors:**
- `422` — Invalid URL format (must be `https://github.com/owner/repo`)

---

## Get Scan Status

```
GET /api/scan/{scan_id}/status
```

**Response (200):**
```json
{
  "scan_id": "abc123def456",
  "status": "running",
  "progress": 50,
  "current_step": "Running Semgrep security scan",
  "steps_completed": ["clone_repo", "detect_language"],
  "steps_remaining": ["analyze", "parse_results", "ai_enhance"],
  "error": null
}
```

**Status values:** `pending`, `running`, `complete`, `failed`

**Steps (in order):**
1. `clone_repo` — Shallow clone the GitHub repository
2. `detect_language` — Detect primary programming language by file extensions
3. `analyze` — Run Semgrep with language-specific rulesets (OWASP Top 10, language-specific security rules)
4. `parse_results` — Parse SARIF output into structured findings
5. `ai_enhance` — Generate AI explanations via Claude (parallel)

**Errors:**
- `404` — Scan not found

---

## Get Scan Results

```
GET /api/scan/{scan_id}/results
```

**Response (200):**
```json
{
  "scan_id": "abc123def456",
  "repo_url": "https://github.com/owner/repo",
  "repo_name": "owner/repo",
  "scanned_at": "2026-03-01T10:30:00Z",
  "language": "python",
  "summary": {
    "total": 5,
    "critical": 2,
    "high": 1,
    "medium": 1,
    "low": 1
  },
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "title": "SQL Injection",
      "severity": "critical",
      "scanner_severity": "high",
      "file": "app.py",
      "line": 23,
      "end_line": 23,
      "rule_id": "python.flask.security.injection.sql-injection",
      "vulnerable_code": "query = f\"SELECT * FROM users WHERE username='{username}'\"",
      "fixed_code": "query = \"SELECT * FROM users WHERE username=?\"\ncursor.execute(query, (username,))",
      "ai_explanation": "This login endpoint directly interpolates user input into a SQL query...",
      "attack_scenario": "1. Attacker visits /login\n2. Enters username: admin' OR '1'='1 --\n...",
      "business_impact": "Complete authentication bypass leading to unauthorized access",
      "fix_time_estimate": "5 minutes",
      "confidence": 0.98,
      "false_positive_likelihood": 0.02
    }
  ]
}
```

**Errors:**
- `202` — Scan still in progress
- `404` — Scan not found
- `500` — Scan failed (includes error message)

## Supported Languages

| Language | Semgrep Rulesets |
|---|---|
| Python | `p/python`, `p/flask`, `p/django`, `p/owasp-top-ten` |
| JavaScript | `p/javascript`, `p/nodejs`, `p/owasp-top-ten` |
| Java | `p/java`, `p/owasp-top-ten` |
| Go | `p/golang`, `p/owasp-top-ten` |
| Ruby | `p/ruby`, `p/owasp-top-ten` |
