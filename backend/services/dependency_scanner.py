"""Software composition analysis: find dependencies with known vulnerabilities.

Parses lockfiles / pinned manifests, then queries the OSV.dev database
(https://osv.dev), which aggregates GitHub Security Advisories, PyPA, npm,
Go, RubyGems, Packagist and more.

Only exact versions can be checked, so unpinned ranges (e.g. "flask>=2" in
requirements.txt or "^4.0.0" in package.json without a lockfile) are skipped
and reported as a warning.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

import httpx

from models.schemas import FindingCategory, Vulnerability

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
MAX_VULN_DETAILS = 300
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor"}

SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str      # OSV ecosystem name
    manifest: str       # repo-relative path
    line: int


# --------------------------------------------------------------------------- parsers

def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _parse_requirements(text: str, rel: str) -> tuple[list[Dependency], int]:
    deps, unpinned = [], 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)", line)
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "PyPI", rel, i))
        else:
            unpinned += 1
    return deps, unpinned


def _parse_pipfile_lock(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    deps = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=")
            if version:
                deps.append(Dependency(name, version, "PyPI", rel, _line_of(text, f'"{name}"')))
    return deps


def _parse_poetry_lock(text: str, rel: str) -> list[Dependency]:
    deps = []
    for m in re.finditer(r'^\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"', text, re.M):
        deps.append(Dependency(m.group(1), m.group(2), "PyPI", rel, text.count("\n", 0, m.start()) + 2))
    return deps


def _parse_package_lock(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    seen: set[tuple[str, str]] = set()
    if "packages" in data:  # lockfile v2 / v3
        for path, info in data["packages"].items():
            if not path or "node_modules/" not in path or info.get("link"):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[1]
            if info.get("version"):
                seen.add((name, info["version"]))
    else:  # lockfile v1
        def walk(tree: dict) -> None:
            for name, info in (tree or {}).items():
                if info.get("version"):
                    seen.add((name, info["version"]))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return [Dependency(n, v, "npm", rel, _line_of(text, f'"{n}"')) for n, v in sorted(seen)]


def _parse_yarn_lock(text: str, rel: str) -> list[Dependency]:
    deps = []
    for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*:\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:? "?([^"\s]+)"?', text, re.M):
        deps.append(Dependency(m.group(1), m.group(2), "npm", rel, text.count("\n", 0, m.start()) + 1))
    return list({(d.name, d.version): d for d in deps}.values())


def _parse_go_mod(text: str, rel: str) -> list[Dependency]:
    deps = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+(v[0-9][^\s]*)", line)
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "Go", rel, i))
    return deps


def _parse_composer_lock(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    deps = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            if pkg.get("name") and pkg.get("version"):
                deps.append(Dependency(pkg["name"], pkg["version"].lstrip("v"), "Packagist", rel,
                                       _line_of(text, f'"{pkg["name"]}"')))
    return deps


def _parse_gemfile_lock(text: str, rel: str) -> list[Dependency]:
    deps = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)\s]*)\)$", line)
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "RubyGems", rel, i))
    return deps


def collect_dependencies(repo_path: Path) -> tuple[list[Dependency], list[str]]:
    """Find and parse all supported manifests. Returns (dependencies, warnings)."""
    deps: list[Dependency] = []
    warnings: list[str] = []
    unpinned_total = 0
    has_npm_lock = False
    package_json_dirs: list[str] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(root) / filename
            rel = path.relative_to(repo_path).as_posix()
            lower = filename.lower()
            try:
                if lower.endswith(".txt") and lower.startswith("requirements"):
                    found, unpinned = _parse_requirements(path.read_text(encoding="utf-8", errors="replace"), rel)
                    deps += found
                    unpinned_total += unpinned
                    continue
                parser = {
                    "pipfile.lock": _parse_pipfile_lock,
                    "poetry.lock": _parse_poetry_lock,
                    "package-lock.json": _parse_package_lock,
                    "npm-shrinkwrap.json": _parse_package_lock,
                    "yarn.lock": _parse_yarn_lock,
                    "go.mod": _parse_go_mod,
                    "composer.lock": _parse_composer_lock,
                    "gemfile.lock": _parse_gemfile_lock,
                }.get(lower)
                if lower == "package.json":
                    package_json_dirs.append(Path(rel).parent.as_posix())
                if parser:
                    deps += parser(path.read_text(encoding="utf-8", errors="replace"), rel)
                    has_npm_lock |= lower in ("package-lock.json", "yarn.lock", "npm-shrinkwrap.json")
            except Exception as e:  # malformed manifest should never fail the scan
                logger.warning("Could not parse %s: %s", rel, e)
                warnings.append(f"Could not parse {rel}: {e}")

    if unpinned_total:
        warnings.append(
            f"{unpinned_total} Python requirement(s) are not pinned with '==' and could not be "
            "checked for known vulnerabilities."
        )
    if package_json_dirs and not has_npm_lock:
        warnings.append(
            "package.json found without a package-lock.json / yarn.lock, so npm dependency "
            "versions could not be checked."
        )

    unique = list({(d.ecosystem, d.name.lower(), d.version, d.manifest): d for d in deps}.values())
    logger.info("Collected %d pinned dependencies", len(unique))
    return unique, warnings


# --------------------------------------------------------------------------- OSV lookup

def _vtuple(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.\-+]", version.lstrip("v")))


def _fixed_version(vuln: dict, dep: Dependency) -> str | None:
    """Smallest 'fixed' version above the installed one, for this package."""
    fixes = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != dep.name.lower() or pkg.get("ecosystem") != dep.ecosystem:
            continue
        for rng in affected.get("ranges", []):
            fixes += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    try:
        above = [f for f in fixes if _vtuple(f) > _vtuple(dep.version)]
        return min(above or fixes, key=_vtuple) if fixes else None
    except TypeError:  # mixed numeric / text version parts
        return fixes[0] if fixes else None


def _severity(vuln: dict) -> str:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in SEVERITY_MAP:
        return SEVERITY_MAP[label.upper()]
    for affected in vuln.get("affected", []):
        label = (affected.get("ecosystem_specific") or {}).get("severity")
        if isinstance(label, str) and label.upper() in SEVERITY_MAP:
            return SEVERITY_MAP[label.upper()]
    return "medium"


async def _query_osv(http: httpx.AsyncClient, deps: list[Dependency]) -> dict[Dependency, list[str]]:
    hits: dict[Dependency, list[str]] = {}
    for start in range(0, len(deps), 1000):  # OSV batch limit
        chunk = deps[start:start + 1000]
        body = {"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk
        ]}
        # One dropped connection must not wipe out the whole dependency check
        for attempt in range(3):
            try:
                res = await http.post(OSV_BATCH_URL, json=body)
                res.raise_for_status()
                break
            except httpx.HTTPError:
                if attempt == 2:
                    raise
                await asyncio.sleep(2 * (attempt + 1))
        for dep, result in zip(chunk, res.json().get("results", [])):
            ids = [v["id"] for v in result.get("vulns", [])]
            if ids:
                hits[dep] = ids
    return hits


async def _fetch_details(http: httpx.AsyncClient, ids: list[str]) -> dict[str, dict]:
    semaphore = asyncio.Semaphore(10)

    async def fetch(vuln_id: str) -> tuple[str, dict]:
        async with semaphore:
            for attempt in range(3):
                try:
                    res = await http.get(OSV_VULN_URL.format(id=vuln_id))
                    res.raise_for_status()
                    return vuln_id, res.json()
                except httpx.HTTPError as e:
                    if attempt == 2:
                        logger.warning("OSV details failed for %s: %s", vuln_id, repr(e))
                    else:
                        await asyncio.sleep(1 + attempt)
            return vuln_id, {"id": vuln_id}

    return dict(await asyncio.gather(*[fetch(i) for i in ids[:MAX_VULN_DETAILS]]))


def _to_finding(index: int, dep: Dependency, vuln: dict) -> Vulnerability:
    vuln_id = vuln.get("id", "unknown")
    aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    summary = vuln.get("summary") or (vuln.get("details") or "").split("\n")[0][:200] or vuln_id
    severity = _severity(vuln)
    fixed = _fixed_version(vuln, dep)
    refs = [f"https://osv.dev/vulnerability/{vuln_id}"]
    refs += [r["url"] for r in vuln.get("references", []) if r.get("type") in ("ADVISORY", "FIX", "WEB")][:3]

    details = (vuln.get("details") or summary).strip()
    if len(details) > 1200:
        details = details[:1200].rsplit(" ", 1)[0] + "…"
    upgrade = f"Upgrade {dep.name} to {fixed} or later." if fixed else "No fixed version is published yet; consider an alternative package or mitigations from the advisory."

    return Vulnerability(
        id=f"dep_{index:03d}",
        title=f"{dep.name} {dep.version}: {summary}",
        severity=severity,
        scanner_severity=severity,
        file=dep.manifest,
        line=dep.line,
        end_line=dep.line,
        rule_id=vuln_id + (f" ({', '.join(aliases)})" if aliases else ""),
        vulnerable_code=f"{dep.name} {dep.version}",
        fixed_code=f"{dep.name} {fixed}" if fixed else "",
        ai_explanation=f"{details}\n\n{upgrade}",
        attack_scenario="",
        business_impact="Attackers routinely scan for applications running package versions with published advisories.",
        fix_time_estimate="15 minutes" if fixed else "Varies",
        confidence=0.95,
        false_positive_likelihood=0.1,  # vulnerable code path may be unused
        category=FindingCategory.DEPENDENCY,
        source="osv",
        package=dep.name,
        installed_version=dep.version,
        fixed_version=fixed,
        references=refs,
    )


async def scan_dependencies(repo_path: Path) -> tuple[list[Vulnerability], list[str]]:
    """Return (findings, warnings). Network problems become warnings, not failures."""
    deps, warnings = collect_dependencies(repo_path)
    if not deps:
        return [], warnings

    try:
        async with httpx.AsyncClient(timeout=60) as http:
            hits = await _query_osv(http, deps)
            all_ids = sorted({i for ids in hits.values() for i in ids})
            details = await _fetch_details(http, all_ids)
    except httpx.HTTPError as e:
        logger.error("OSV query failed: %s", e)
        return [], warnings + [f"Dependency check skipped: could not reach OSV.dev ({e})"]

    if len(all_ids) > MAX_VULN_DETAILS:
        warnings.append(f"Only the first {MAX_VULN_DETAILS} of {len(all_ids)} advisories were fetched in detail.")

    findings: list[Vulnerability] = []
    for dep, ids in hits.items():
        for vuln_id in ids:
            findings.append(_to_finding(len(findings) + 1, dep, details.get(vuln_id, {"id": vuln_id})))

    findings.sort(key=lambda v: -SEVERITY_ORDER.get(v.severity, 0))
    logger.info("Dependency scan: %d deps checked, %d vulnerable, %d advisories",
                len(deps), len(hits), len(findings))
    return findings, warnings
