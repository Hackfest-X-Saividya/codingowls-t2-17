"""Fix validation for single findings of any kind: code (any language), dependencies, secrets.

Findings that belong to a Python attack chain get the deeper chain checks
(fix_validation.ChainTarget); every other finding is validated here with the same
loop (fix_validation.run_loop: carry-forward revisions, early stopping):

  code        first fix: the scan's AI-suggested code, placed on the flagged lines.
              verified by re-running Semgrep on the file (original vs fixed): the
              finding's rule must no longer match where it did; no new findings;
              the file still parses; Python files keep their names and imports.
  dependency  first fix: pin the package to the advisory's fixed version
              (requirements*.txt, go.mod). npm lockfiles are never edited by hand: the
              range in package.json is raised (an `overrides` entry for packages other
              packages pull in) and npm regenerates the lockfile in a throwaway copy.
              Verified by re-querying OSV.dev; if the new version has advisories of
              its own, the next revision moves past them.
  secret      first fix: read the value from an environment variable instead
              (Python / JavaScript assignments). Verified by re-running the secret
              scanner and checking the value is gone from the file. The exposed
              credential still has to be rotated; no code change can do that.

Later revisions come from the LLM, given the current code and the failure evidence.
"""
from __future__ import annotations

import ast
import asyncio
import json
import logging
import re
import shutil
import subprocess
import textwrap
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional

from models.schemas import (
    ChainFix, Evidence, EvidenceKind, FindingCategory, FixEdit, NewIssue, ValidationAttempt, ValidationCheck,
    ValidationStatus, Vulnerability,
)
from services import fix_planner, secret_scanner
from services.fix_validation import Scanner, edits_between, python_regressions
from utils import sandbox

logger = logging.getLogger(__name__)

# Predefined strategies for single findings (fix_planner.choose keeps their record)
DEPENDENCY_UPGRADE, SECRET_ENV, SCAN_SUGGESTION = "template:dependency-upgrade", "template:secret-env", "scan-suggestion"

PLACEHOLDER_FIX = re.compile(r"AI enhancement unavailable|set GROQ_API_KEY", re.I)
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}

FINDING_FIX_PROMPT = """\
You are a senior application security engineer fixing one vulnerability.

## Finding
- {title}
- Rule: {rule_id} ({category})
- File: {file}, around line {line}
{explanation}

## Code (current version, including earlier attempts' changes; line numbers are exact)
{code}

## Previous attempts and why they failed
{history}

## Lessons from validated fixes of similar problems (other code; do not copy, adapt the approach)
{lessons}

Propose the smallest change to {file} that removes this vulnerability without changing what the code does.
Earlier attempts' changes are already in the code; only add what is still missing or wrong.
Your fix must differ from every previous attempt. Avoid approaches that the lessons show failing.
Use APIs that exist in current library versions.{extra}

Respond with JSON only, replacing every <...> placeholder:
{{
  "strategy": "<what the change does, in one sentence>",
  "rationale": "<why this removes the vulnerability>",
  "edits": [{{"file": "{file}", "start_line": <first line>, "end_line": <last line>, "replacement": "<new text for those lines, with indentation>"}}]
}}
"""


@dataclass
class FindingTarget:
    finding: Vulnerability
    root: Path
    languages: list[str]
    scanner: Optional[Scanner]
    use_ai: bool = False
    developer_fix: Optional[ChainFix] = None
    all_findings: list[Vulnerability] = field(default_factory=list)
    lessons: str = ""  # outcomes of similar fixes elsewhere (validation_history.lessons), for the LLM
    strategy_stats: dict = field(default_factory=dict)  # per-strategy record in comparable cases (fix_planner.choose)
    _before: Optional[tuple[list[Vulnerability], Optional[str]]] = None

    # ---------- Target protocol ----------

    def not_reproducible(self) -> Optional[str]:
        if not (self.root / self.finding.file).is_file():
            return f"{self.finding.file} no longer exists in the scanned code. Re-scan the repository."
        return None

    def no_fix_message(self) -> Optional[str]:
        """Why no first fix could be generated, where there is a more specific reason than the default."""
        f = self.finding
        if f.category != FindingCategory.DEPENDENCY:
            return None
        if not f.fixed_version:
            return (f"No fixed version of {f.package} has been published for this advisory, so there is nothing "
                    "to upgrade to. Replace the package or apply the mitigations in the advisory.")
        name = PurePosixPath(f.file).name
        if name in NPM_LOCKFILES and not shutil.which("npm"):
            return f"Upgrading {f.package} needs npm to regenerate {name}, and npm is not installed on the server."
        if name in NPM_LOCKFILES:
            return (f"npm could not upgrade {f.package} to {f.fixed_version} (see the backend log). "
                    f"Try `npm install {f.package}@^{f.fixed_version}` in {PurePosixPath(f.file).parent}.")
        if name.lower() not in ("go.mod",) and not re.search(r"requirements[^/]*\.(txt|in)$", f.file, re.I):
            return (f"{name} is maintained by its package manager, so it is not edited automatically. "
                    f"Upgrade {f.package} to {f.fixed_version} with that package manager.")
        return None

    async def first_fix(self) -> Optional[ChainFix]:
        if self.developer_fix:
            return self.developer_fix
        f = self.finding
        value = fix_planner._value
        if f.category == FindingCategory.DEPENDENCY:
            # In a thread: an npm lockfile is regenerated by npm, which takes a while
            candidates = [(DEPENDENCY_UPGRADE, lambda: asyncio.to_thread(dependency_fix, f, self.root, f.fixed_version))]
        elif f.category == FindingCategory.SECRET:
            candidates = [(SECRET_ENV, lambda: value(secret_fix(f, self.root)))]
        else:
            candidates = [(SCAN_SUGGESTION, lambda: value(snippet_fix(f, self.root)))]
        if self.use_ai and f.category != FindingCategory.DEPENDENCY:
            candidates.append(("ai", lambda: self._ai_fix(self.root, [])))
        return await fix_planner.choose(candidates, [], self.strategy_stats, lambda fix: bool(fix and fix.edits))

    async def next_fix(self, current: Path, history: list[ValidationAttempt]) -> Optional[ChainFix]:
        tried = {fix_planner._edits_key(a.fix.edits) for a in history}
        candidates: list[fix_planner.Candidate] = []
        if self.finding.category == FindingCategory.DEPENDENCY:
            remaining = [s for s in history[-1].remaining_signatures if s.get("fixed_version")]
            if remaining:
                sig = max(remaining, key=lambda s: _vtuple(s["fixed_version"]))
                candidates.append((DEPENDENCY_UPGRADE, lambda: asyncio.to_thread(
                    dependency_fix, self.finding, current, sig["fixed_version"], sig.get("installed_version"))))
        elif self.use_ai:
            candidates.append(("ai", lambda: self._ai_fix(current, history)))
        return await fix_planner.choose(candidates, history, self.strategy_stats,
                                        lambda fix: bool(fix and fix.edits and fix_planner._edits_key(fix.edits) not in tried))

    async def evaluate(self, fix: ChainFix, attempt_no: int, patched: Path, changed: list[str]) -> ValidationAttempt:
        f = self.finding
        attempt = ValidationAttempt(attempt=attempt_no, fix=fix, status=ValidationStatus.INCONCLUSIVE, summary="")
        syntax = await asyncio.to_thread(syntax_check, patched, changed)
        attempt.checks.append(syntax)
        if syntax.status == "failed":
            attempt.regressions += [f"{e.file}:{e.line or '-'} {e.description}" for e in syntax.evidence]
            attempt.checks.append(ValidationCheck(name="reproduce_original", status="error",
                                                  detail="The changed file does not parse, so it could not be re-checked."))
            decide_finding(attempt)
            return attempt

        changed_lines = _changed_lines(self.root, patched, f.file)
        if f.category == FindingCategory.DEPENDENCY:
            await self._recheck_dependency(patched, attempt)
        elif f.category == FindingCategory.SECRET:
            await asyncio.to_thread(self._recheck_secret, patched, changed, changed_lines, attempt)
        else:
            await self._recheck_code(patched, changed_lines, attempt)

        problems = []
        for rel in changed:
            if rel.endswith(".py") and (self.root / rel).is_file() and (patched / rel).is_file():
                problems += python_regressions(rel, _read(self.root / rel), _read(patched / rel))
        attempt.regressions += [f"{e.file}:{e.line or '-'} {e.description}" for e in problems]
        attempt.checks.append(ValidationCheck(
            name="regression_static", status="failed" if problems else "passed",
            detail=f"{len(problems)} regression(s)" if problems else "Changed files keep their names, imports and functions",
            evidence=problems))
        decide_finding(attempt)
        return attempt

    # ---------- re-checks ----------

    async def _recheck_code(self, patched: Path, changed_lines: set[int], attempt: ValidationAttempt) -> None:
        f = self.finding
        if self.scanner is None:
            attempt.checks.append(ValidationCheck(name="reproduce_original", status="error", infrastructure=True,
                                                  detail="The security scanner is not available."))
            return
        if self._before is None:
            self._before = await self.scanner(self.root, [f.file], self.languages)
        (before, err_a), (after, err_b) = self._before, await self.scanner(patched, [f.file], self.languages)
        if err_a or err_b:
            attempt.checks.append(ValidationCheck(name="reproduce_original", status="error", infrastructure=True,
                                                  detail=err_a or err_b or ""))
            return
        if not any(v.rule_id == f.rule_id for v in before):
            attempt.checks.append(ValidationCheck(
                name="reproduce_original", status="error",
                detail="The scanner no longer reports this finding on the original code, so the fix cannot be confirmed."))
            return
        flagged = _line(self.root / f.file, f.line).strip()
        persisting = [v for v in after if v.rule_id == f.rule_id
                      and (v.line in changed_lines or _line(patched / f.file, v.line).strip() == flagged)]
        attempt.remaining_paths = [f"{_short(v.rule_id)} still matches at {v.file}:{v.line}" for v in persisting]
        attempt.checks.append(ValidationCheck(
            name="reproduce_original", status="failed" if persisting else "passed",
            detail=(f"The {_short(f.rule_id)} rule still matches {len(persisting)} time(s)" if persisting
                    else f"The {_short(f.rule_id)} rule no longer matches the fixed code"),
            evidence=[Evidence(kind=EvidenceKind.SCANNER, file=v.file, line=v.line, code=_line(patched / v.file, v.line).strip(),
                               description=f"{_short(v.rule_id)} still matches") for v in persisting]))

        def key(v: Vulnerability, root: Path) -> tuple[str, str]:
            return (v.rule_id, _line(root / v.file, v.line).strip())
        known = {key(v, self.root) for v in before}
        for v in after:
            if v.rule_id != f.rule_id and key(v, patched) not in known:
                attempt.new_issues.append(NewIssue(
                    description=f"New scanner finding {_short(v.rule_id)}: {v.title}", file=v.file, line=v.line,
                    origin="scanner", relation="extends_chain" if v.line in changed_lines else "unrelated"))

    def _recheck_secret(self, patched: Path, changed: list[str], changed_lines: set[int], attempt: ValidationAttempt) -> None:
        f = self.finding
        after, _ = secret_scanner.scan_secrets(patched)
        before_keys = {(v.file, v.rule_id, v.vulnerable_code) for v in secret_scanner.scan_secrets(self.root)[0]
                       if v.file in changed}
        original_line = _line(self.root / f.file, f.line)
        persisting = [v for v in after if v.file == f.file and v.rule_id == f.rule_id
                      and (v.line in changed_lines or _line(patched / v.file, v.line) == original_line)]
        value = _secret_value(original_line, f.rule_id)
        if value and value in _read(patched / f.file):
            persisting.append(f)
        attempt.remaining_paths = [f"the secret is still in {f.file}"] if persisting else []
        attempt.checks.append(ValidationCheck(
            name="reproduce_original", status="failed" if persisting else "passed",
            detail="The secret value is still in the file" if persisting else "The secret value is no longer in the code"))
        for v in after:
            if v.file in changed and (v.file, v.rule_id, v.vulnerable_code) not in before_keys and v not in persisting:
                attempt.new_issues.append(NewIssue(description=f"New hardcoded secret: {v.title}", file=v.file,
                                                   line=v.line, origin="scanner", relation="unrelated"))

    async def _recheck_dependency(self, patched: Path, attempt: ValidationAttempt) -> None:
        from services import dependency_scanner

        f = self.finding
        findings, warnings = await dependency_scanner.scan_dependencies(patched)
        if any("could not reach OSV" in w for w in warnings):
            attempt.checks.append(ValidationCheck(name="reproduce_original", status="error", infrastructure=True,
                                                  detail="The vulnerability database (OSV.dev) could not be reached."))
            return
        pkg = (f.package or "").lower()
        same = [d for d in findings if (d.package or "").lower() == pkg and d.file == f.file]
        persisting = [d for d in same if d.rule_id == f.rule_id]
        known = {d.rule_id for d in self.all_findings if (d.package or "").lower() == pkg}
        attempt.remaining_paths = [f"{f.package} {d.installed_version} is still affected by {d.rule_id}" for d in persisting]
        attempt.checks.append(ValidationCheck(
            name="reproduce_original", status="failed" if persisting else "passed",
            detail=(f"{f.package} is still affected by {f.rule_id}" if persisting
                    else f"{f.package} {same[0].installed_version if same else ''} is no longer affected by {f.rule_id}".replace("  ", " "))))
        for d in same:
            if d.rule_id not in known:
                attempt.new_issues.append(NewIssue(
                    description=f"{d.package} {d.installed_version} has another advisory: {d.rule_id}",
                    file=d.file, line=d.line, origin="scanner", relation="extends_chain"))
            if d.fixed_version:
                attempt.remaining_signatures.append({"fixed_version": d.fixed_version,
                                                     "installed_version": d.installed_version})

    # ---------- AI ----------

    async def _ai_fix(self, current: Path, history: list[ValidationAttempt]) -> Optional[ChainFix]:
        from services import ai_enhancer
        from utils.config import settings

        if not settings.GROQ_API_KEY:
            return None
        import httpx

        f = self.finding
        center = f.line
        for a in reversed(history):  # where the last attempt still saw the problem
            lines = [e.line for c in a.checks for e in c.evidence if e.line and e.file == f.file]
            if lines:
                center = lines[0]
                break
        code = _numbered(current / f.file, center)
        if f.category == FindingCategory.SECRET:
            code = secret_scanner.mask_secrets(code)
        prompt = FINDING_FIX_PROMPT.format(
            title=f.title, rule_id=f.rule_id, category=f.category.value, file=f.file, line=center,
            explanation=(f.ai_explanation or "")[:800], code=code,
            history=fix_planner._describe_history(history) or "(none)", lessons=self.lessons or "(none)",
            extra=(" Replace the hardcoded secret with a value read from an environment variable."
                   if f.category == FindingCategory.SECRET else ""),
        )
        try:
            async with httpx.AsyncClient(timeout=90) as http:
                data = ai_enhancer._parse_ai_response((await ai_enhancer._groq_complete(http, prompt)).strip())
        except Exception as e:
            logger.warning("AI fix for finding %s failed: %s", f.id, e)
            return None
        edits = []
        for raw in data.get("edits") or []:
            edit = fix_planner._checked_edit(current, raw, allowed={f.file})
            if edit is None:
                return None
            edits.append(edit)
        if not edits:
            return None
        return ChainFix(strategy=str(data.get("strategy", "AI-suggested fix"))[:200], break_point=f.id,
                        target_nodes=[f.id], rationale=str(data.get("rationale", ""))[:1500], edits=edits, origin="ai",
                        strategy_id="ai")


# ---------- first fixes ----------

def snippet_fix(f: Vulnerability, root: Path) -> Optional[ChainFix]:
    """Place the scan's AI-suggested code on the lines it was written for."""
    fixed = fix_planner_strip(f.fixed_code)
    if not fixed.strip() or PLACEHOLDER_FIX.search(fixed) or not f.vulnerable_code.strip():
        return None
    lines = _read(root / f.file).replace("\r\n", "\n").split("\n")
    wanted = [l.strip() for l in f.vulnerable_code.splitlines() if l.strip()]
    nonblank = [(i, l.strip()) for i, l in enumerate(lines) if l.strip()]
    starts = [k for k in range(len(nonblank) - len(wanted) + 1)
              if [t for _, t in nonblank[k:k + len(wanted)]] == wanted]
    if not starts:
        return None
    k = min(starts, key=lambda s: abs(nonblank[s][0] + 1 - f.line))
    start, end = nonblank[k][0] + 1, nonblank[k + len(wanted) - 1][0] + 1
    first = lines[start - 1]
    indent = first[: len(first) - len(first.lstrip())]
    body = textwrap.dedent(fixed).strip("\n").split("\n")
    replacement = "\n".join(indent + l if l.strip() else "" for l in body)
    original = "\n".join(lines[start - 1:end])
    if replacement.strip() == original.strip():
        return None
    return ChainFix(strategy="Apply the suggested fix to the flagged code", break_point=f.id, target_nodes=[f.id],
                    rationale="The scan's suggested fix, placed on the lines it was written for.",
                    edits=[FixEdit(file=f.file, start_line=start, end_line=end, original=original, replacement=replacement)],
                    origin="ai", strategy_id=SCAN_SUGGESTION)


def dependency_fix(f: Vulnerability, root: Path, version: Optional[str],
                   installed: Optional[str] = None) -> Optional[ChainFix]:
    """Upgrade the package to `version`: pinned in requirements*.txt or go.mod, through npm for
    package-lock.json. `installed` is the affected copy's version (default: the finding's)."""
    if not version or not f.package:
        return None
    path = root / f.file
    if not path.is_file():
        return None
    lines = _read(path).replace("\r\n", "\n").split("\n")
    name = re.escape(f.package)
    if re.search(r"requirements[^/]*\.(txt|in)$", f.file, re.I):
        pattern = re.compile(rf"^(\s*{name}\s*(?:\[[^\]]*\])?\s*==\s*)([^\s;#]+)(.*)$", re.I)
        new_version = version
    elif f.file.endswith("go.mod"):
        pattern = re.compile(rf"^(\s*(?:require\s+)?{name}\s+)(v[^\s]+)(.*)$")
        new_version = version if version.startswith("v") else f"v{version}"
    elif PurePosixPath(f.file).name in NPM_LOCKFILES:
        return npm_dependency_fix(f, root, version, installed or f.installed_version)
    else:
        return None  # other lockfiles need their package manager to regenerate them
    for i, line in enumerate(lines, 1):
        m = pattern.match(line)
        if m and m.group(2) != new_version:
            return ChainFix(
                strategy=f"Upgrade {f.package} to {new_version}", break_point=f.id, target_nodes=[f.id],
                rationale=f"{new_version} is the first version not affected by {f.rule_id}.",
                edits=[FixEdit(file=f.file, start_line=i, end_line=i, original=line,
                               replacement=f"{m.group(1)}{new_version}{m.group(3)}")],
                origin="template", strategy_id=DEPENDENCY_UPGRADE)
    return None


NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
NPM_TIMEOUT_SECONDS = 180


def npm_dependency_fix(f: Vulnerability, root: Path, version: str, installed: Optional[str]) -> Optional[ChainFix]:
    """Upgrade a package of an npm project: raise its range in package.json (direct dependency)
    or add an `overrides` entry (pulled in by other packages), then let npm regenerate the
    lockfile. npm runs on a throwaway copy with --package-lock-only --ignore-scripts, so nothing
    is installed and no package scripts run. The fix is the resulting change to both files."""
    lock = root / f.file
    project = lock.parent
    manifest = project / "package.json"
    if not manifest.is_file():
        return None
    text = _read(manifest)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    pkg, wanted = f.package, f"^{version.lstrip('v')}"
    section = next((s for s in NPM_SECTIONS if isinstance(data.get(s), dict) and pkg in data[s]), None)
    if section:
        if data[section][pkg] == wanted:
            return None
        data[section][pkg] = wanted
        strategy = f"Upgrade {pkg} to {wanted} in package.json and regenerate {lock.name}"
    else:
        # Scoped to the affected copy's major version: a tree can hold several (minimatch 5 needs
        # brace-expansion 2 while older packages use 1), and each major line is fixed separately
        overrides = data.get("overrides") if isinstance(data.get("overrides"), dict) else {}
        major = re.match(r"\d+", (installed or version).lstrip("v"))
        key = f"{pkg}@^{major.group()}" if major else pkg
        if overrides.get(key) == wanted:
            return None
        overrides[key] = wanted
        data["overrides"] = overrides
        strategy = f"Override {pkg} to {wanted} (other packages pull it in) and regenerate {lock.name}"
    indent = (re.search(r"^[ \t]+(?=\")", text, re.M) or [None])[0] or "  "
    newline = "\r\n" if "\r\n" in text else "\n"

    from utils.config import settings

    work = settings.TEMP_DIR / "npm-resolve" / uuid.uuid4().hex[:12]
    try:
        sandbox.copy_tree(project, work)
        (work / "package.json").write_bytes((json.dumps(data, indent=indent, ensure_ascii=False) + "\n")
                                            .replace("\n", newline).encode("utf-8"))
        if not _npm_lock_only(work):
            return None
        edits = edits_between(project, work, ["package.json", lock.name])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not edits:
        return None
    prefix = PurePosixPath(f.file).parent
    return ChainFix(
        strategy=strategy, break_point=f.id, target_nodes=[f.id],
        rationale=f"{version} is the first version not affected by {f.rule_id}. npm regenerated {lock.name}, "
                  "so its integrity hashes and dependency tree stay consistent.",
        edits=[e.model_copy(update={"file": (prefix / e.file).as_posix()}) for e in edits],
        origin="template", strategy_id=DEPENDENCY_UPGRADE)


def _npm_lock_only(work: Path) -> bool:
    """Regenerate package-lock.json in `work` from its package.json. False if npm is missing or fails."""
    npm = shutil.which("npm")
    if not npm:
        logger.warning("npm is not installed; npm dependency fixes are unavailable")
        return False
    base = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    # Peer-dependency conflicts the project already has would block the upgrade; retry like npm 6 did
    for extra in ([], ["--legacy-peer-deps"]):
        try:
            proc = subprocess.run(base + extra, cwd=work, env=sandbox.restricted_env(), capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=NPM_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.info("npm could not regenerate the lockfile: %s", e)
            return False
        if proc.returncode == 0:
            return True
        if "ERESOLVE" not in proc.stderr:
            break
    logger.info("npm could not regenerate the lockfile: %s", proc.stderr.strip()[-500:])
    return False


SECRET_ASSIGNMENT = re.compile(
    r"""^(?P<indent>\s*)(?P<decl>(?:export\s+)?(?:const|let|var)\s+)?(?P<name>[A-Za-z_]\w*)(?P<sep>\s*[:=]\s*)"""
    r"""(?P<q>["'])(?P<value>.*?)(?P=q)(?P<tail>\s*[;,]?\s*(?:#.*|//.*)?)$""")


def secret_fix(f: Vulnerability, root: Path) -> Optional[ChainFix]:
    """Read the value from an environment variable instead of the source code."""
    path = root / f.file
    line = _line(path, f.line)
    m = SECRET_ASSIGNMENT.match(line)
    ext = path.suffix.lower()
    if not m or (ext != ".py" and ext not in JS_EXT):
        return None
    env = re.sub(r"[^A-Za-z0-9]", "_", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", m["name"])).upper()
    value = f'os.environ.get("{env}", "")' if ext == ".py" else f'process.env.{env} || ""'
    new_line = f"{m['indent']}{m['decl'] or ''}{m['name']}{m['sep']}{value}{m['tail']}"
    edits = [FixEdit(file=f.file, start_line=f.line, end_line=f.line, original=line, replacement=new_line)]
    if ext == ".py":
        try:
            imp = fix_planner._Source(root, f.file).add_import("import os", "os")
        except SyntaxError:
            imp = None
        if imp and imp.start_line != f.line:
            edits.append(imp)
    return ChainFix(strategy=f"Read {m['name']} from the {env} environment variable", break_point=f.id,
                    target_nodes=[f.id],
                    rationale="Keeps the credential out of the code. It was already exposed, so rotate it as well.",
                    edits=edits, origin="template", strategy_id=SECRET_ENV)


# ---------- checks ----------

def syntax_check(root: Path, files: list[str]) -> ValidationCheck:
    """Parse each changed file with the language's own checker where one is available."""
    problems: list[Evidence] = []
    checked = 0
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        try:
            if ext == ".py":
                ast.parse(_read(path), filename=rel)
            elif ext == ".json":
                json.loads(_read(path))
            elif ext in (".js", ".mjs", ".cjs") and shutil.which("node"):
                rc, out = sandbox.run_command(["node", "--check", str(path)], root, 30)
                if rc != 0:
                    problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, description=f"node --check: {out.strip()[-300:]}"))
            elif ext == ".php" and shutil.which("php"):
                rc, out = sandbox.run_command(["php", "-l", str(path)], root, 30)
                if rc != 0:
                    problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, description=f"php -l: {out.strip()[-300:]}"))
            elif ext == ".rb" and shutil.which("ruby"):
                rc, out = sandbox.run_command(["ruby", "-c", str(path)], root, 30)
                if rc != 0:
                    problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, description=f"ruby -c: {out.strip()[-300:]}"))
            else:
                continue
            checked += 1
        except SyntaxError as e:
            checked += 1
            problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=e.lineno, code=(e.text or "").strip(),
                                     description=f"SyntaxError: {e.msg}"))
        except ValueError as e:
            checked += 1
            problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, description=f"Invalid JSON: {e}"))
    if problems:
        return ValidationCheck(name="syntax", status="failed", detail=f"{len(problems)} file(s) no longer parse",
                               evidence=problems)
    if not checked:
        return ValidationCheck(name="syntax", status="skipped", detail="No syntax checker for these file types")
    return ValidationCheck(name="syntax", status="passed", detail=f"{checked} changed file(s) parse")


def decide_finding(attempt: ValidationAttempt) -> None:
    by_name = {c.name: c for c in attempt.checks}
    reproduce = by_name.get("reproduce_original")
    executed = [c.name for c in attempt.checks if c.status in ("passed", "failed")]
    attempt.scope = f"Checked: {', '.join(executed)}. No exploit was executed against a running app."
    if by_name.get("syntax") and by_name["syntax"].status == "failed":
        attempt.status = ValidationStatus.FAIL
        attempt.summary = "The fix breaks the code (it no longer parses)."
    elif reproduce is None or reproduce.status == "error":
        attempt.status = ValidationStatus.INCONCLUSIVE
        attempt.summary = f"The problem could not be re-checked: {reproduce.detail if reproduce else 'no check ran'}"
    elif reproduce.status == "failed":
        attempt.status = ValidationStatus.FAIL
        attempt.summary = f"The problem is still there: {reproduce.detail}."
    elif attempt.regressions:
        attempt.status = ValidationStatus.FAIL
        attempt.summary = "The problem is gone, but the fix breaks something else: " + "; ".join(attempt.regressions[:3])
    elif attempt.new_issues:
        attempt.status = ValidationStatus.NEW_VULNERABILITY
        attempt.summary = "The problem is gone, but the fix adds: " + "; ".join(i.description for i in attempt.new_issues[:3])
    else:
        attempt.status = ValidationStatus.PASS
        attempt.summary = "The problem is no longer reported and nothing else broke (within the checks performed)."


# ---------- helpers ----------

def fix_planner_strip(text: str) -> str:
    lines = [l for l in (text or "").replace("\r\n", "\n").split("\n") if not l.strip().startswith("```")]
    return "\n".join(lines)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace") if path.is_file() else ""


def _line(path: Path, n: int) -> str:
    lines = _read(path).replace("\r\n", "\n").split("\n")
    return lines[n - 1] if 0 < n <= len(lines) else ""


def _changed_lines(original: Path, patched: Path, rel: str) -> set[int]:
    """Lines of the patched file inside (or next to) a change, 1-based."""
    import difflib

    a = _read(original / rel).replace("\r\n", "\n").split("\n")
    b = _read(patched / rel).replace("\r\n", "\n").split("\n")
    out: set[int] = set()
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag != "equal":
            out |= set(range(max(j1, 1), j2 + 2))
    return out


def _numbered(path: Path, center: int, radius: int = 30) -> str:
    lines = _read(path).replace("\r\n", "\n").split("\n")
    shown = sorted(set(range(1, min(15, len(lines)) + 1)) | set(range(max(1, center - radius), min(len(lines), center + radius) + 1)))
    out, prev = [], 0
    for n in shown:
        if prev and n != prev + 1:
            out.append("    ...")
        out.append(f"{n:4d}| {lines[n - 1]}")
        prev = n
    return "\n".join(out)


def _secret_value(line: str, rule_id: str) -> str:
    slug = rule_id.split("/", 1)[-1]
    for rule in secret_scanner.RULES:
        if rule.slug == slug:
            m = rule.pattern.search(line)
            if m:
                return m.group(rule.group) if rule.group else m.group(0)
    return ""


def _short(rule_id: str) -> str:
    return rule_id.split(".")[-1]


def _vtuple(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+]", version.lstrip("v")))
