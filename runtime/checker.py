"""Find code that fails when it runs, without running it.

A scanned repository is untrusted and there is no container per scan, so its code is
never executed or imported here. Everything is read from the source, in-process; the
only other process is one short-lived `node` that parses (compiles, never runs) every
JavaScript file at once, and only if Node is installed.

  Python      SyntaxError: the module cannot be imported at all
              NameError / UnboundLocalError: names used but never defined (pyflakes)
              ImportError: relative or in-repo imports of modules / names that do not exist
              TypeError: calls to functions and classes defined in the repo with the wrong
                         arguments; `raise NotImplemented`
              format strings whose arguments do not match their placeholders
  JavaScript  SyntaxError in .js / .mjs / .cjs files (JSX and Flow files are skipped)

Third-party imports are not checked: whether a package is installed (directly or
through another package) is only known on the machine that runs the code. Errors that
depend on data, configuration or library versions show up only at run time.

Usage:  python checker.py <folder> [--json] [--fail-on low|medium|high]
"""
from __future__ import annotations

import argparse
import ast
import builtins
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from pyflakes import checker as pyflakes_checker, messages as pyflakes_messages

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000
MAX_PROBLEMS = 200
NODE_TIMEOUT_SECONDS = 60
SKIP_DIRS = {"node_modules", "venv", "env", "__pycache__", "dist", "build", "vendor", "site-packages",
             "coverage", "out",  # plus every hidden directory (.git, .venv, .next, .tox, ...)
             # Documentation snippets and test inputs are often incomplete or broken on purpose
             "docs", "docs_src", "fixtures", "testdata", "test_data", "test-data"}
TEST_DIRS = {"tests", "test"}  # whose data/ folders hold test inputs
SUPPRESSED = re.compile(r"#\s*(noqa(?![a-z])|type:\s*ignore)", re.I)
# Attributes every module has, so `from module import __file__` works
MODULE_DUNDERS = {"__file__", "__name__", "__doc__", "__spec__", "__loader__", "__package__", "__builtins__",
                  "__cached__", "__dict__", "__path__", "__annotations__"}
# What a try/except around the problem must catch for the error to be expected
CAUGHT_BY = {
    "undefined-name": {"NameError"},
    "undefined-local": {"UnboundLocalError", "NameError"},
    "call-arguments": {"TypeError"},
    "format-string": {"TypeError", "KeyError", "ValueError", "IndexError"},
}
JS_EXT = (".js", ".mjs", ".cjs")
STUB_EXT = (".pyi", ".so", ".pyd")
STDLIB = set(sys.stdlib_module_names) | {"__future__"}
# Builtin exceptions add no metaclass, so a subclass is constructed through its own __init__
EXCEPTION_BASES = {n for n, v in vars(builtins).items() if isinstance(v, type) and issubclass(v, BaseException)}
# Builtins of newer Pythons than the one running the check, so their code is not flagged
NEWER_BUILTINS = {"ExceptionGroup", "BaseExceptionGroup", "EncodingWarning", "aiter", "anext",
                  "PythonFinalizationError", "frozendict"}
PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}"
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
# Enough for Node to start; nothing that carries credentials
SAFE_ENV_KEYS = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
                 "HOME", "USERPROFILE", "LANG", "LC_ALL")


@dataclass(frozen=True)
class Rule:
    slug: str
    error: str        # what Python / Node raises
    title: str
    severity: str
    confidence: float
    explanation: str  # what happens when the code runs


RULES: dict[str, Rule] = {r.slug: r for r in [
    Rule("syntax-error", "SyntaxError", "File cannot be parsed", "high", 0.95,
         "Python refuses to load this file, so every import of it fails, usually as soon as the application starts."),
    Rule("undefined-name", "NameError", "Name is used but never defined", "medium", 0.85,
         "The line raises NameError when it runs: the name is not defined, imported or a builtin."),
    Rule("undefined-local", "UnboundLocalError", "Local variable used before it is assigned", "medium", 0.85,
         "The function assigns this name later, which makes it local to the whole function, so reading it "
         "before that assignment raises UnboundLocalError instead of using the outer value."),
    Rule("undefined-export", "AttributeError", "__all__ lists a name the module does not define", "low", 0.8,
         "`from module import *` fails with AttributeError because __all__ names something that does not exist."),
    Rule("missing-module", "ModuleNotFoundError", "Import of a module that does not exist", "high", 0.85,
         "The import fails as soon as this file is loaded, so the module (and everything importing it) cannot be used."),
    Rule("missing-name", "ImportError", "Import of a name the module does not define", "high", 0.8,
         "The import fails as soon as this file is loaded: the imported module exists but does not define this name."),
    Rule("call-arguments", "TypeError", "Call does not match the function's parameters", "medium", 0.8,
         "The call raises TypeError when it runs: the arguments do not match the parameters of the function or "
         "class it calls."),
    Rule("format-string", "TypeError / KeyError / ValueError", "Format string does not match its arguments", "low", 0.8,
         "Formatting the string raises an exception: its placeholders and the arguments passed to it do not match."),
    Rule("raise-notimplemented", "TypeError", "`raise NotImplemented` instead of NotImplementedError", "low", 0.9,
         "NotImplemented is a value, not an exception, so raising it fails with TypeError and hides the intended error."),
    Rule("js-syntax-error", "SyntaxError", "File cannot be parsed", "high", 0.9,
         "The JavaScript engine refuses to load this file, so nothing in it runs and every import of it fails."),
]}
LOAD_FAILURES = {"syntax-error", "js-syntax-error", "missing-module", "missing-name"}

PYFLAKES_RULES: dict[str, str] = {
    "UndefinedName": "undefined-name",
    "UndefinedLocal": "undefined-local",
    "UndefinedExport": "undefined-export",
    "RaiseNotImplemented": "raise-notimplemented",
    # Only the format mismatches that raise; extra unused arguments are ignored by Python
    **{name: "format-string" for name in (
        "PercentFormatInvalidFormat", "PercentFormatMixedPositionalAndNamed", "PercentFormatUnsupportedFormatCharacter",
        "PercentFormatPositionalCountMismatch", "PercentFormatMissingArgument", "PercentFormatExpectedMapping",
        "PercentFormatExpectedSequence", "PercentFormatStarRequiresSequence", "StringDotFormatMissingArgument",
        "StringDotFormatMixingAutomatic", "StringDotFormatInvalidFormat")},
}
PYFLAKES_CLASSES = {getattr(pyflakes_messages, name): slug for name, slug in PYFLAKES_RULES.items()
                    if hasattr(pyflakes_messages, name)}


@dataclass
class Problem:
    rule: str
    file: str
    line: int
    message: str


@dataclass
class ModuleInfo:
    """What another module can import from a Python file."""
    names: set[str] = field(default_factory=set)
    dynamic: bool = False  # star import, module __getattr__, globals() writes: names cannot be listed
    signatures: dict[str, ast.arguments] = field(default_factory=dict)  # callable name -> parameters (self dropped)


# ---------- repository index ----------

class RepoIndex:
    """Resolves imports the way Python would, from every import root a file can have: the
    folders above it (its own folder when run as a script, the working directory) and their
    src/ folders (an installed src-layout package). Parsed modules are cached."""

    def __init__(self, root: Path):
        self.root = root
        self._roots: dict[Path, list[Path]] = {}
        self._trees: dict[Path, Optional[ast.Module]] = {}
        self._info: dict[Path, Optional[ModuleInfo]] = {}

    def import_roots(self, importer: Path) -> list[Path]:
        folder = importer.parent
        if folder not in self._roots:
            roots: list[Path] = []
            for d in (folder, *folder.parents):
                roots += [d, d / "src"] if (d / "src").is_dir() else [d]
                if d == self.root:
                    break
            self._roots[folder] = roots
        return self._roots[folder]

    def resolve(self, importer: Path, dotted: str) -> Optional[list[Path]]:
        """Where `import dotted` leads from importer. None when its top-level package is not in the
        repository (standard library or third-party: what is installed is unknown here); an empty
        list when the package is in the repository but the module is not."""
        parts = dotted.split(".")
        if parts[0] in STDLIB:
            return None
        # Only a regular package or a module claims a top-level name: a folder without
        # __init__.py (docs_src/opentelemetry/) loses to an installed package of that name
        homes = [r for r in self.import_roots(importer) if module_at(r, parts[:1], namespace=False)]
        if not homes:
            return None
        return list(dict.fromkeys(m for r in homes if (m := module_at(r, parts))))

    def tree(self, path: Path) -> Optional[ast.Module]:
        if path not in self._trees:
            try:
                self._trees[path] = ast.parse(_read(path), filename=str(path))
            except (SyntaxError, ValueError, RecursionError, MemoryError, OSError):
                self._trees[path] = None
        return self._trees[path]

    def info(self, path: Path) -> Optional[ModuleInfo]:
        if path not in self._info:
            tree = self.tree(path)
            self._info[path] = module_info(tree, path) if tree else None
        return self._info[path]


def module_at(base: Path, parts: list[str], namespace: bool = True) -> Optional[Path]:
    """The module `parts` under base: its .py file, a package's __init__.py, a namespace package's
    folder, or a stub / compiled extension. None if there is none."""
    target = base.joinpath(*parts)
    if target.with_name(target.name + ".py").is_file():
        return target.with_name(target.name + ".py")
    if (target / "__init__.py").is_file():
        return target / "__init__.py"
    if target.parent.is_dir():
        for p in target.parent.iterdir():  # foo.pyi, foo.cpython-312-x86_64-linux-gnu.so
            if p.name.split(".")[0] == target.name and p.name.endswith(STUB_EXT):
                return p
    if namespace and target.is_dir():
        return target
    return None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")  # Python accepts a BOM
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def _source_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirs, files in os.walk(root):
        parts = set(Path(dirpath).relative_to(root).parts)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")
                         and not (d == "data" and parts & TEST_DIRS))
        for name in sorted(files):
            path = Path(dirpath) / name
            if name.endswith(JS_EXT) and "templates" in parts:
                continue  # server-side templates ({% ... %}) that render to JavaScript
            if name.endswith(suffixes) and not name.endswith(".min.js"):
                try:
                    if path.stat().st_size <= MAX_FILE_BYTES:
                        out.append(path)
                except OSError:
                    continue
    return out


# ---------- module contents ----------

def _local_bindings(nodes: list[ast.stmt]) -> list[str]:
    """Names bound by these statements, not looking inside functions, classes or lambdas."""
    names: list[str] = []
    stack: list[ast.AST] = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
            stack.extend(node.decorator_list)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names += [a.asname or a.name.split(".")[0] for a in node.names if a.name != "*"]
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.append(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.append(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)
        stack.extend(ast.iter_child_nodes(node))
    return names


def module_info(tree: ast.Module, path: Path) -> ModuleInfo:
    bindings = _local_bindings(tree.body)
    declared_global = [n for g in ast.walk(tree) if isinstance(g, ast.Global) for n in g.names]
    info = ModuleInfo(names=set(bindings) | set(declared_global) | MODULE_DUNDERS)  # `global x` in a function defines x on the module
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            info.dynamic = True
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id in ("globals", "vars", "setattr", "exec")):
            info.dynamic = True
    if "__getattr__" in info.names:
        info.dynamic = True
    if path.name == "__init__.py":  # submodules are importable from the package
        for child in path.parent.iterdir():
            if child.is_dir():
                info.names.add(child.name)
            elif child.name.endswith((".py",) + STUB_EXT):
                info.names.add(child.name.split(".")[0])

    counts: dict[str, int] = {}
    for name in bindings + declared_global:
        counts[name] = counts.get(name, 0) + 1
    for node in _module_level_defs(tree.body):
        if counts.get(node.name) != 1 or node.decorator_list:
            continue  # redefined or decorated: the decorator may change the signature
        params = _class_parameters(node) if isinstance(node, ast.ClassDef) else node.args
        if params is not None:
            info.signatures[node.name] = params
    return info


def _module_level_defs(body: list[ast.stmt]):
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node
        elif isinstance(node, (ast.If, ast.Try, ast.With)) or type(node).__name__ == "TryStar":
            for block in ("body", "orelse", "finalbody"):
                yield from _module_level_defs(getattr(node, block, []) or [])
            for handler in getattr(node, "handlers", []):
                yield from _module_level_defs(handler.body)


def _class_parameters(node: ast.ClassDef) -> Optional[ast.arguments]:
    """Parameters of calling the class, when they come only from its own __init__."""
    if node.keywords or any(not (isinstance(b, ast.Name) and (b.id == "object" or b.id in EXCEPTION_BASES))
                            for b in node.bases):
        return None  # metaclasses and other bases (Enum, BaseModel, NamedTuple, ...) build their own constructor
    special = [n for n in node.body if {"__init__", "__new__", "__call__"} & set(_local_bindings([n]))]
    if not special:
        if any(b.id != "object" for b in node.bases):
            return None  # exception classes accept any arguments
        return ast.arguments(posonlyargs=[], args=[], vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[])
    init = special[0]
    if len(special) != 1 or not isinstance(init, ast.FunctionDef) or init.name != "__init__" or init.decorator_list:
        return None
    p = init.args
    if not (p.posonlyargs or p.args):
        return None
    # Drop `self`
    if p.posonlyargs:
        return ast.arguments(posonlyargs=p.posonlyargs[1:], args=p.args, vararg=p.vararg, kwonlyargs=p.kwonlyargs,
                             kw_defaults=p.kw_defaults, kwarg=p.kwarg, defaults=p.defaults)
    return ast.arguments(posonlyargs=[], args=p.args[1:], vararg=p.vararg, kwonlyargs=p.kwonlyargs,
                         kw_defaults=p.kw_defaults, kwarg=p.kwarg, defaults=p.defaults)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def call_mismatch(name: str, params: ast.arguments, call: ast.Call) -> Optional[str]:
    """Why calling `name` with these arguments raises TypeError, or None if it does not (or cannot be told)."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return None
    positional = [a.arg for a in params.posonlyargs + params.args]
    posonly = {a.arg for a in params.posonlyargs}
    n_required = len(positional) - len(params.defaults)
    given = len(call.args)
    if given > len(positional) and not params.vararg:
        return (f"{name}() takes {_plural(len(positional), 'positional argument')} "
                f"but {given} {'was' if given == 1 else 'were'} given")
    keywords = [k.arg for k in call.keywords]
    accepted = (set(positional) - posonly) | {a.arg for a in params.kwonlyargs}
    for kw in keywords:
        if kw in positional[:given] and kw not in posonly:
            return f"{name}() got multiple values for argument '{kw}'"
        if kw not in accepted and not params.kwarg:
            return f"{name}() got an unexpected keyword argument '{kw}'"
    missing = [p for i, p in enumerate(positional[:n_required]) if i >= given and (p not in keywords or p in posonly)]
    if missing:
        return (f"{name}() missing {_plural(len(missing), 'required positional argument')}: "
                + ", ".join(f"'{m}'" for m in missing))
    missing_kw = [a.arg for a, d in zip(params.kwonlyargs, params.kw_defaults) if d is None and a.arg not in keywords]
    if missing_kw:
        return (f"{name}() missing {_plural(len(missing_kw), 'required keyword-only argument')}: "
                + ", ".join(f"'{m}'" for m in missing_kw))
    return None


# ---------- Python checks ----------

def _guarded_imports(tree: ast.Module) -> set[int]:
    """ids of import nodes that a missing module does not break: inside try/except,
    `if TYPE_CHECKING:` blocks, or functions (those fail only when called, and often on purpose)."""
    guarded: set[int] = set()

    def mark(nodes: list[ast.stmt]) -> None:
        for n in nodes:
            guarded.update(id(sub) for sub in ast.walk(n) if isinstance(sub, (ast.Import, ast.ImportFrom)))

    for node in ast.walk(tree):
        if (isinstance(node, ast.Try) or type(node).__name__ == "TryStar") and node.handlers:
            mark(node.body)
        elif isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test):
            mark(node.body)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            mark(node.body)
    return guarded


def _resolve_relative(path: Path, level: int, module: Optional[str]) -> list[Path]:
    """Where a relative import leads (see RepoIndex.resolve); empty if the module does not exist."""
    base = path.parent
    for _ in range(level - 1):
        base = base.parent
    if not module:
        return [base / "__init__.py" if (base / "__init__.py").is_file() else base]
    found = module_at(base, module.split("."))
    return [found] if found else []


def _import_problems(path: Path, rel: str, tree: ast.Module,
                     index: RepoIndex) -> tuple[list[Problem], dict[str, ast.arguments]]:
    """Broken imports, and the signatures of in-repo functions this file imports (for call checks)."""
    problems: list[Problem] = []
    imported: dict[str, ast.arguments] = {}
    guarded = _guarded_imports(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "." in alias.name and id(node) not in guarded and index.resolve(path, alias.name) == []:
                    problems.append(Problem("missing-module", rel, node.lineno,
                                            f"No module named '{alias.name}' in the repository"))
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        is_guarded = id(node) in guarded
        dotted = "." * node.level + (node.module or "")
        found = _resolve_relative(path, node.level, node.module) if node.level else index.resolve(path, dotted)
        if found is None:
            continue
        if not found:
            if not is_guarded:
                where = f"next to {rel}" if node.level else "in the repository"
                problems.append(Problem("missing-module", rel, node.lineno, f"No module named '{dotted}' {where}"))
            continue
        if len(found) == 1 and found[0].is_dir():
            # Namespace package: only its submodules can be imported from it
            missing = [a.name for a in node.names if a.name != "*" and not module_at(found[0], [a.name])]
            if missing and not is_guarded:
                problems += [Problem("missing-name", rel, node.lineno, f"cannot import name '{m}' from '{dotted}'")
                             for m in missing]
            continue
        if any(f.suffix != ".py" for f in found):
            continue  # a stub, extension or namespace package also matches: names unknown
        infos = [index.info(c) for c in found]
        if any(i is None or i.dynamic for i in infos):
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            if all(alias.name not in i.names for i in infos):
                if not is_guarded:
                    problems.append(Problem("missing-name", rel, node.lineno,
                                            f"cannot import name '{alias.name}' from '{dotted}'"))
            elif len(infos) == 1 and alias.name in infos[0].signatures:
                imported[alias.asname or alias.name] = infos[0].signatures[alias.name]
    return problems, imported


def _call_problems(rel: str, tree: ast.Module, signatures: dict[str, ast.arguments]) -> list[Problem]:
    """Calls by plain name to module-level functions / classes whose parameters are known."""
    problems: list[Problem] = []
    counts: dict[str, int] = {}
    for name in _local_bindings(tree.body):
        counts[name] = counts.get(name, 0) + 1
    known = {n: p for n, p in signatures.items() if counts.get(n, 0) <= 1}

    def visit(node: ast.AST, shadowed: frozenset[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            local = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
            local |= {a.arg for a in (args.vararg, args.kwarg) if a}
            body = node.body if isinstance(node.body, list) else [node.body]
            # A superset of the scope's own bindings: over-shadowing only skips checks
            local |= {n.id for b in body for n in ast.walk(b) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            local |= set(_local_bindings(body if isinstance(node.body, list) else []))
            shadowed = shadowed | local
        elif isinstance(node, ast.ClassDef):
            shadowed = shadowed | set(_local_bindings(node.body))
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            shadowed = shadowed | {n.id for g in node.generators for n in ast.walk(g.target) if isinstance(n, ast.Name)}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in known and name not in shadowed:
                why = call_mismatch(name, known[name], node)
                if why:
                    problems.append(Problem("call-arguments", rel, node.lineno, why))
        for child in ast.iter_child_nodes(node):
            visit(child, shadowed)

    visit(tree, frozenset())
    return problems


def check_python_file(path: Path, rel: str, index: RepoIndex) -> list[Problem]:
    try:
        source = _read(path)
        tree = ast.parse(source, filename=rel)
    except SyntaxError as e:
        return [Problem("syntax-error", rel, e.lineno or 1,
                        e.msg if type(e) is SyntaxError else f"{type(e).__name__}: {e.msg}")]
    except (ValueError, RecursionError, MemoryError, OSError):
        return []

    problems: list[Problem] = []
    lazy = _unevaluated_annotations(tree)
    lines = source.splitlines()
    for m in pyflakes_checker.Checker(tree, filename=rel, builtins=NEWER_BUILTINS).messages:
        slug = PYFLAKES_CLASSES.get(type(m))
        if not slug or (slug == "undefined-name" and _within(lazy, m.lineno, m.col)):
            continue
        # The developer already marked this line as intended (`# noqa`, `# type: ignore[...]`)
        if SUPPRESSED.search(lines[m.lineno - 1] if 0 < m.lineno <= len(lines) else ""):
            continue
        problems.append(Problem(slug, rel, m.lineno, m.message % m.message_args))

    import_problems, imported = _import_problems(path, rel, tree, index)
    problems += import_problems
    own = index.info(path)
    problems += _call_problems(rel, tree, {**imported, **(own.signatures if own else {})})
    expected = _expected_errors(tree)
    return [p for p in problems if not any(start <= p.line <= end and (caught is None or caught & CAUGHT_BY.get(p.rule, set()))
                                           for start, end, caught in expected)]


Span = tuple[int, int, int, int]


def _span(node: ast.AST) -> Span:
    return node.lineno, node.col_offset, node.end_lineno or node.lineno, node.end_col_offset or 0


def _within(spans: list[Span], line: int, col: int) -> bool:
    return any((l1, c1) <= (line, col) < (l2, c2) for l1, c1, l2, c2 in spans)


def _unevaluated_annotations(tree: ast.Module) -> list[Span]:
    """Annotations Python never evaluates: strings, all of them under `from __future__ import
    annotations` or on Python 3.14+ (deferred annotations), and variable annotations inside functions."""
    postponed = sys.version_info >= (3, 14) or any(isinstance(n, ast.ImportFrom) and n.module == "__future__"
                    and any(a.name == "annotations" for a in n.names) for n in tree.body)
    annotations: list[tuple[ast.expr, bool]] = []  # (annotation, inside a function body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            annotations += [(arg.annotation, False) for arg in a.posonlyargs + a.args + a.kwonlyargs
                            + [x for x in (a.vararg, a.kwarg) if x] if arg.annotation]
            if not isinstance(node, ast.Lambda):
                if node.returns:
                    annotations.append((node.returns, False))
                annotations += [(n.annotation, True) for b in node.body for n in ast.walk(b) if isinstance(n, ast.AnnAssign)]
        elif isinstance(node, ast.AnnAssign):
            annotations.append((node.annotation, False))
    spans: list[Span] = []
    for annotation, in_function in annotations:
        if postponed or in_function:
            spans.append(_span(annotation))
        else:
            spans += [_span(n) for n in ast.walk(annotation) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return spans


def _expected_errors(tree: ast.Module) -> list[tuple[int, int, Optional[set[str]]]]:
    """Line ranges where an error is expected: `with pytest.raises(...)` / `self.assertRaises(...)`
    blocks (any error), and try bodies (the exceptions their handlers catch; None = any)."""
    out: list[tuple[int, int, Optional[set[str]]]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            if any("raises" in ast.unparse(item.context_expr).lower() for item in node.items):
                out.append((node.lineno, node.end_lineno or node.lineno, None))
        elif (isinstance(node, ast.Try) or type(node).__name__ == "TryStar") and node.body:
            caught: set[str] = set()
            for h in node.handlers:
                names = {n.id if isinstance(n, ast.Name) else n.attr
                         for n in ast.walk(h.type) if isinstance(n, (ast.Name, ast.Attribute))} if h.type else set()
                if not names or names & {"Exception", "BaseException"}:
                    caught = None
                    break
                caught |= names
            if caught is None or caught:
                out.append((node.body[0].lineno, node.body[-1].end_lineno or node.body[-1].lineno, caught))
    return out


# ---------- JavaScript ----------

# Parses every file in one Node process. CommonJS goes through vm.compileFunction (exact line
# numbers); ES modules through vm.SourceTextModule, and only those that fail are parsed again
# with `node --check` to get the line. Nothing is evaluated.
NODE_SCRIPT = r"""
const fs = require("fs"), vm = require("vm"), cp = require("child_process");
const out = [];
const ESM = /^\s*(import\s*[\w{*'"]|export\s)/m;
for (const [rel, abs] of JSON.parse(fs.readFileSync(0, "utf8"))) {
  let src;
  try { src = fs.readFileSync(abs, "utf8"); } catch { continue; }
  if (src.startsWith("#!")) src = "//" + src.slice(2);
  if (/@flow\b/.test(src.slice(0, 500))) continue;
  const asModule = abs.endsWith(".mjs") || (!abs.endsWith(".cjs") && ESM.test(src));
  if (!asModule) {
    try { vm.compileFunction(src, ["exports", "require", "module", "__filename", "__dirname"], { filename: rel }); }
    catch (e) { out.push([rel, Number((/:(\d+)\n/.exec(e.stack || "") || [])[1] || 1), e.message]); }
    continue;
  }
  if (vm.SourceTextModule) {
    try { new vm.SourceTextModule(src, { identifier: rel }); continue; } catch {}
  }
  const r = cp.spawnSync(process.execPath, ["--input-type=module", "--check"], { input: src, encoding: "utf8", timeout: 10000 });
  if (r.status === 0) continue;
  const err = r.stderr || "";
  const msg = (/^SyntaxError: (.*)$/m.exec(err) || [])[1];
  if (msg) out.push([rel, Number((/\[stdin\]:(\d+)/.exec(err) || [])[1] || 1), msg]);
}
process.stdout.write(JSON.stringify(out));
"""


def check_javascript(root: Path, files: list[Path]) -> tuple[list[Problem], list[str]]:
    if not files:
        return [], []
    node = shutil.which("node")
    if not node:
        return [], ["Node.js is not installed, so JavaScript files were not checked."]
    payload = json.dumps([[f.relative_to(root).as_posix(), str(f)] for f in files])
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    try:
        proc = subprocess.run([node, "--experimental-vm-modules", "--no-warnings", "-e", NODE_SCRIPT],
                              input=payload.encode(), capture_output=True, timeout=NODE_TIMEOUT_SECONDS,
                              env=env, cwd=root)
        results = json.loads(proc.stdout.decode(errors="replace") or "[]")
    except subprocess.TimeoutExpired:
        return [], [f"The JavaScript check timed out after {NODE_TIMEOUT_SECONDS}s."]
    except (OSError, ValueError) as e:
        logger.warning("JavaScript check failed: %s", e)
        return [], ["JavaScript files could not be checked."]
    problems = [Problem("js-syntax-error", rel, int(line), message)
                for rel, line, message in results
                if "Unexpected token '<'" not in message]  # JSX: valid for the project's bundler, not for Node
    return problems, []


# ---------- report ----------

def _code_at(root: Path, rel: str, line: int, context: int = 2) -> tuple[str, int]:
    """Lines around `line`, and the number of the first one."""
    try:
        lines = _read(root / rel).splitlines()
    except OSError:
        return "", line
    start = max(line - 1 - context, 0)
    return "\n".join(l[:300] for l in lines[start:line + context]), start + 1


def to_dict(p: Problem, root: Path) -> dict[str, Any]:
    rule = RULES[p.rule]
    code, code_start = _code_at(root, p.file, p.line)
    return {
        "rule": f"runtime/{rule.slug}",
        "error": rule.error,
        "title": rule.title,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "file": p.file,
        "line": p.line,
        "message": p.message,
        "explanation": rule.explanation,
        "impact": (f"{p.file} fails to load, so every feature that depends on it is down."
                   if p.rule in LOAD_FAILURES else
                   f"Whatever reaches line {p.line} (a request, job or command) stops with "
                   f"{rule.error.split(' / ')[0]} instead of finishing."),
        "code": code,
        "code_start": code_start,
    }


def check(repo_path: Path) -> dict[str, Any]:
    """Check every Python and JavaScript file under repo_path; returns the report."""
    repo_path = repo_path.resolve()
    py_files = _source_files(repo_path, (".py",))
    js_files = _source_files(repo_path, JS_EXT)
    index = RepoIndex(repo_path)

    problems: list[Problem] = []
    for path in py_files:
        try:
            problems += check_python_file(path, path.relative_to(repo_path).as_posix(), index)
        except Exception:  # one odd file must not stop the check
            logger.exception("Runtime check failed for %s", path)
    js_problems, warnings = check_javascript(repo_path, js_files)
    problems += js_problems

    unique = list({(p.file, p.line, p.message): p for p in problems}.values())
    unique.sort(key=lambda p: (SEVERITY_RANK[RULES[p.rule].severity], p.file, p.line))
    if len(unique) > MAX_PROBLEMS:
        warnings.append(f"Stopped after {MAX_PROBLEMS} problems; fix these and check again.")
        unique = unique[:MAX_PROBLEMS]
    if not py_files and not js_files:
        warnings.append("No Python or JavaScript files found.")
    if any(p.rule == "syntax-error" for p in unique):
        warnings.append(f"Python files were parsed as Python {PYTHON_VERSION}: code written for a newer Python "
                        "shows up as a syntax error here.")
    summary = {s: 0 for s in SEVERITY_RANK}
    for p in unique:
        summary[RULES[p.rule].severity] += 1
    logger.info("Checked %d Python and %d JavaScript files: %d problems", len(py_files), len(js_files), len(unique))
    return {
        "files_checked": {"python": len(py_files), "javascript": len(js_files)},
        "python_version": PYTHON_VERSION,
        "summary": {"total": len(unique), **summary},
        "problems": [to_dict(p, repo_path) for p in unique],
        "warnings": warnings,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Find code that fails at run time, without running it.")
    parser.add_argument("path", type=Path, help="folder to check")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="exit with 1 if a problem this severe or worse is found")
    args = parser.parse_args(argv)
    if not args.path.is_dir():
        parser.error(f"{args.path} is not a folder")

    report = check(args.path)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        files = report["files_checked"]
        print(f"Checked {files['python']} Python and {files['javascript']} JavaScript files: "
              f"{report['summary']['total']} runtime problem(s)")
        for p in report["problems"]:
            print(f"  [{p['severity'].upper():6s}] {p['file']}:{p['line']}  {p['error']}: {p['message']}")
        for w in report["warnings"]:
            print(f"  note: {w}")
    if args.fail_on:
        limit = SEVERITY_RANK[args.fail_on]
        return int(any(SEVERITY_RANK[p["severity"]] <= limit for p in report["problems"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
