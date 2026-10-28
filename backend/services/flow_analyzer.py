"""Static data-flow analysis for Python, the evidence behind chains of weaknesses.

Semgrep's community edition reports *where* a rule matched but gives no
source-to-sink trace, so on its own it cannot say how two findings connect.
This module recovers that evidence with the standard library's `ast`:

- sources: HTTP request data (Flask / Django / Starlette), route path
  parameters, FastAPI handler parameters, stdin and argv
- propagation: assignments, string building (f-strings, +, %, .format) and
  known string/path helpers; an unknown call is *assumed* to propagate and the
  step is flagged, so the relationship is reported as a hypothesis
- controls: sanitizers (int(), shlex.quote, secure_filename, escape, ...) and
  validation guards (`if` checks), graded strong / weak / unverified
- sinks: SQL execution, shell commands, eval/exec, deserialization, file
  paths, template rendering, outbound requests, redirects, HTML responses
- access control: auth decorators, session / current_user checks,
  before_request hooks, FastAPI auth dependencies
- calls into functions of the same module are followed (bounded depth), so a
  helper reached from two endpoints yields two paths into one sink

Limitations are listed in docs/CHAIN_ANALYSIS.md: Python only, no call
following across modules, loops evaluated once, containers tainted as a whole,
dynamic features (getattr, argument-rewriting decorators) not modelled.
"""
from __future__ import annotations

import ast
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", "site-packages"}
MAX_FILE_BYTES = 1_000_000
MAX_CALL_DEPTH = 3
MAX_TRACES_PER_VAR = 20
CALL_BUDGET = 5000  # interprocedural function entries per module

SINK_KINDS = (
    "sql_injection", "command_injection", "code_injection", "deserialization",
    "path_traversal", "template_injection", "ssrf", "open_redirect", "xss",
)

# request.<attr> that carries attacker-controlled data, and how to describe it
SOURCE_ATTRS: dict[str, str] = {
    "args": "query parameter", "values": "request parameter", "GET": "query parameter",
    "query_params": "query parameter", "form": "form field", "POST": "form field",
    "json": "JSON body", "data": "request body", "body": "request body", "files": "uploaded file",
    "cookies": "cookie", "COOKIES": "cookie", "headers": "HTTP header", "META": "HTTP header",
    "path_params": "path parameter",
}
SOURCE_METHODS = {"get_json": "JSON body", "get_data": "request body"}
SOURCE_GETTERS = {"get", "getlist", "to_dict", "get_all", "getall"}

TYPE_CASTS = {"int", "float", "bool", "len", "abs", "round", "uuid.UUID", "decimal.Decimal"}
SANITIZERS: dict[str, frozenset[str]] = {
    "shlex.quote": frozenset({"command_injection"}),
    "pipes.quote": frozenset({"command_injection"}),
    "html.escape": frozenset({"xss"}),
    "markupsafe.escape": frozenset({"xss"}),
    "flask.escape": frozenset({"xss"}),
    "jinja2.escape": frozenset({"xss"}),
    "bleach.clean": frozenset({"xss"}),
    "django.utils.html.escape": frozenset({"xss"}),
    "werkzeug.utils.secure_filename": frozenset({"path_traversal"}),
    "werkzeug.secure_filename": frozenset({"path_traversal"}),
    "os.path.basename": frozenset({"path_traversal"}),
    "werkzeug.security.safe_join": frozenset({"path_traversal"}),
    "flask.safe_join": frozenset({"path_traversal"}),
}
# Calls whose result carries the taint of their inputs without being "unknown"
PROPAGATORS = {
    "str", "bytes", "repr", "list", "tuple", "dict", "set", "sorted", "reversed", "format",
    "os.path.join", "os.path.normpath", "os.path.abspath", "os.path.expanduser", "os.path.realpath",
    "posixpath.join", "pathlib.Path", "urllib.parse.urljoin", "urllib.parse.unquote",
    "urllib.parse.unquote_plus", "base64.b64decode", "base64.urlsafe_b64decode", "json.loads", "json.dumps",
}
STR_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "replace",
    "format", "join", "split", "rsplit", "splitlines", "encode", "decode", "removeprefix",
    "removesuffix", "zfill", "ljust", "rjust", "center", "partition", "rpartition", "expandtabs",
}
SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
}
REQUEST_FUNCS = {f"{m}.{v}" for m in ("requests", "httpx") for v in ("get", "post", "put", "patch", "delete", "head", "request")}
SAFE_RESPONSE_CALLS = {"jsonify", "json.dumps", "render_template", "redirect", "send_file", "send_from_directory", "abort", "url_for"}
TERMINATING_CALLS = {"abort", "exit", "_exit", "quit", "sys.exit", "flask.abort", "os._exit"}

AUTH_DECORATOR = re.compile(
    r"(login|auth|admin|jwt|token|permission|roles?|staff|superuser|user)_?(required|accepted)"
    r"|requires?_(auth|login|role|roles|permission|admin)|authenticated|protected",
    re.I,
)
VALIDATOR_METHODS = {"isdigit", "isalnum", "isalpha", "isdecimal", "isnumeric", "isidentifier", "isascii"}
FLASK_PARAM = re.compile(r"<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>")
FASTAPI_PARAM = re.compile(r"{(\w+)(?::\w+)?}")
SAFE_PARAM_TYPES = {"int", "float", "bool", "UUID", "uuid.UUID", "date", "datetime", "Decimal"}


@dataclass(frozen=True)
class Step:
    file: str
    line: int
    code: str
    note: str
    assumed: bool = False  # propagation through a call whose behaviour is unknown


@dataclass(frozen=True)
class Control:
    kind: str  # "sanitizer" | "guard"
    file: str
    line: int
    code: str
    name: str
    strength: str  # "strong" | "weak" | "unverified"
    effective_for: frozenset[str] = frozenset()

    def blocks(self, sink_kind: str) -> bool:
        return self.strength == "strong" and sink_kind in self.effective_for


@dataclass(frozen=True)
class Source:
    kind: str  # e.g. "query parameter", "path parameter", "stdin"
    expr: str
    file: str
    line: int
    code: str
    function: str
    remote: bool = True  # reachable over the network (HTTP) rather than locally


@dataclass(frozen=True)
class Trace:
    source: Source
    steps: tuple[Step, ...] = ()
    controls: tuple[Control, ...] = ()
    calls: tuple[str, ...] = ()

    def add(self, step: Optional[Step] = None, control: Optional[Control] = None,
            call: Optional[str] = None) -> "Trace":
        return replace(
            self,
            steps=self.steps + ((step,) if step else ()),
            controls=self.controls + ((control,) if control else ()),
            calls=self.calls + ((call,) if call else ()),
        )


@dataclass(frozen=True)
class Sink:
    kind: str
    callee: str
    file: str
    line: int
    code: str
    function: str


@dataclass(frozen=True)
class AuthCheck:
    kind: str  # "decorator" | "inline" | "before_request" | "dependency"
    file: str
    line: int
    code: str
    session_based: Optional[bool]  # True: relies on the signed session cookie


@dataclass
class Endpoint:
    file: str
    function: str
    line: int
    route: str
    methods: list[str]
    framework: str
    auth: list[AuthCheck] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{'/'.join(self.methods)} {self.route}"


@dataclass
class Flow:
    source: Source
    steps: tuple[Step, ...]
    controls: tuple[Control, ...]
    calls: tuple[str, ...]
    sink: Sink
    root: str  # function analysed at depth 0 (where the path starts)
    entry: Optional[Endpoint] = None

    @property
    def blocking_controls(self) -> list[Control]:
        return [c for c in self.controls if c.blocks(self.sink.kind)]

    @property
    def blocked(self) -> bool:
        return bool(self.blocking_controls)

    @property
    def assumed(self) -> bool:
        return any(s.assumed for s in self.steps)

    def signature(self) -> tuple:
        """Identity that survives line shifts, used to match flows before and after a fix."""
        return (self.sink.file, self.sink.function, self.sink.callee, self.sink.kind,
                self.source.function, _normalize(self.source.expr), self.calls)

    @property
    def id(self) -> str:
        return "flow_" + hashlib.sha1(repr(self.signature()).encode()).hexdigest()[:10]

    def lines(self) -> set[int]:
        return {self.source.line, self.sink.line, *(s.line for s in self.steps if s.file == self.sink.file)}


@dataclass
class SecretKeyAssignment:
    file: str
    line: int
    code: str
    target: str


@dataclass
class ModuleFacts:
    file: str
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    secret_keys: list[SecretKeyAssignment] = field(default_factory=list)
    callers: dict[str, set[str]] = field(default_factory=dict)  # function -> functions calling it
    functions: dict[str, tuple[int, int]] = field(default_factory=dict)  # qualname -> (start, end) lines
    # Every call to a sink-capable callee, tainted or not: (function, callee) -> lines.
    # Lets "the 2nd cursor.execute in login()" be found again after a fix made the 1st one safe.
    sink_sites: dict[tuple[str, str], set[int]] = field(default_factory=dict)


@dataclass
class FlowAnalysis:
    flows: list[Flow] = field(default_factory=list)
    modules: dict[str, ModuleFacts] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)  # file -> parse error
    files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def entries_for(self, flow: Flow) -> list[Endpoint]:
        """Endpoints through which the flow's starting function is reached."""
        if flow.entry:
            return [flow.entry]
        facts = self.modules.get(flow.sink.file) or self.modules.get(flow.source.file)
        if not facts:
            return []
        return [facts.endpoints[c] for c in sorted(facts.callers.get(flow.root, ())) if c in facts.endpoints]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", "", text).replace('"', "'")


def iter_python_files(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            if name.endswith(".py"):
                full = Path(dirpath) / name
                try:
                    if full.stat().st_size <= MAX_FILE_BYTES:
                        out.append(full.relative_to(root).as_posix())
                except OSError:
                    continue
    return sorted(out)


def analyze_repository(root: Path, files: Optional[list[str]] = None) -> FlowAnalysis:
    """Analyse every Python file under root (or only `files`, relative posix paths)."""
    result = FlowAnalysis(files=files if files is not None else iter_python_files(root))
    for rel in result.files:
        try:
            text = (root / rel).read_text(encoding="utf-8-sig", errors="replace")  # -sig: Windows editors add a BOM
            tree = ast.parse(text, filename=rel)
        except (SyntaxError, ValueError, OSError) as e:
            result.errors[rel] = f"{type(e).__name__}: {e}"
            continue
        module = _ModuleAnalyzer(rel, text, tree)
        module.run()
        result.flows.extend(module.flows)
        result.modules[rel] = module.facts
        result.notes.extend(module.notes)

    # The same path is found once per route into a helper; keep one of each
    unique: dict[tuple, Flow] = {}
    for f in result.flows:
        key = (f.signature(), f.sink.line, f.source.line, f.entry.function if f.entry else None)
        unique.setdefault(key, f)
    result.flows = list(unique.values())
    logger.info("Flow analysis: %d files, %d flows (%d unblocked), %d parse errors",
                len(result.files), len(result.flows), sum(not f.blocked for f in result.flows), len(result.errors))
    return result


@dataclass
class _Ctx:
    function: str
    root: str
    entry: Optional[Endpoint]
    depth: int
    stack: tuple[str, ...]
    returns: list[Trace] = field(default_factory=list)


Env = dict[str, list[Trace]]


class _ModuleAnalyzer:
    def __init__(self, file: str, text: str, tree: ast.Module) -> None:
        self.file = file
        self.lines = text.splitlines()
        self.tree = tree
        self.imports: dict[str, str] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.class_of: dict[str, str] = {}
        self.flows: list[Flow] = []
        self.facts = ModuleFacts(file=file)
        self.notes: list[str] = []
        self.budget = CALL_BUDGET
        self.uses_fastapi = False

    # ---------- module-level facts ----------

    def run(self) -> None:
        self._collect_imports()
        self._collect_functions()
        self._collect_secret_keys()
        hooks = self._before_request_auth()
        for name, fn in self.functions.items():
            ep = self._endpoint(name, fn)
            if ep:
                ep.auth.extend(self._decorator_auth(fn) + self._inline_auth(fn) + hooks)
                self.facts.endpoints[name] = ep
        self._collect_callers()
        for name, fn in self.functions.items():
            ep = self.facts.endpoints.get(name)
            ctx = _Ctx(function=name, root=name, entry=ep, depth=0, stack=(name,))
            env = self._param_sources(name, fn, ep) if ep else {}
            self._block(fn.body, env, ctx)

    def _collect_imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.imports[a.asname] = a.name
                    else:
                        self.imports[a.name.split(".")[0]] = a.name.split(".")[0]
                    self.uses_fastapi |= a.name.startswith("fastapi")
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self.imports[a.asname or a.name] = f"{node.module}.{a.name}"
                self.uses_fastapi |= node.module.startswith("fastapi")

    def _collect_functions(self) -> None:
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qual = f"{node.name}.{item.name}"
                        self.functions[qual] = item
                        self.class_of[qual] = node.name
        for name, fn in self.functions.items():
            self.facts.functions[name] = (fn.lineno, fn.end_lineno or fn.lineno)

    def _collect_secret_keys(self) -> None:
        literals = {
            t.id: n.value.value
            for n in self.tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str) for t in n.targets if isinstance(t, ast.Name)
        }

        def is_literal(v: ast.AST) -> bool:
            return (isinstance(v, ast.Constant) and isinstance(v.value, str) and bool(v.value)) or (
                isinstance(v, ast.Name) and v.id in literals)

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and is_literal(node.value):
                for t in node.targets:
                    target = ""
                    if isinstance(t, ast.Attribute) and t.attr == "secret_key":
                        target = ast.unparse(t)
                    elif isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == "SECRET_KEY":
                        target = ast.unparse(t)
                    elif isinstance(t, ast.Name) and t.id == "SECRET_KEY":
                        target = "SECRET_KEY"
                    if target:
                        self.facts.secret_keys.append(SecretKeyAssignment(self.file, node.lineno, self._code(node.lineno), target))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "update":
                for kw in node.keywords:
                    if kw.arg == "SECRET_KEY" and is_literal(kw.value):
                        self.facts.secret_keys.append(SecretKeyAssignment(self.file, node.lineno, self._code(node.lineno), "SECRET_KEY"))

    def _collect_callers(self) -> None:
        for name, fn in self.functions.items():
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    callee = self._local_function(node.func, name)
                    if callee and callee != name:
                        self.facts.callers.setdefault(callee, set()).add(name)

    def _endpoint(self, name: str, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Optional[Endpoint]:
        for dec in fn.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            attr = dec.func.attr
            if attr not in ("route", "get", "post", "put", "patch", "delete", "api_route"):
                continue
            route = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else "?"
            if attr in ("route", "api_route"):
                methods = ["GET"]
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [str(e.value).upper() for e in kw.value.elts if isinstance(e, ast.Constant)] or methods
            else:
                methods = [attr.upper()]
            framework = "fastapi" if self.uses_fastapi and attr != "route" else "flask"
            return Endpoint(self.file, name, fn.lineno, str(route), methods, framework)
        return None

    def _decorator_auth(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[AuthCheck]:
        out = []
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            if name and AUTH_DECORATOR.search(name) and name not in ("route",):
                low = name.lower()
                session = True if low in ("login_required", "fresh_login_required") or "session" in low else (
                    False if ("jwt" in low or "token" in low) else None)
                out.append(AuthCheck("decorator", self.file, dec.lineno, self._code(dec.lineno), session))
        for arg, default in self._defaults(fn):
            if isinstance(default, ast.Call) and self._name(default.func).split(".")[-1] in ("Depends", "Security"):
                dep = self._name(default.args[0]) if default.args else ""
                if re.search(r"auth|user|token|login|admin|permission", dep, re.I):
                    out.append(AuthCheck("dependency", self.file, default.lineno, self._code(default.lineno), False))
        return out

    def _inline_auth(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[AuthCheck]:
        out = []
        for node in ast.walk(fn):
            if isinstance(node, ast.If) and _terminates(node.body, self):
                names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
                text = ast.unparse(node.test)
                if "session" in names or "current_user" in names:
                    out.append(AuthCheck("inline", self.file, node.lineno, self._code(node.lineno), True))
                elif re.search(r"\bg\.user\b|authorization|api_key|token", text, re.I):
                    out.append(AuthCheck("inline", self.file, node.lineno, self._code(node.lineno), False))
        return out

    def _before_request_auth(self) -> list[AuthCheck]:
        out = []
        for fn in self.functions.values():
            if any(isinstance(d, ast.Attribute) and d.attr in ("before_request", "before_app_request") for d in fn.decorator_list):
                for check in self._inline_auth(fn):
                    out.append(replace(check, kind="before_request"))
        return out

    def _defaults(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, Optional[ast.expr]]]:
        args = fn.args.posonlyargs + fn.args.args
        defaults: list[Optional[ast.expr]] = [None] * (len(args) - len(fn.args.defaults)) + list(fn.args.defaults)
        pairs = list(zip(args, defaults))
        pairs += list(zip(fn.args.kwonlyargs, fn.args.kw_defaults))
        return pairs

    def _param_sources(self, name: str, fn: ast.FunctionDef | ast.AsyncFunctionDef, ep: Endpoint) -> Env:
        env: Env = {}
        path_params: dict[str, Optional[str]] = {}
        for conv, pname in FLASK_PARAM.findall(ep.route):
            path_params[pname] = conv or None
        for pname in FASTAPI_PARAM.findall(ep.route):
            path_params.setdefault(pname, None)
        for arg, default in self._defaults(fn):
            if arg.arg in ("self", "cls", "request", "db", "session", "response", "background_tasks"):
                continue
            annotation = ast.unparse(arg.annotation) if arg.annotation else ""
            if annotation.split("[")[0] in SAFE_PARAM_TYPES:
                continue
            if arg.arg in path_params:
                if path_params[arg.arg] in ("int", "float", "uuid"):
                    continue
                kind = "path parameter"
            elif ep.framework == "fastapi" and not (isinstance(default, ast.Call) and
                                                     self._name(default.func).split(".")[-1] in ("Depends", "Security")):
                if annotation and annotation not in ("str", "Optional[str]", "str | None") and not annotation.startswith("Query"):
                    continue  # Pydantic models etc.: validated by the framework
                kind = "query parameter"
            else:
                continue
            src = Source(kind, arg.arg, self.file, fn.lineno, self._code(fn.lineno), name)
            env[arg.arg] = [Trace(src)]
        return env

    # ---------- statements ----------

    def _block(self, stmts: list[ast.stmt], env: Env, ctx: _Ctx) -> Env:
        for stmt in stmts:
            env = self._stmt(stmt, env, ctx)
        return env

    def _stmt(self, stmt: ast.stmt, env: Env, ctx: _Ctx) -> Env:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return env
        for expr in _header_exprs(stmt):
            self._check_sinks(expr, env, ctx)

        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            value = stmt.value
            if value is None:
                return env
            traces = self._taint(value, env, ctx)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            env = dict(env)
            for t in targets:
                self._assign(t, traces, env, stmt)
            return env
        if isinstance(stmt, ast.AugAssign):
            traces = self._taint(stmt.value, env, ctx)
            env = dict(env)
            if isinstance(stmt.target, ast.Name) and traces:
                step = Step(self.file, stmt.lineno, self._code(stmt.lineno), f"appended to {stmt.target.id}")
                env[stmt.target.id] = _cap(env.get(stmt.target.id, []) + [t.add(step) for t in traces])
            return env
        if isinstance(stmt, ast.Expr):
            self._taint(stmt.value, env, ctx)
            return env
        if isinstance(stmt, ast.Return):
            if ctx.depth == 0 and ctx.entry:
                self.facts.sink_sites.setdefault((ctx.function, "return"), set()).add(stmt.lineno)
            if stmt.value is not None:
                traces = self._taint(stmt.value, env, ctx)
                ctx.returns.extend(traces)
                self._check_response(stmt, traces, ctx)
            return env
        if isinstance(stmt, ast.If):
            return self._if(stmt, env, ctx)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            loop_env = dict(env)
            traces = self._taint(stmt.iter, env, ctx)
            self._assign(stmt.target, traces, loop_env, stmt)
            body_env = self._block(stmt.body, loop_env, ctx)
            return _merge(env, self._block(stmt.orelse, body_env, ctx))
        if isinstance(stmt, ast.While):
            return _merge(env, self._block(stmt.body + stmt.orelse, dict(env), ctx))
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            env = dict(env)
            for item in stmt.items:
                traces = self._taint(item.context_expr, env, ctx)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, traces, env, stmt)
            return self._block(stmt.body, env, ctx)
        if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            body_env = self._block(stmt.body, dict(env), ctx)
            merged = body_env
            for handler in stmt.handlers:
                merged = _merge(merged, self._block(handler.body, dict(body_env), ctx))
            merged = self._block(stmt.orelse, merged, ctx)
            return self._block(stmt.finalbody, merged, ctx)
        if isinstance(stmt, ast.Match):
            self._taint(stmt.subject, env, ctx)
            merged = env
            for case in stmt.cases:
                merged = _merge(merged, self._block(case.body, dict(env), ctx))
            return merged
        return env

    def _assign(self, target: ast.expr, traces: list[Trace], env: Env, stmt: ast.stmt) -> None:
        if isinstance(target, ast.Name):
            if traces:
                step = Step(self.file, stmt.lineno, self._code(stmt.lineno), f"assigned to {target.id}")
                env[target.id] = _cap([t.add(step) for t in traces])
            else:
                env.pop(target.id, None)  # overwritten with untainted data
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt.value if isinstance(elt, ast.Starred) else elt, traces, env, stmt)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and traces:
            name = target.value.id
            step = Step(self.file, stmt.lineno, self._code(stmt.lineno), f"stored in {name}")
            env[name] = _cap(env.get(name, []) + [t.add(step) for t in traces])
        elif isinstance(target, ast.Attribute) and traces:
            key = ast.unparse(target)
            step = Step(self.file, stmt.lineno, self._code(stmt.lineno), f"assigned to {key}")
            env[key] = _cap([t.add(step) for t in traces])

    def _if(self, stmt: ast.If, env: Env, ctx: _Ctx) -> Env:
        self._taint(stmt.test, env, ctx)
        tainted = {n for n in _names(stmt.test) if n in env}
        if _terminates(stmt.body, self):
            # `if <bad input>: return/abort` guards everything after the if
            self._block(stmt.body, dict(env), ctx)
            guarded = self._apply_guards(stmt, env, tainted, rejecting=True)
            return self._block(stmt.orelse, guarded, ctx)
        body_env = self._block(stmt.body, self._apply_guards(stmt, env, tainted, rejecting=False), ctx)
        else_env = self._block(stmt.orelse, dict(env), ctx)
        return _merge(body_env, else_env)

    def _apply_guards(self, stmt: ast.If, env: Env, tainted: set[str], rejecting: bool) -> Env:
        if not tainted:
            return dict(env)
        strengths = self._classify(stmt.test, rejecting, tainted)
        out = dict(env)
        for var, (strength, label) in strengths.items():
            control = Control(
                "guard", self.file, stmt.lineno, self._code(stmt.lineno), label, strength,
                frozenset(SINK_KINDS) if strength == "strong" else frozenset(),
            )
            out[var] = [t.add(control=control) for t in env.get(var, [])]
        return out

    def _classify(self, test: ast.expr, rejecting: bool, tainted: set[str]) -> dict[str, tuple[str, str]]:
        """Grade an if-test as validation of each tainted variable it mentions.

        rejecting=True means the branch rejects the input (early return / abort).
        Allowlists (`x not in ALLOWED` → reject, `re.fullmatch` must hold) are strong;
        blocklists (`'..' in x` → reject), prefix and emptiness checks are weak;
        calls to project functions (`is_valid(x)`) are unverified.
        """
        rank = {"weak": 0, "unverified": 1, "strong": 2}
        result: dict[str, tuple[str, str]] = {}

        def put(var: str, strength: str, label: str) -> None:
            if var in tainted and (var not in result or rank[strength] > rank[result[var][0]]):
                result[var] = (strength, label)

        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._classify(test.operand, not rejecting, tainted)
        if isinstance(test, ast.BoolOp):
            for value in test.values:
                for var, (s, label) in self._classify(value, rejecting, tainted).items():
                    put(var, s, label)
            return result
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, left, right = test.ops[0], test.left, test.comparators[0]
            left_vars = {n for n in _names(left) if n in tainted}
            right_vars = {n for n in _names(right) if n in tainted}
            if isinstance(op, (ast.In, ast.NotIn)):
                allow = isinstance(op, ast.NotIn) == rejecting
                for v in left_vars:
                    put(v, "strong" if allow else "weak", "allowlist membership check" if allow else "blocklist check")
                for v in right_vars:
                    put(v, "weak", "substring check (blocklist)")
            elif isinstance(op, (ast.Eq, ast.NotEq)):
                exact = isinstance(op, ast.NotEq) == rejecting
                for v in left_vars | right_vars:
                    put(v, "strong" if exact else "weak", "exact value check" if exact else "single-value blocklist")
            else:
                for v in left_vars | right_vars:
                    put(v, "weak", "range/length check")
            return result
        if isinstance(test, ast.Call):
            name = self._name(test.func)
            short = name.split(".")[-1]
            subjects = set()
            for a in test.args:
                subjects |= {n for n in _names(a) if n in tainted}
            if isinstance(test.func, ast.Attribute):
                subjects |= {n for n in _names(test.func.value) if n in tainted}
            validator = short in VALIDATOR_METHODS or short == "isinstance" or name.endswith("fullmatch") or (
                short == "match" and _anchored(test))
            if validator:
                for v in subjects:
                    put(v, "weak" if rejecting else "strong",
                        "blocklist pattern" if rejecting else f"{short}() validation")
            elif short in ("startswith", "endswith", "search", "match", "find"):
                for v in subjects:
                    put(v, "weak", f"partial check ({short})")
            else:
                for v in subjects:
                    put(v, "unverified", f"custom check {short}() (not verified)")
            return result
        for v in {n for n in _names(test) if n in tainted}:
            put(v, "weak", "presence/emptiness check")
        return result

    # ---------- expressions ----------

    def _taint(self, node: Optional[ast.AST], env: Env, ctx: _Ctx) -> list[Trace]:
        if node is None:
            return []
        src = self._source(node, ctx)
        if src:
            return [Trace(src)]
        if isinstance(node, ast.Name):
            return list(env.get(node.id, []))
        if isinstance(node, ast.Attribute):
            key = ast.unparse(node)
            return list(env.get(key, [])) or self._taint(node.value, env, ctx)
        if isinstance(node, ast.Subscript):
            return self._taint(node.value, env, ctx)
        if isinstance(node, ast.JoinedStr):
            return _union(self._taint(v.value, env, ctx) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.FormattedValue):
            return self._taint(node.value, env, ctx)
        if isinstance(node, ast.BinOp):
            return _union([self._taint(node.left, env, ctx), self._taint(node.right, env, ctx)])
        if isinstance(node, ast.BoolOp):
            return _union(self._taint(v, env, ctx) for v in node.values)
        if isinstance(node, ast.IfExp):
            return _union([self._taint(node.body, env, ctx), self._taint(node.orelse, env, ctx)])
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return _union(self._taint(e, env, ctx) for e in node.elts)
        if isinstance(node, ast.Dict):
            return _union(self._taint(v, env, ctx) for v in node.values)
        if isinstance(node, (ast.Starred, ast.Await, ast.NamedExpr)):
            return self._taint(node.value, env, ctx)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return _union(self._taint(g.iter, env, ctx) for g in node.generators)
        if isinstance(node, ast.Call):
            return self._call(node, env, ctx)
        return []

    def _source(self, node: ast.AST, ctx: _Ctx) -> Optional[Source]:
        def make(kind: str, remote: bool = True) -> Source:
            line = getattr(node, "lineno", 0)
            return Source(kind, ast.unparse(node)[:120], self.file, line, self._code(line), ctx.function, remote)

        def request_attr(n: ast.AST) -> Optional[str]:
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "request":
                return SOURCE_ATTRS.get(n.attr)
            return None

        if isinstance(node, ast.Attribute):
            kind = request_attr(node)
            if kind:
                return make(kind)
            if ast.unparse(node) == "sys.argv":
                return make("command-line argument", remote=False)
        if isinstance(node, ast.Subscript):
            kind = request_attr(node.value)
            if kind:
                return make(kind)
            if ast.unparse(node.value) == "sys.argv":
                return make("command-line argument", remote=False)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if func.attr in SOURCE_GETTERS and request_attr(func.value):
                    return make(request_attr(func.value) or "request parameter")
                if func.attr in SOURCE_METHODS and isinstance(func.value, ast.Name) and func.value.id == "request":
                    return make(SOURCE_METHODS[func.attr])
            if self._name(func) == "input":
                return make("stdin", remote=False)
        return None

    def _call(self, node: ast.Call, env: Env, ctx: _Ctx) -> list[Trace]:
        name = self._name(node.func)
        short = name.split(".")[-1]
        args = list(node.args) + [kw.value for kw in node.keywords]
        arg_taint = _union(self._taint(a, env, ctx) for a in args)
        recv_taint = self._taint(node.func.value, env, ctx) if isinstance(node.func, ast.Attribute) else []

        if name in TYPE_CASTS or name in SANITIZERS:
            effective = frozenset(SINK_KINDS) if name in TYPE_CASTS else SANITIZERS[name]
            control = Control("sanitizer", self.file, node.lineno, self._code(node.lineno), name, "strong", effective)
            return [t.add(control=control) for t in arg_taint]

        local = self._local_function(node.func, ctx.function)
        if local:
            return self._enter(local, node, env, ctx)

        if self._sink(node, name) and self._sink(node, name)[0] in ("sql_injection", "command_injection", "path_traversal"):
            return []  # the result is the operation's output, not the attacker's string
        if name in PROPAGATORS or (isinstance(node.func, ast.Attribute) and short in STR_METHODS):
            return _union([recv_taint, arg_taint])
        traces = _union([recv_taint, arg_taint])
        if not traces:
            return []
        step = Step(self.file, node.lineno, self._code(node.lineno),
                    f"passed through {name or 'call'}() (assumed to preserve attacker control)", assumed=True)
        return [t.add(step) for t in traces]

    def _enter(self, callee: str, node: ast.Call, env: Env, ctx: _Ctx) -> list[Trace]:
        fn = self.functions[callee]
        if ctx.depth >= MAX_CALL_DEPTH or callee in ctx.stack or self.budget <= 0:
            if self.budget <= 0 and "budget" not in " ".join(self.notes):
                self.notes.append(f"{self.file}: call-following budget exhausted; some helper paths were not followed")
            return _union(self._taint(a, env, ctx) for a in list(node.args) + [k.value for k in node.keywords])
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        if callee in self.class_of and params and params[0] in ("self", "cls"):
            params = params[1:]
        callee_env: Env = {}
        for i, a in enumerate(node.args):
            if i < len(params):
                callee_env[params[i]] = self._taint(a, env, ctx)
        for kw in node.keywords:
            if kw.arg:
                callee_env[kw.arg] = self._taint(kw.value, env, ctx)
        callee_env = {k: v for k, v in callee_env.items() if v}
        if not callee_env:
            return []
        self.budget -= 1
        code = self._code(node.lineno)
        callee_env = {
            p: [t.add(Step(self.file, node.lineno, code, f"passed to {callee}({p})"), call=callee) for t in traces]
            for p, traces in callee_env.items()
        }
        sub = _Ctx(function=callee, root=ctx.root, entry=ctx.entry, depth=ctx.depth + 1, stack=ctx.stack + (callee,))
        self._block(fn.body, callee_env, sub)
        if not sub.returns:
            return []
        step = Step(self.file, node.lineno, code, f"returned from {callee}()")
        return _cap([t.add(step) for t in sub.returns])

    # ---------- sinks ----------

    def _check_sinks(self, expr: ast.AST, env: Env, ctx: _Ctx) -> None:
        for node in ast.walk(expr):
            if not isinstance(node, ast.Call):
                continue
            name = self._name(node.func)
            hit = self._sink(node, name)
            if hit or name in SUBPROCESS_FUNCS or name in ("yaml.load", "yaml.load_all"):
                callee = name or ast.unparse(node.func)
                self.facts.sink_sites.setdefault((ctx.function, callee), set()).add(node.lineno)
            if not hit:
                continue
            kind, arg = hit
            sink = Sink(kind, name or ast.unparse(node.func), self.file, node.lineno, self._code(node.lineno), ctx.function)
            for trace in self._taint(arg, env, ctx):
                self.flows.append(Flow(trace.source, trace.steps, trace.controls, trace.calls, sink, ctx.root, ctx.entry))

    def _sink(self, node: ast.Call, name: str) -> Optional[tuple[str, ast.expr]]:
        first = node.args[0] if node.args else None
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        short = name.split(".")[-1]
        if first is None and short not in ("Request",):
            first = kw.get("url") or kw.get("sql") or kw.get("args")
            if first is None:
                return None
        if isinstance(node.func, ast.Attribute) and short in ("execute", "executemany", "executescript"):
            return "sql_injection", first
        if short == "raw" and ".objects" in name:
            return "sql_injection", first
        if name in SUBPROCESS_FUNCS:
            shell = kw.get("shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                return "command_injection", first
            return None
        if name in ("subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "commands.getoutput"):
            return "command_injection", first
        if name in ("eval", "exec"):
            return "code_injection", first
        if name in ("pickle.loads", "pickle.load", "_pickle.loads", "cPickle.loads", "marshal.loads",
                    "dill.loads", "jsonpickle.decode", "yaml.unsafe_load"):
            return "deserialization", first
        if name in ("yaml.load", "yaml.load_all"):
            loader = kw.get("Loader") if "Loader" in kw else (node.args[1] if len(node.args) > 1 else None)
            if loader is not None and "Safe" in ast.unparse(loader):
                return None
            return "deserialization", first
        if name in ("open", "io.open", "codecs.open", "flask.send_file", "os.remove", "os.unlink",
                    "shutil.rmtree", "os.rmdir", "shutil.copyfile"):
            return "path_traversal", first
        if name in ("flask.render_template_string", "jinja2.Template") or (
                short == "from_string" and isinstance(node.func, ast.Attribute)):
            return "template_injection", first
        if name in REQUEST_FUNCS or name in ("urllib.request.urlopen", "urllib.request.Request", "urllib2.urlopen"):
            target = node.args[1] if short == "request" and len(node.args) > 1 else first
            return "ssrf", target
        if name in ("flask.redirect", "django.shortcuts.redirect", "redirect") or short == "HttpResponseRedirect":
            return "open_redirect", first
        if short in ("HttpResponse", "make_response", "Response", "HTMLResponse"):
            return "xss", first
        return None

    def _check_response(self, stmt: ast.Return, traces: list[Trace], ctx: _Ctx) -> None:
        """A route that returns a string built from request data is reflected XSS."""
        if not traces or ctx.depth != 0 or not ctx.entry or ctx.entry.framework != "flask":
            return
        value = stmt.value
        if isinstance(value, ast.Tuple) and value.elts:
            value = value.elts[0]
        if isinstance(value, ast.Call):
            name = self._name(value.func)
            if name.split(".")[-1] in SAFE_RESPONSE_CALLS or self._sink(value, name):
                return
            if not (isinstance(value.func, ast.Attribute) and value.func.attr == "format"):
                return
        elif not isinstance(value, (ast.JoinedStr, ast.BinOp, ast.Name)):
            return
        sink = Sink("xss", "return", self.file, stmt.lineno, self._code(stmt.lineno), ctx.function)
        for trace in traces:
            self.flows.append(Flow(trace.source, trace.steps, trace.controls, trace.calls, sink, ctx.root, ctx.entry))

    # ---------- helpers ----------

    def _name(self, node: ast.AST) -> str:
        """Dotted name of a callee with import aliases resolved ("sp.run" -> "subprocess.run")."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.imports.get(node.id, node.id))
        elif isinstance(node, ast.Call):
            parts.append(self._name(node.func) + "()")
        else:
            return ""
        return ".".join(reversed(parts))

    def _local_function(self, func: ast.AST, current: str) -> Optional[str]:
        if isinstance(func, ast.Name) and func.id in self.functions and func.id not in self.imports:
            return func.id
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id in ("self", "cls") and current in self.class_of):
            qual = f"{self.class_of[current]}.{func.attr}"
            return qual if qual in self.functions else None
        return None

    def _code(self, line: int) -> str:
        if 0 < line <= len(self.lines):
            return self.lines[line - 1].strip()[:200]
        return ""


def _header_exprs(stmt: ast.stmt) -> list[ast.AST]:
    if isinstance(stmt, ast.If) or isinstance(stmt, ast.While):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [i.context_expr for i in stmt.items]
    if isinstance(stmt, ast.Match):
        return [stmt.subject]
    if isinstance(stmt, (ast.Try, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or type(stmt).__name__ == "TryStar":
        return []
    return [stmt]


def _terminates(body: list[ast.stmt], module: _ModuleAnalyzer) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        name = module._name(last.value.func)
        return name in TERMINATING_CALLS or name.split(".")[-1] in ("abort", "exit")
    return False


def _anchored(call: ast.Call) -> bool:
    pattern = call.args[0] if call.args else None
    if isinstance(call.func, ast.Attribute) and not (isinstance(call.func.value, ast.Name) and call.func.value.id == "re"):
        return False  # compiled pattern: anchoring unknown
    return isinstance(pattern, ast.Constant) and isinstance(pattern.value, str) and pattern.value.endswith(("$", "\\Z"))


def _names(node: ast.AST) -> set[str]:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(ast.unparse(n))
    return out


def _union(groups) -> list[Trace]:
    seen: dict[Trace, None] = {}
    for g in groups:
        for t in g:
            seen.setdefault(t, None)
    return _cap(list(seen))


def _cap(traces: list[Trace]) -> list[Trace]:
    return traces[:MAX_TRACES_PER_VAR]


def _merge(a: Env, b: Env) -> Env:
    out = dict(a)
    for k, v in b.items():
        out[k] = _union([out.get(k, []), v])
    return out
