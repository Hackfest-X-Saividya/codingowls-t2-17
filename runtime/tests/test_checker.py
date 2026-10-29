import shutil
import textwrap
from pathlib import Path

import pytest

import checker


def make_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def problems(root: Path) -> list[tuple[str, str, int]]:
    return [(p["rule"].removeprefix("runtime/"), p["file"], p["line"]) for p in checker.check(root)["problems"]]


def test_syntax_error(tmp_path):
    make_repo(tmp_path, {"app.py": "def f(:\n    pass\n"})
    assert problems(tmp_path) == [("syntax-error", "app.py", 1)]


def test_bom_is_not_a_syntax_error(tmp_path):
    (tmp_path / "app.py").write_bytes(b"\xef\xbb\xbfx = 1\n")
    assert problems(tmp_path) == []


def test_undefined_and_unbound_names(tmp_path):
    make_repo(tmp_path, {"app.py": """\
        import os
        total = 0

        def handler(request):
            return reqeust.args

        def add(n):
            total += n
            return total

        def fine():
            try:
                unicode
            except NameError:
                pass
            return os.getcwd(), len([])
        """})
    found = problems(tmp_path)
    assert ("undefined-name", "app.py", 5) in found
    assert ("undefined-local", "app.py", 8) in found
    assert len(found) == 2


def test_relative_and_local_imports(tmp_path):
    make_repo(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/models.py": "class User: pass\nVERSION = 1\n",
        "pkg/sub/__init__.py": "",
        "pkg/views.py": """\
            from .models import User, Missing
            from .nothere import x
            from . import models, sub
            from pkg.models import VERSION, Gone
            from pkg.absent import y
            import pkg.ghost
            import requests                    # third-party: not checked
            from flask import Flask            # third-party: not checked
            try:
                from .optional import z        # guarded
            except ImportError:
                z = None
            """,
    })
    found = problems(tmp_path)
    assert ("missing-name", "pkg/views.py", 1) in found
    assert ("missing-module", "pkg/views.py", 2) in found
    assert ("missing-name", "pkg/views.py", 4) in found
    assert ("missing-module", "pkg/views.py", 5) in found
    assert ("missing-module", "pkg/views.py", 6) in found
    assert len(found) == 5


def test_folders_named_like_installed_packages_are_not_local(tmp_path):
    make_repo(tmp_path, {
        "docs/celery/example.py": "from celery.result import AsyncResult\n",  # docs/celery has no __init__.py
        "tools/yaml/__init__.py": "",  # not on main.py's import path
        "main.py": "import celery.result\nfrom yaml import safe_load\n",
        "src/mylib/__init__.py": "def run(): pass\n",
        "tests/test_mylib.py": "from mylib import run, nope\n",  # src layout: an installed package
    })
    assert problems(tmp_path) == [("missing-name", "tests/test_mylib.py", 1)]


def test_dynamic_module_names_are_not_reported(tmp_path):
    make_repo(tmp_path, {
        "lazy.py": "def __getattr__(name):\n    return name\n",
        "star.py": "from os.path import *\n",
        "main.py": "from lazy import anything\nfrom star import join\n",
    })
    assert problems(tmp_path) == []


def test_call_arguments(tmp_path):
    make_repo(tmp_path, {
        "lib.py": """\
            def connect(host, port=5432, *, timeout):
                return host, port, timeout

            class Point:
                def __init__(self, x, y):
                    self.x, self.y = x, y

            class Empty:
                pass
            """,
        "main.py": """\
            from lib import connect, Point, Empty

            def area(w, h):
                return w * h

            area(1)
            area(1, 2, 3)
            area(1, h=2, w=3)
            area(1, depth=2)
            connect("db")
            connect("db", 1, 2, timeout=3)
            Point(1)
            Empty(1)
            area(1, 2)
            connect("db", timeout=1)
            Point(1, y=2)
            area(*[1, 2])

            def shadow(area):
                return area(1, 2, 3)
            """,
    })
    found = [p for p in problems(tmp_path)]
    assert found == [("call-arguments", "main.py", n) for n in (6, 7, 8, 9, 10, 11, 12, 13)]


def test_decorated_and_redefined_functions_are_skipped(tmp_path):
    make_repo(tmp_path, {"app.py": """\
        import functools

        @functools.lru_cache
        def cached(a):
            return a

        def twice(a):
            return a

        def twice(a, b):
            return a + b

        class Model(dict):
            pass

        cached(1, 2)
        twice(1, 2)
        Model(a=1)
        """})
    assert problems(tmp_path) == []


def test_format_strings(tmp_path):
    make_repo(tmp_path, {"app.py": """\
        a = "%s and %s" % (1,)
        b = "{name}".format(other=1)
        c = "{} {}".format(1, 2, 3)
        """})
    assert problems(tmp_path) == [("format-string", "app.py", 1), ("format-string", "app.py", 2)]


def test_report_shape(tmp_path):
    make_repo(tmp_path, {"app.py": "x = 1\nprint(y)\nz = 2\n"})
    report = checker.check(tmp_path)
    assert report["files_checked"] == {"python": 1, "javascript": 0}
    assert report["summary"] == {"total": 1, "high": 0, "medium": 1, "low": 0}
    p = report["problems"][0]
    assert p["error"] == "NameError" and p["message"] == "undefined name 'y'"
    assert p["code_start"] == 1 and p["code"].splitlines()[1] == "print(y)"


def test_skips_dependency_folders(tmp_path):
    make_repo(tmp_path, {"venv/lib/bad.py": "def (", "node_modules/x/bad.js": "if (", ".hidden/bad.py": "def ("})
    assert problems(tmp_path) == []


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not installed")
def test_javascript_syntax(tmp_path):
    make_repo(tmp_path, {
        "src/broken.js": "const a = 1;\nif (a {\n}\n",
        "src/broken.mjs": "import fs from 'fs';\nexport const = 2;\n",
        "src/ok.mjs": "import fs from 'fs';\nexport const a = await Promise.resolve(fs);\n",
        "src/ok.cjs": "#!/usr/bin/env node\nmodule.exports = require('./x');\nreturn;\n",
        "src/component.js": "export default function App() { return <div/>; }\n",
    })
    assert problems(tmp_path) == [("js-syntax-error", "src/broken.js", 2), ("js-syntax-error", "src/broken.mjs", 2)]


def test_cli_fail_on(tmp_path, capsys):
    make_repo(tmp_path, {"app.py": "print(y)\n"})
    assert checker.main([str(tmp_path), "--fail-on", "high"]) == 0
    assert checker.main([str(tmp_path), "--fail-on", "medium"]) == 1
    assert "app.py:1" in capsys.readouterr().out


def test_expected_errors_are_not_reported(tmp_path):
    make_repo(tmp_path, {"test_app.py": """\
        import pytest
        from typing import TYPE_CHECKING

        def add(a, b):
            return a + b

        def test_bad_call():
            with pytest.raises(TypeError):
                add(1)

        def detect():
            try:
                return get_ipython()
            except NameError:
                return None

        def wrong_handler():
            try:
                return add(1)
            except KeyError:
                return None

        def hinted(x: "SomeType") -> "Other":
            y: Missing = x
            return y

        mod_level: "AlsoMissing" = 1
        """})
    assert problems(tmp_path) == [("call-arguments", "test_app.py", 19)]


def test_test_data_docs_and_templates_are_skipped(tmp_path):
    make_repo(tmp_path, {
        "tests/data/cases/broken.py": "def (",
        "docs/snippet.py": "print(undefined)\n",
        "app/templates/catalog.js": "{% autoescape off %}\nvar x = 1;\n",
        "data/real.py": "def (",  # a data/ folder outside tests is real code
    })
    assert problems(tmp_path) == [("syntax-error", "data/real.py", 1)]
    assert "Python " in checker.check(tmp_path)["warnings"][0]


def test_module_attributes_can_be_imported(tmp_path):
    make_repo(tmp_path, {"pkg/__init__.py": "", "pkg/admin.py": "x = 1\n",
                         "pkg/tests.py": "from .admin import __file__ as admin_file, x\n"})
    assert problems(tmp_path) == []


def test_suppression_comments_are_respected(tmp_path):
    make_repo(tmp_path, {"app.py": """\
        def is_jupyter():
            try:
                get_ipython  # type: ignore[name-defined]
            except NameError:
                return False
            return get_ipython()  # type: ignore[name-defined]

        value = undefined_thing  # noqa: F821
        other = really_undefined
        """})
    assert problems(tmp_path) == [("undefined-name", "app.py", 9)]
