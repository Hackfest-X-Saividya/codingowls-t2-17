"""Hugging Face Space (Gradio SDK, free CPU) for the runtime-error checker.

Upload this file with checker.py, server.py, requirements.txt, packages.txt and the
README.md from this folder. Each check runs inside the button click (clone, read,
delete), exactly as in server.py; the scanned code is never executed.

Local try-out (from the runtime folder):  pip install gradio  then  python huggingface/app.py
"""
from __future__ import annotations

import html
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import gradio as gr

HERE = Path(__file__).resolve().parent
if not (HERE / "checker.py").exists():  # running from runtime/huggingface/ inside the repository
    sys.path.insert(0, str(HERE.parent))

import server  # noqa: E402  (after the path fix above)

SEVERITY_COLOR = {"high": "#e5484d", "medium": "#f5a524", "low": "#5b8def"}

CSS = """
.rc {font-size: 14px; color: var(--body-text-color);}
.rc .tiles {display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 8px; margin: 8px 0 12px;}
.rc .tile {border: 1px solid var(--border-color-primary); border-radius: 8px; padding: 10px;}
.rc .tile b {display: block; font-size: 22px;}
.rc .note {border-left: 3px solid #f5a524; padding: 6px 10px; margin: 6px 0; background: var(--block-background-fill);}
.rc h3 {margin: 18px 0 6px; font-size: 15px; word-break: break-all;}
.rc details {border: 1px solid var(--border-color-primary); border-radius: 8px; margin: 6px 0; padding: 8px 10px;}
.rc summary {cursor: pointer;}
.rc .sev {display: inline-block; color: #fff; border-radius: 4px; padding: 1px 6px; font-size: 12px; margin-right: 6px;}
.rc pre {overflow-x: auto; background: var(--background-fill-secondary); padding: 8px; border-radius: 6px; font-size: 12.5px;}
.rc .hit {background: rgba(229, 72, 77, .22); display: inline-block; min-width: 100%;}
.rc .muted {opacity: .75;}
"""


def _code(problem: dict[str, Any]) -> str:
    if not problem.get("code"):
        return ""
    lines = []
    for n, text in enumerate(problem["code"].split("\n"), start=problem["code_start"]):
        row = f"{n:>5}  {html.escape(text)}"
        lines.append(f'<span class="hit">{row}</span>' if n == problem["line"] else row)
    return "<pre>" + "\n".join(lines) + "</pre>"


def render(report: dict[str, Any]) -> str:
    e = html.escape
    s, files = report["summary"], report["files_checked"]
    commit = (report.get("commit") or "")[:7]
    out = [f'<div class="rc"><p><b>{e(report["repo_name"])}</b>'
           f'{f" <span class=muted>@ {e(commit)}</span>" if commit else ""} · '
           f'{files["python"]} Python and {files["javascript"]} JavaScript files checked</p>',
           '<div class="tiles">']
    for label, value in (("Problems", s["total"]), ("High", s["high"]), ("Medium", s["medium"]), ("Low", s["low"])):
        out.append(f'<div class="tile">{label}<b>{value}</b></div>')
    out.append("</div>")
    out += [f'<div class="note">{e(w)}</div>' for w in report["warnings"]]
    if not report["problems"]:
        out.append("<p>No runtime errors found in the files that were checked.</p></div>")
        return "".join(out)

    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in report["problems"]:
        by_file[p["file"]].append(p)
    for file, problems in by_file.items():
        out.append(f"<h3>{e(file)} <span class=muted>({len(problems)})</span></h3>")
        for p in problems:
            color = SEVERITY_COLOR.get(p["severity"], "#888")
            out.append(
                f'<details><summary><span class="sev" style="background:{color}">{e(p["severity"])}</span>'
                f'<b>{e(p["title"])}</b> · line {p["line"]}<br><span class="muted">{e(p["error"])}: '
                f'{e(p["message"])}</span></summary>'
                f'<p>{e(p["explanation"])}</p><p><b>Impact:</b> {e(p["impact"])}</p>{_code(p)}'
                f'<p class="muted">Confidence: {e(p["confidence"])} · {e(p["rule"])}</p></details>')
    out.append("</div>")
    return "".join(out)


def run_check(repo_url: str) -> str:
    try:
        return render(server.check_repository(repo_url))
    except server.CheckError as exc:
        return f'<div class="rc"><div class="note">{html.escape(str(exc))}</div></div>'


with gr.Blocks(title="Runtime Error Check", css=CSS) as demo:
    gr.Markdown("## Runtime error check\nFinds code that will crash when it runs (syntax errors, undefined names, "
                "broken imports, wrong call arguments) by reading a **public** GitHub repository. "
                "The repository's code is never executed.")
    with gr.Row():
        url = gr.Textbox(label="GitHub repository", placeholder="https://github.com/owner/repo", scale=5)
        button = gr.Button("Check", variant="primary", scale=1)
    result = gr.HTML()
    button.click(run_check, inputs=url, outputs=result, concurrency_limit=server.MAX_CONCURRENT)
    url.submit(run_check, inputs=url, outputs=result, concurrency_limit=server.MAX_CONCURRENT)

if __name__ == "__main__":
    demo.launch()
