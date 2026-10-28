"""Render a scan as a PDF report containing every finding.

Layout:
  1. Cover: repository, date, languages, totals by severity and type, coverage notes
  2. Findings index: one row per finding (severity, type, title, location)
  3. Finding details: explanation, attack scenario, impact, vulnerable + fixed
     code, package versions, references, confidence

Uses ReportLab with its bundled Bitstream Vera fonts, so output is identical on
Windows, macOS and the slim Docker image (no system fonts needed). Characters the
font can't draw are transliterated instead of rendering as black boxes.
"""
from __future__ import annotations

import io
import os
from datetime import datetime
from typing import Optional
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from models.schemas import Vulnerability

# --------------------------------------------------------------------------- fonts

_FONT_DIR = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
for _name, _file in (("Vera", "Vera.ttf"), ("Vera-Bold", "VeraBd.ttf"), ("Vera-Italic", "VeraIt.ttf")):
    if _name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(_name, os.path.join(_FONT_DIR, _file)))
pdfmetrics.registerFontFamily("Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic")
_GLYPHS = set(pdfmetrics.getFont("Vera").face.charToGlyph)

_TRANSLIT = {
    "→": "->", "←": "<-", "⇒": "=>", "…": "...", "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "•": "*", "·": "-", "✓": "v", "✗": "x", "≥": ">=", "≤": "<=", "≠": "!=",
    # LLM output often uses typographic hyphens/spaces the font lacks
    "‐": "-", "‑": "-", "‒": "-", "−": "-", "­": "",
    " ": " ", " ": " ", " ": " ", "​": "", "\t": "    ",
}


def _clean(text: str, glyphs: Optional[set[int]] = _GLYPHS) -> str:
    """Replace characters the font can't render (glyphs=None -> Latin-1 for Courier)."""
    out = []
    for ch in text or "":
        if ch in "\n\r":
            out.append(ch)
            continue
        ch = _TRANSLIT.get(ch, ch)
        if len(ch) > 1:
            out.append(ch)
        elif (glyphs is None and ord(ch) < 256) or (glyphs is not None and ord(ch) in glyphs):
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _p(text: str) -> str:
    """Text for a Paragraph: transliterate, XML-escape, keep line breaks."""
    return escape(_clean(text)).replace("\n", "<br/>")


# --------------------------------------------------------------------------- styles

INK = colors.HexColor("#0b0b0b")
INK_2 = colors.HexColor("#52514e")
MUTED = colors.HexColor("#898781")
HAIRLINE = colors.HexColor("#e1e0d9")
PANEL = colors.HexColor("#f6f5f2")

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLOR = {
    "critical": colors.HexColor("#b42318"),
    "high": colors.HexColor("#c4500f"),
    "medium": colors.HexColor("#a15c07"),
    "low": colors.HexColor("#1d5fb8"),
}
CATEGORY_LABEL = {"code": "Code", "dependency": "Dependency", "secret": "Secret"}

_base = ParagraphStyle("base", fontName="Vera", fontSize=9, leading=12.5, textColor=INK, alignment=TA_LEFT)
S = {
    "title": ParagraphStyle("title", parent=_base, fontName="Vera-Bold", fontSize=22, leading=27),
    "subtitle": ParagraphStyle("subtitle", parent=_base, fontSize=11, leading=15, textColor=INK_2),
    "h1": ParagraphStyle("h1", parent=_base, fontName="Vera-Bold", fontSize=14, leading=18, spaceBefore=6, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=_base, fontName="Vera-Bold", fontSize=11, leading=14.5),
    # keepWithNext: a section heading never ends a page without its content
    "label": ParagraphStyle("label", parent=_base, fontName="Vera-Bold", fontSize=8.5, textColor=INK_2,
                            spaceBefore=7, spaceAfter=2, keepWithNext=1),
    "body": _base,
    "small": ParagraphStyle("small", parent=_base, fontSize=8, leading=10.5, textColor=INK_2),
    "cell": ParagraphStyle("cell", parent=_base, fontSize=8, leading=10),
    "cell_bold": ParagraphStyle("cell_bold", parent=_base, fontName="Vera-Bold", fontSize=8, leading=10),
    "code": ParagraphStyle("code", parent=_base, fontName="Courier", fontSize=7.5, leading=9.5),
}

CODE_WRAP = 100  # characters per line in code blocks at 7.5pt Courier on A4


# --------------------------------------------------------------------------- building blocks

def _severity_cell(sev: str) -> Paragraph:
    color = SEVERITY_COLOR.get(sev, INK_2)
    return Paragraph(f'<font color="{color.hexval()}"><b>{sev.upper()}</b></font>', S["cell"])


def _location(v: Vulnerability) -> str:
    return f"{v.file}:{v.line}" if v.line else v.file


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"


def _code_block(text: str) -> Table:
    lines = _clean(text, glyphs=None).splitlines() or [""]
    if len(lines) > 60:
        lines = lines[:60] + [f"... ({len(lines) - 60} more lines)"]
    # Preformatted ignores backColor, so a one-cell table draws the panel
    block = Table([[Preformatted("\n".join(lines), S["code"], maxLineLength=CODE_WRAP, newLineChars="")]],
                  colWidths=[170 * mm])
    block.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return block


def _table(data, widths, header=True, extra=()) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, HAIRLINE),
    ]
    if header:
        style += [("LINEBELOW", (0, 0), (-1, 0), 0.8, INK_2)]
    t.setStyle(TableStyle(style + list(extra)))
    return t


def _summary(findings: list[Vulnerability]) -> list:
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_cat: dict[str, dict[str, int]] = {c: {s: 0 for s in SEVERITY_ORDER} for c in CATEGORY_LABEL}
    for v in findings:
        sev = v.severity if v.severity in by_sev else "low"
        by_sev[sev] += 1
        by_cat.setdefault(v.category.value, {s: 0 for s in SEVERITY_ORDER})[sev] += 1

    head = [Paragraph("<b>Type</b>", S["cell"])] + [
        Paragraph(f"<b>{s.capitalize()}</b>", S["cell"]) for s in SEVERITY_ORDER
    ] + [Paragraph("<b>Total</b>", S["cell"])]
    rows = [head]
    for cat, label in CATEGORY_LABEL.items():
        counts = by_cat.get(cat, {})
        rows.append([Paragraph(label, S["cell"])] + [Paragraph(str(counts.get(s, 0)), S["cell"]) for s in SEVERITY_ORDER]
                    + [Paragraph(str(sum(counts.values())), S["cell_bold"])])
    rows.append([Paragraph("<b>All</b>", S["cell"])] + [Paragraph(f"<b>{by_sev[s]}</b>", S["cell"]) for s in SEVERITY_ORDER]
                + [Paragraph(f"<b>{len(findings)}</b>", S["cell"])])
    w = 170 * mm
    return [_table(rows, [w * 0.30] + [w * 0.14] * 5, extra=[("LINEABOVE", (0, -1), (-1, -1), 0.8, INK_2)])]


def _index(findings: list[Vulnerability]) -> Table:
    rows = [[Paragraph(f"<b>{h}</b>", S["cell"]) for h in ("#", "Severity", "Type", "Finding", "Location")]]
    for i, v in enumerate(findings, 1):
        rows.append([
            Paragraph(str(i), S["cell"]),
            _severity_cell(v.severity),
            Paragraph(CATEGORY_LABEL.get(v.category.value, v.category.value), S["cell"]),
            Paragraph(f'<a href="#f{i}" color="#0b0b0b">{_p(_truncate(v.title, 140))}</a>', S["cell"]),
            Paragraph(_p(_location(v)), S["cell"]),
        ])
    w = 170 * mm
    return _table(rows, [w * 0.06, w * 0.12, w * 0.14, w * 0.43, w * 0.25])


def _finding(i: int, v: Vulnerability) -> list:
    sev_color = SEVERITY_COLOR.get(v.severity, INK_2).hexval()
    header = Paragraph(
        f'<a name="f{i}"/><font color="{MUTED.hexval()}">#{i}</font>&nbsp;&nbsp;'
        f'<font color="{sev_color}">{escape(v.severity.upper())}</font>&nbsp;&nbsp;{_p(v.title)}',
        S["h2"],
    )

    meta = [
        ["Type", f"{CATEGORY_LABEL.get(v.category.value, v.category.value)} (detected by {v.source})"],
        ["Location", _location(v)],
        ["Rule / advisory", v.rule_id],
    ]
    if v.package:
        meta.append(["Package", f"{v.package} {v.installed_version} -> {v.fixed_version or 'no fixed version published'}"])
    if v.scanner_severity and v.scanner_severity != v.severity:
        meta.append(["Scanner severity", v.scanner_severity])
    meta.append(["Confidence", f"{round(v.confidence * 100)}%   (false-positive risk {round(v.false_positive_likelihood * 100)}%)"])
    if v.fix_time_estimate:
        meta.append(["Estimated fix time", v.fix_time_estimate])
    meta_table = _table(
        [[Paragraph(k, S["small"]), Paragraph(_p(val), S["cell"])] for k, val in meta],
        [35 * mm, 135 * mm], header=False,
        extra=[("LINEBELOW", (0, 0), (-1, -1), 0.3, HAIRLINE)],
    )

    flow: list = [CondPageBreak(45 * mm), KeepTogether([header, Spacer(1, 4), meta_table])]

    def section(label: str, text: str, code: bool = False) -> None:
        if not text or "AI enhancement unavailable" in text:
            return
        flow.append(Paragraph(label, S["label"]))
        flow.append(_code_block(text) if code else Paragraph(_p(text), S["body"]))

    section("Explanation" if v.category.value == "code" else "Details", v.ai_explanation)
    section("Attack scenario", v.attack_scenario)
    section("Business impact", v.business_impact)
    if v.category.value == "secret":
        section("Location (secret value masked)", v.vulnerable_code, code=True)
        section("Remediation", v.fixed_code, code=True)
    else:
        section("Vulnerable code" if v.category.value == "code" else "Installed", v.vulnerable_code, code=True)
        section("Suggested fix" if v.category.value == "code" else "Upgrade to", v.fixed_code, code=True)
    if v.references:
        flow.append(Paragraph("References", S["label"]))
        for url in v.references:
            flow.append(Paragraph(f'<a href="{escape(url)}" color="#1d5fb8">{_p(url)}</a>', S["small"]))
    flow.append(Spacer(1, 10))
    return flow


# --------------------------------------------------------------------------- document

def render_pdf(
    *,
    repo_name: str,
    repo_url: str,
    scanned_at: str,
    languages: list[str],
    findings: list[Vulnerability],
    warnings: list[str],
    scan_id: str = "",
) -> bytes:
    buf = io.BytesIO()
    try:
        when = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).strftime("%d %b %Y, %H:%M UTC")
    except ValueError:
        when = scanned_at

    def on_page(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Vera", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 10 * mm, _clean(f"Security scan report - {repo_name}"))
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=_clean(f"Security scan report - {repo_name}"), author="AI Security Scanner",
        subject=_clean(f"{len(findings)} findings for {repo_url}"),
    )

    story: list = [
        Paragraph("Security Scan Report", S["title"]),
        Spacer(1, 4),
        Paragraph(_p(repo_name), S["subtitle"]),
        Spacer(1, 10),
        _table(
            [[Paragraph(k, S["small"]), Paragraph(_p(v), S["cell"])] for k, v in (
                ("Repository", repo_url),
                ("Scanned", when),
                ("Languages", ", ".join(languages) or "none detected"),
                ("Detectors", "Semgrep (code), OSV.dev (dependencies), secret scanner, LLM analysis"),
                *([("Scan ID", scan_id)] if scan_id else []),
            )],
            [35 * mm, 135 * mm], header=False,
        ),
        Spacer(1, 14),
        Paragraph("Summary", S["h1"]),
        *_summary(findings),
    ]

    if warnings:
        story += [Spacer(1, 10), Paragraph("Coverage notes", S["h1"])]
        story += [Paragraph(f"- {_p(w)}", S["body"]) for w in warnings]

    if not findings:
        story += [Spacer(1, 14), Paragraph("No problems were found.", S["body"])]
    else:
        story += [
            Spacer(1, 10),
            Paragraph(
                "Findings are ordered by severity. Secret values are masked. Each row in the index "
                "links to the full details.", S["small"]),
            PageBreak(),
            Paragraph(f"Findings index ({len(findings)})", S["h1"]),
            _index(findings),
            PageBreak(),
            Paragraph("Finding details", S["h1"]),
        ]
        for i, v in enumerate(findings, 1):
            story += _finding(i, v)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
