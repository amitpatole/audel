"""Human-readable QC report — a single, self-contained HTML page for an operator.

The JSON :class:`~audel.models.Report` is what agents and pipelines consume; this page is what a
QC operator or a producer reads. It is fully self-contained (no scripts, no external requests, no
fonts fetched), so it can be attached to a ticket or archived with the deliverable.

Security: every value that reaches the page (file name, container tags, issue messages, transcript
excerpts, claim text) can be attacker-controlled, so ALL of it goes through :func:`html.escape`.
No script is emitted and a strict Content-Security-Policy meta tag forbids any from loading.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from . import __version__
from .models import Report

_VERDICT_INK = {"pass": "#2f6b3a", "warn": "#90641a", "fail": "#9a2b22"}
_SEV_RANK = {"critical": 0, "error": 1, "warning": 2, "info": 3}

_CSS = """
:root{--bg:#f7f5f1;--surface:#fffdf9;--panel:#efece4;--ink:#1b1a17;--muted:#6b6862;
--faint:#918d84;--rule:#e3ded4;--accent:#c4943f;--accent-ink:#90641a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:40px 16px 64px}
h1,h2{font-family:"Source Serif 4",Georgia,serif;font-weight:600;letter-spacing:-.01em}
h1{font-size:28px;margin:0 0 4px}h1:after{content:"";display:block;width:40px;height:2px;
background:var(--accent);margin-top:10px}h2{font-size:19px;margin:36px 0 10px}
.eyebrow{color:var(--accent-ink);text-transform:uppercase;letter-spacing:.08em;font-size:12px}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,"JetBrains Mono",Menlo,monospace;font-size:13px}
.verdict{display:inline-block;font-weight:600;letter-spacing:.06em;padding:2px 10px;
border:1px solid currentColor;border-radius:3px;margin-right:10px}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--rule)}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
th{font-weight:600;font-size:13px;color:var(--muted);background:var(--panel)}
tr:last-child td{border-bottom:0}.timeline{background:var(--surface);border:1px solid var(--rule);
padding:12px}.tl-row{display:flex;align-items:center;gap:10px;margin:4px 0}
.tl-label{width:150px;flex:none;font-size:12px;color:var(--muted);overflow:hidden;
text-overflow:ellipsis;white-space:nowrap}.tl-bar{position:relative;flex:1;height:12px;
background:var(--panel)}.tl-span{position:absolute;top:0;height:12px;min-width:2px}
footer{margin-top:48px;padding-top:12px;border-top:1px solid var(--rule);color:var(--faint);
font-size:13px}.mark{font-family:"Source Serif 4",Georgia,serif;font-style:italic;color:var(--accent-ink)}
@media (max-width:640px){.tl-label{width:90px}th,td{padding:6px}}
"""


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _fmt_ms(ms: int | None) -> str:
    if ms is None:
        return ""
    s = ms / 1000.0
    m, sec = divmod(s, 60)
    return f"{int(m):d}:{sec:05.2f}"


def _num(v, unit: str = "") -> str:
    return "" if v is None else f"{v:.1f}{unit}"


def render_html(report: Report, *, source_name: str = "", generated_at: datetime | None = None) -> str:
    when = (generated_at or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M UTC")
    verdict = report.verdict.value
    ink = _VERDICT_INK.get(verdict, "#1b1a17")
    dur = report.duration_ms or 0
    issues = sorted(report.issues, key=lambda i: (_SEV_RANK.get(i.severity.value, 9),
                                                  i.span.start_ms if i.span else 0))
    out: list[str] = []
    out.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    out.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    out.append("<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
               "style-src 'unsafe-inline'; img-src 'none'; script-src 'none'\">")
    out.append(f"<title>Audel QC report</title><style>{_CSS}</style></head><body><main>")
    out.append("<div class='eyebrow'>Audel QC report</div>")
    out.append(f"<h1>{_e(source_name) or 'Audio deliverable'}</h1>")
    out.append(f"<p><span class='verdict' style='color:{ink}'>{_e(verdict.upper())}</span>"
               f"{_e(report.summary)}</p>")
    out.append("<table><tbody>")
    for k, v in (("Delivery spec", report.spec or "none"), ("Duration", _fmt_ms(dur)),
                 ("Sample rate", f"{report.sample_rate} Hz" if report.sample_rate else ""),
                 ("Channels", report.channels), ("Graded by", report.backend),
                 ("Generated", when)):
        out.append(f"<tr><th style='width:180px'>{_e(k)}</th><td>{_e(v)}</td></tr>")
    out.append("</tbody></table>")

    if report.tracks:
        out.append("<h2>Tracks</h2><table><thead><tr><th>#</th><th>Codec / layout</th>"
                   "<th>Language</th><th>Integrated</th><th>Speech-gated</th><th>True peak</th>"
                   "<th>Max short-term</th><th>LRA</th></tr></thead><tbody>")
        for t in report.tracks:
            out.append(
                f"<tr><td>{t.index}</td><td>{_e(t.codec)} {_e(t.layout or f'{t.channels}ch')}</td>"
                f"<td>{_e(t.language or '')}</td><td>{_num(t.integrated_lufs, ' LUFS')}</td>"
                f"<td>{_num(t.dialogue_lufs, ' LUFS')}</td><td>{_num(t.true_peak_dbtp, ' dBTP')}</td>"
                f"<td>{_num(t.max_short_term_lufs, ' LUFS')}</td><td>{_num(t.lra, ' LU')}</td></tr>")
        out.append("</tbody></table>")

    out.append(f"<h2>Findings ({len(issues)})</h2>")
    if not issues:
        out.append("<p class='muted'>No issues found.</p>")
    else:
        if dur > 0:
            out.append("<div class='timeline' aria-label='Issue timeline'>")
            for i in issues[:60]:
                if not i.span:
                    continue
                left = max(0.0, min(100.0, 100.0 * i.span.start_ms / dur))
                width = max(0.3, min(100.0 - left, 100.0 * (i.span.end_ms - i.span.start_ms) / dur))
                color = _VERDICT_INK["fail"] if i.severity.value in ("critical", "error") else \
                    _VERDICT_INK["warn"]
                label = i.detail.get("check") or i.kind.value
                out.append(f"<div class='tl-row'><div class='tl-label'>{_e(label)}</div>"
                           f"<div class='tl-bar'><div class='tl-span' style='left:{left:.2f}%;"
                           f"width:{width:.2f}%;background:{color}'></div></div></div>")
            out.append("</div><br>")
        out.append("<table><thead><tr><th>Severity</th><th>When</th><th>Check</th>"
                   "<th>Finding</th></tr></thead><tbody>")
        for i in issues:
            when_s = f"{_fmt_ms(i.span.start_ms)}–{_fmt_ms(i.span.end_ms)}" if i.span else ""
            check = i.detail.get("check") or i.kind.value
            out.append(f"<tr><td>{_e(i.severity.value)}</td><td class='mono'>{_e(when_s)}</td>"
                       f"<td class='mono'>{_e(check)}</td><td>{_e(i.message)}</td></tr>")
        out.append("</tbody></table>")

    if report.conformance and report.conformance.claims:
        out.append("<h2>Requirements</h2><table><thead><tr><th>Importance</th><th>Status</th>"
                   "<th>Requirement</th><th>Evidence</th></tr></thead><tbody>")
        for c in report.conformance.claims:
            out.append(f"<tr><td>{_e(c.importance.value)}</td><td>{_e(c.status.value)}</td>"
                       f"<td>{_e(c.text)}</td><td class='muted'>{_e(c.evidence)}</td></tr>")
        out.append("</tbody></table>")

    out.append(f"<footer>Generated by Audel {_e(__version__)}. Deterministic findings come from "
               "ffmpeg's BS.1770 meters and signal statistics; advisory findings are marked with "
               "lower confidence in the JSON report. <span class='mark'>— amitpatole</span></footer>")
    out.append("</main></body></html>")
    return "".join(out)
