"""``check`` — the deterministic grade (no LLM, no egress).

Decodes via ``render``, runs the deterministic signal checks, and assembles a verdict-bearing
:class:`audel.models.Report` with time-grounded issues. This is the "trustworthy grounding" path:
it never reaches the network and never loads a backend.
"""

from __future__ import annotations

import asyncio

from ..config import Settings, load_settings
from ..errors import AudelError
from ..models import Issue, IssueKind, Report, Severity, Span, Verdict, verdict_from_issues
from ..signals.checks import evaluate
from .render import _render_sync

# IssueKinds the deterministic DSP path is able to emit (advertised on the Report).
DSP_CAPABILITIES = [
    IssueKind.SILENCE, IssueKind.CLIPPING, IssueKind.LOUDNESS, IssueKind.TRUNCATION,
    IssueKind.MISSING_AUDIO, IssueKind.DECODE_ERROR, IssueKind.DURATION,
]


def _check_sync(source, settings: Settings) -> Report:
    try:
        rr = _render_sync(source, settings)
    except AudelError as e:
        # A guard/decode failure is itself a gradeable, time-grounded fail (not a crash).
        return Report(
            verdict=Verdict.FAIL,
            summary=f"could not decode: {e}",
            issues=[Issue.make(IssueKind.DECODE_ERROR, Severity.CRITICAL, str(e),
                               span=Span(start_ms=0, end_ms=0))],
            capabilities=DSP_CAPABILITIES, backend="dsp", audio_path=str(source),
        )
    assert rr.measurements is not None  # set on every successful render
    issues = evaluate(rr.measurements, settings)
    return Report(
        verdict=verdict_from_issues(issues),  # type: ignore[arg-type]  # Issue <: IssueBase
        summary=_summarize(rr, issues),
        issues=issues,
        capabilities=DSP_CAPABILITIES,
        backend="dsp",
        sample_rate=rr.sample_rate, channels=rr.channels, duration_ms=rr.duration_ms,
        audio_path=str(source),
    )


def _summarize(rr, issues) -> str:
    if not issues:
        return f"audio ok: {rr.duration_ms or 0}ms, {rr.channels or 0}ch, {rr.integrated_lufs} LUFS"
    kinds = ", ".join(sorted({i.kind.value for i in issues}))
    return f"{len(issues)} issue(s): {kinds}"


async def check(source, *, settings: Settings | None = None, brief=None) -> Report:
    """Deterministically grade ``source``. ``brief`` conformance grading arrives in Phase 2."""
    settings = settings or load_settings()
    return await asyncio.to_thread(_check_sync, source, settings)
