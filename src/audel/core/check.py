"""``check`` — the deterministic grade (no LLM, no egress).

Decodes via ``render``, runs the deterministic signal checks, and — when a ``brief`` is given —
transcribes locally (faster-whisper) and grades language/phrase/duration claims. Still no network:
the ``local`` backend is offline. Assembles a verdict-bearing :class:`audel.models.Report` with
time-grounded issues and a populated :class:`Conformance`.
"""

from __future__ import annotations

import asyncio

from ..backends.local import LocalBackend
from ..config import Settings, load_settings
from ..errors import AudelError
from ..models import (
    Conformance,
    Issue,
    IssueKind,
    Report,
    Severity,
    Span,
    Verdict,
    verdict_from_issues,
)
from ..signals.checks import evaluate
from ..speech.conformance import grade
from .render import _render_sync

# IssueKinds the deterministic path is able to emit (advertised on the Report).
DSP_CAPABILITIES = [
    IssueKind.SILENCE, IssueKind.CLIPPING, IssueKind.LOUDNESS, IssueKind.TRUNCATION,
    IssueKind.MISSING_AUDIO, IssueKind.DECODE_ERROR, IssueKind.DURATION,
    IssueKind.TRANSCRIPT_MISMATCH, IssueKind.WRONG_LANGUAGE,
]


def _decode_error(source, e: Exception) -> Report:
    return Report(
        verdict=Verdict.FAIL,
        summary=f"could not decode: {e}",
        issues=[Issue.make(IssueKind.DECODE_ERROR, Severity.CRITICAL, str(e),
                           span=Span(start_ms=0, end_ms=0))],
        capabilities=DSP_CAPABILITIES, backend="dsp", audio_path=str(source),
    )


def _summarize(rr, issues) -> str:
    if not issues:
        return f"audio ok: {rr.duration_ms or 0}ms, {rr.channels or 0}ch, {rr.integrated_lufs} LUFS"
    kinds = ", ".join(sorted({i.kind.value for i in issues}))
    return f"{len(issues)} issue(s): {kinds}"


async def check(source, *, settings: Settings | None = None, brief=None) -> Report:
    """Deterministically grade ``source``; with ``brief``, also grade transcript claims via the
    OFFLINE local ASR only. This path never constructs a network backend — no egress, ever."""
    settings = settings or load_settings()
    try:
        rr = await asyncio.to_thread(_render_sync, source, settings)
    except AudelError as e:
        return _decode_error(source, e)

    issues: list[Issue] = list(evaluate(rr.measurements, settings))  # type: ignore[arg-type]
    conformance: Conformance | None = None
    used = "dsp"

    if brief is not None and getattr(brief, "claims", None):
        transcript = None
        be = LocalBackend(settings)  # check is offline by construction — local ASR only
        if be.available():
            transcript = await be.transcribe(rr.path or rr.source)
            used = f"dsp+{be.name}"
        conformance, intent_issues = grade(brief, transcript, rr.duration_ms)
        issues.extend(intent_issues)

    return Report(
        verdict=verdict_from_issues(issues),  # type: ignore[arg-type]
        summary=_summarize(rr, issues),
        issues=issues,
        conformance=conformance,
        capabilities=DSP_CAPABILITIES,
        backend=used,
        sample_rate=rr.sample_rate, channels=rr.channels, duration_ms=rr.duration_ms,
        audio_path=str(source),
    )
