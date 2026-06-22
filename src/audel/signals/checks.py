"""Turn :class:`Measurements` into time-grounded :class:`audel.models.Issue` objects.

Deterministic only — no LLM, no network. Each issue carries a ``span`` (ms) so an agent can jump
to the exact moment. Thresholds come from Settings (loudness target, silence floor, clip ceiling).
"""

from __future__ import annotations

import math

from ..config import Settings
from ..models import Confidence, Issue, IssueKind, IssueSource, Severity, Span
from .measure import Measurements

_LOUDNESS_TOL_LU = 2.0          # |integrated - target| beyond this warns
_TRUNCATION_TAIL_DBFS = -25.0   # tail RMS louder than this with no trailing silence => maybe cut
_FULL_SILENCE_FRACTION = 0.98   # a single silence covering ~all of the file = dead audio


def _full_span(m: Measurements) -> Span:
    return Span(start_ms=0, end_ms=int(max(0.0, m.info.duration_s) * 1000))


def _span(start_s: float, end_s: float, m: Measurements) -> Span:
    if end_s < 0:
        end_s = m.info.duration_s
    return Span(start_ms=int(max(0.0, start_s) * 1000), end_ms=int(max(start_s, end_s) * 1000))


def evaluate(m: Measurements, settings: Settings) -> list[Issue]:
    issues: list[Issue] = []
    dur = m.info.duration_s

    if not m.info.has_audio:
        issues.append(Issue.make(IssueKind.MISSING_AUDIO, Severity.CRITICAL,
                                 "no audio stream in the media", span=_full_span(m),
                                 source=IssueSource.DSP))
        return issues

    # --- silence ---
    silent_total = sum((e if e >= 0 else dur) - s for s, e in m.silences)
    rms_silent = m.rms_dbfs is not None and (m.rms_dbfs == -math.inf or m.rms_dbfs <= settings.silence_dbfs)
    if (dur > 0 and silent_total >= _FULL_SILENCE_FRACTION * dur) or rms_silent:
        issues.append(Issue.make(IssueKind.SILENCE, Severity.CRITICAL,
                                 "audio is silent throughout", span=_full_span(m),
                                 source=IssueSource.DSP,
                                 detail={"rms_dbfs": m.rms_dbfs}))
    else:
        for s, e in m.silences:
            gap = (e if e >= 0 else dur) - s
            if gap >= 1.5:
                issues.append(Issue.make(
                    IssueKind.SILENCE, Severity.WARNING,
                    f"{gap:.1f}s of silence", span=_span(s, e, m), source=IssueSource.DSP,
                    confidence=Confidence.MEDIUM, detail={"gap_s": round(gap, 2)}))

    # --- clipping (true-peak preferred; peak level as backstop) ---
    tp = m.true_peak_dbtp
    if tp is not None and tp != -math.inf and tp > settings.clipping_dbtp:
        issues.append(Issue.make(
            IssueKind.CLIPPING, Severity.ERROR,
            f"true peak {tp:.1f} dBTP exceeds {settings.clipping_dbtp:.1f} dBTP (clipping)",
            span=_full_span(m), source=IssueSource.DSP, detail={"true_peak_dbtp": tp}))

    # --- loudness vs target ---
    li = m.integrated_lufs
    if li is not None and li != -math.inf:
        target = settings.loudness_target.lufs
        delta = li - target
        if abs(delta) > _LOUDNESS_TOL_LU:
            direction = "louder" if delta > 0 else "quieter"
            issues.append(Issue.make(
                IssueKind.LOUDNESS, Severity.WARNING,
                f"integrated loudness {li:.1f} LUFS is {abs(delta):.1f} LU {direction} than the "
                f"{settings.loudness_target.value} target ({target:.0f} LUFS)",
                span=_full_span(m), source=IssueSource.DSP,
                detail={"lufs": li, "target_lufs": target}))

    # --- truncation cue (loud tail, no trailing silence) ---
    ends_silent = any((e < 0 or abs((e if e >= 0 else dur) - dur) < 0.2) for _, e in m.silences)
    tail = m.tail_rms_dbfs
    if (tail is not None and tail != -math.inf and tail > _TRUNCATION_TAIL_DBFS
            and not ends_silent and dur > 0.5):
        end_ms = int(dur * 1000)
        issues.append(Issue.make(
            IssueKind.TRUNCATION, Severity.WARNING,
            "audio ends at high energy with no trailing silence — possibly cut off",
            span=Span(start_ms=max(0, end_ms - 250), end_ms=end_ms), source=IssueSource.DSP,
            confidence=Confidence.LOW, detail={"tail_rms_dbfs": tail}))

    return issues
