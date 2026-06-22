"""``watch`` — temporal verification: does the audio actually play THROUGH over time?

For a media file this grades liveness (plays through vs silent-though-it-"plays"), **dropouts**
(short interior silences in otherwise-active audio), and **A/V desync** (audio vs video stream
duration/start mismatch). The headless web-capture path (play a URL, detect whether sounds fire on
interaction) is the harder, browser-bound extension — see :mod:`audel.core.capture`; it reuses the
SSRF ``netguard`` + DNS-rebinding ``proxy`` and a sandboxed browser.
"""

from __future__ import annotations

import asyncio
import math

from ..config import Settings, load_settings
from ..errors import AudelError
from ..mediaguard import probe_streams, validate_source
from ..models import (
    Confidence,
    Issue,
    IssueKind,
    IssueSource,
    Report,
    Severity,
    Span,
    verdict_from_issues,
)
from .check import DSP_CAPABILITIES, _decode_error
from .render import _render_sync

_DROPOUT_MIN_S = 0.15   # interior gaps at/above this are dropouts
_DROPOUT_MAX_S = 1.5    # at/above this they're graded as plain silence by check()
_EDGE_S = 0.3           # ignore gaps within this of start/end (lead-in / trailing silence)
_DESYNC_S = 0.25        # audio/video duration or start mismatch beyond this = desync


def _watch_sync(source, settings: Settings, frames: int, interval_ms: int) -> Report:
    path = validate_source(source, settings)
    rr = _render_sync(source, settings)
    m = rr.measurements
    assert m is not None  # set on every successful render
    dur = (rr.duration_ms or 0) / 1000.0
    issues: list[Issue] = []

    # --- liveness: does it play through? ---
    if not rr.has_audio:
        issues.append(Issue.make(IssueKind.MISSING_AUDIO, Severity.CRITICAL,
                                 "media plays but carries no audio stream",
                                 span=Span(start_ms=0, end_ms=int(dur * 1000)), source=IssueSource.DSP))
    else:
        silent_total = sum((e if e >= 0 else dur) - s for s, e in m.silences)
        rms_silent = m.rms_dbfs is not None and (m.rms_dbfs == -math.inf
                                                 or m.rms_dbfs <= settings.silence_dbfs)
        if rms_silent or (dur > 0 and silent_total >= 0.9 * dur):
            issues.append(Issue.make(IssueKind.SILENCE, Severity.CRITICAL,
                                     "audio is silent for the whole playback (does not play through)",
                                     span=Span(start_ms=0, end_ms=int(dur * 1000)), source=IssueSource.DSP))
        else:
            # --- dropouts: short interior gaps ---
            for s, e in m.silences:
                end = e if e >= 0 else dur
                gap = end - s
                interior = s > _EDGE_S and (dur - end) > _EDGE_S
                if interior and _DROPOUT_MIN_S <= gap < _DROPOUT_MAX_S:
                    issues.append(Issue.make(
                        IssueKind.DROPOUT, Severity.ERROR,
                        f"audio dropout: {gap*1000:.0f}ms of silence mid-playback",
                        span=Span(start_ms=int(s * 1000), end_ms=int(end * 1000)),
                        source=IssueSource.DSP, confidence=Confidence.MEDIUM,
                        detail={"gap_ms": round(gap * 1000)}))

    # --- A/V desync ---
    streams = probe_streams(path, settings)
    a, v = streams.get("audio"), streams.get("video")
    if a and v and a.get("duration") and v.get("duration"):
        ddur = abs(a["duration"] - v["duration"])
        dstart = abs((a.get("start") or 0.0) - (v.get("start") or 0.0))
        if ddur > _DESYNC_S or dstart > _DESYNC_S:
            issues.append(Issue.make(
                IssueKind.DESYNC, Severity.WARNING,
                f"A/V desync: audio {a['duration']:.2f}s vs video {v['duration']:.2f}s "
                f"(Δdur {ddur:.2f}s, Δstart {dstart:.2f}s)",
                span=Span(start_ms=0, end_ms=int(dur * 1000)), source=IssueSource.DSP,
                detail={"audio_s": a["duration"], "video_s": v["duration"]}))

    summary = ("plays through" if not issues else
               f"{len(issues)} temporal issue(s): " + ", ".join(sorted({i.kind.value for i in issues})))
    return Report(verdict=verdict_from_issues(issues), summary=summary, issues=issues,  # type: ignore[arg-type]
                  capabilities=DSP_CAPABILITIES, backend="dsp",
                  sample_rate=rr.sample_rate, channels=rr.channels, duration_ms=rr.duration_ms,
                  audio_path=str(source))


async def _watch_url(source, settings: Settings, click_selector, observe_ms: int) -> Report:
    from .capture import capture_sound

    state = await capture_sound(str(source), settings=settings, click_selector=click_selector,
                                observe_ms=observe_ms)
    issues: list[Issue] = []
    fired = (state.get("played", 0) or 0) + (state.get("audio_contexts", 0) or 0)
    if click_selector and state.get("clicked") and fired == 0:
        issues.append(Issue.make(IssueKind.MISSING_AUDIO, Severity.ERROR,
                                 f"no sound fired after clicking {click_selector!r}",
                                 span=Span(start_ms=0, end_ms=0), source=IssueSource.DSP))
    elif not click_selector and fired == 0:
        issues.append(Issue.make(IssueKind.SILENCE, Severity.WARNING,
                                 "page produced no audio during the observation window",
                                 span=Span(start_ms=0, end_ms=0), source=IssueSource.DSP,
                                 confidence=Confidence.LOW))
    summary = "sound fired" if not issues else "; ".join(i.message for i in issues)
    return Report(verdict=verdict_from_issues(issues), summary=summary, issues=issues,  # type: ignore[arg-type]
                  capabilities=DSP_CAPABILITIES, backend="capture", audio_path=str(source))


async def watch(source, *, settings: Settings | None = None, frames: int | None = None,
                interval_ms: int | None = None, click_selector: str | None = None) -> Report:
    """Temporal grade of ``source`` (file OR http(s) URL). ``frames``/``interval_ms`` clamped (DoS)."""
    settings = settings or load_settings()
    frames = min(frames or settings.watch_frames, settings.watch_max_frames)
    interval_ms = min(interval_ms or settings.watch_interval_ms, settings.watch_max_interval_ms)
    from .capture import is_url

    try:
        if is_url(str(source)):
            return await _watch_url(source, settings, click_selector, frames * interval_ms)
        return await asyncio.to_thread(_watch_sync, source, settings, frames, interval_ms)
    except AudelError as e:
        return _decode_error(source, e)
