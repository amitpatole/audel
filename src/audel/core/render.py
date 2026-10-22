"""``render`` — decode a media source to trustworthy signals (the DOM/CV analog).

Returns a :class:`RenderResult`: validated metadata plus deterministic acoustic measurements
(loudness, true-peak, RMS, silent spans). No LLM, no network. All decoding is bounded by
``mediaguard``.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, field

from ..config import Settings, load_settings
from ..mediaguard import probe, validate_source
from ..models import TrackSummary
from ..signals.measure import Measurements, TrackMeasurements, measure
from ..specs import DeliverySpec, Gating


@dataclass
class RenderResult:
    source: str
    has_audio: bool
    path: str = ""  # resolved, mediaguard-validated local path (reused for ASR)
    codec: str = ""
    sample_rate: int | None = None
    channels: int | None = None
    duration_ms: int | None = None
    integrated_lufs: float | None = None
    lra: float | None = None
    true_peak_dbtp: float | None = None
    peak_dbfs: float | None = None
    rms_dbfs: float | None = None
    silences: list[tuple[float, float]] = field(default_factory=list)
    spec: str | None = None
    tracks: list[TrackSummary] = field(default_factory=list)
    measurements: Measurements | None = field(default=None, repr=False)


def _finite(v: float | None) -> float | None:
    return None if v is None or not math.isfinite(v) else round(float(v), 2)


def _max(values) -> float | None:
    vals = [v for v in values if v is not None and math.isfinite(v)]
    return _finite(max(vals)) if vals else None


def summarize_track(tm: TrackMeasurements) -> TrackSummary:
    st = tm.stream
    return TrackSummary(
        index=st.index, codec=st.codec, channels=st.channels, sample_rate=st.sample_rate,
        layout=st.layout, language=st.language, title=st.title,
        integrated_lufs=_finite(tm.integrated_lufs), dialogue_lufs=_finite(tm.dialogue_lufs),
        dialogue_coverage=_finite(tm.dialogue_coverage), lra=_finite(tm.lra),
        true_peak_dbtp=_finite(tm.true_peak_dbtp),
        max_momentary_lufs=_max(f[1] for f in tm.frames),
        max_short_term_lufs=_max(f[2] for f in tm.frames),
        rms_dbfs=_finite(tm.rms_dbfs))


def _dialogue_gate(path, m: Measurements, settings: Settings) -> None:
    """Speech-gated loudness for every track (VAD approximation of dialogue gating).

    Inside the file's own deadline. A host failure or the deadline propagates (retry / refuse);
    a track whose speech can't be measured is marked, so the grade says so instead of silently
    using programme loudness."""
    import time

    from ..errors import AudelError, BusyError, UnsafeSourceError
    from ..signals.vad import gated_lufs_from_frames, speech_regions

    if 0 < m.info.decode_cap_s < settings.max_duration_s:  # the same per-stream cap as measure()
        settings = settings.model_copy(update={"max_duration_s": m.info.decode_cap_s})
    dur = m.info.duration_s or 0.0
    for tm in m.tracks:
        if tm.failed:
            continue  # already reported as track_decode_error; the others are still graded
        left = (m.deadline - time.monotonic()) if m.deadline is not None else None
        if left is not None and left <= 1:
            raise UnsafeSourceError("analysis exceeded the per-file time budget")
        try:
            regions = speech_regions(path, settings, stream=tm.stream.index,
                                     labels=tm.stream.channel_labels(),
                                     channels=tm.stream.channels, timeout_s=left,
                                     layout=tm.stream.layout, codec=tm.stream.codec)
            if regions is None:
                return  # no VAD installed: graders fall back to programme loudness
            speech_s = sum(b - a for a, b in regions)
            tm.dialogue_coverage = (speech_s / dur) if dur > 0 else None
            tm.dialogue_lufs = gated_lufs_from_frames(tm.frames, regions)
            tm.dialogue_status = "ok" if tm.dialogue_lufs is not None else "no_speech"
        except (BusyError, UnsafeSourceError):
            raise
        except AudelError:
            tm.dialogue_status = "failed"  # graded on programme loudness, and the grade says so


def _render_sync(source, settings: Settings, spec: DeliverySpec | str | None = None) -> RenderResult:
    from ..signals.checks import effective_spec

    path = validate_source(source, settings)
    info = probe(path, settings)
    m = measure(path, info, settings)
    sp = effective_spec(settings, spec)
    if sp.gating is Gating.DIALOGUE and m.tracks:
        _dialogue_gate(path, m, settings)
    return RenderResult(
        source=str(source), has_audio=info.has_audio, path=str(path), codec=info.codec,
        sample_rate=info.sample_rate or None, channels=info.channels or None,
        duration_ms=int(m.info.duration_s * 1000) if m.info.duration_s else None,
        integrated_lufs=m.integrated_lufs, lra=m.lra, true_peak_dbtp=m.true_peak_dbtp,
        peak_dbfs=m.peak_dbfs, rms_dbfs=m.rms_dbfs, silences=m.silences, measurements=m,
        spec=sp.name, tracks=[summarize_track(t) for t in m.tracks],
    )


async def render(source, *, settings: Settings | None = None,
                 spec: DeliverySpec | str | None = None) -> RenderResult:
    """Decode ``source`` to a RenderResult. Async wrapper over the bounded ffmpeg work."""
    settings = settings or load_settings()
    return await asyncio.to_thread(_render_sync, source, settings, spec)
