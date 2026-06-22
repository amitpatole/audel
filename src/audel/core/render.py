"""``render`` — decode a media source to trustworthy signals (the DOM/CV analog).

Returns a :class:`RenderResult`: validated metadata plus deterministic acoustic measurements
(loudness, true-peak, RMS, silent spans). No LLM, no network. All decoding is bounded by
``mediaguard``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ..config import Settings, load_settings
from ..mediaguard import probe, validate_source
from ..signals.measure import Measurements, measure


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
    measurements: Measurements | None = field(default=None, repr=False)


def _render_sync(source, settings: Settings) -> RenderResult:
    path = validate_source(source, settings)
    info = probe(path, settings)
    m = measure(path, info, settings)
    return RenderResult(
        source=str(source), has_audio=info.has_audio, path=str(path), codec=info.codec,
        sample_rate=info.sample_rate or None, channels=info.channels or None,
        duration_ms=int(info.duration_s * 1000) if info.duration_s else None,
        integrated_lufs=m.integrated_lufs, lra=m.lra, true_peak_dbtp=m.true_peak_dbtp,
        peak_dbfs=m.peak_dbfs, rms_dbfs=m.rms_dbfs, silences=m.silences, measurements=m,
    )


async def render(source, *, settings: Settings | None = None) -> RenderResult:
    """Decode ``source`` to a RenderResult. Async wrapper over the bounded ffmpeg work."""
    settings = settings or load_settings()
    return await asyncio.to_thread(_render_sync, source, settings)
