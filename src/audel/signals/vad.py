"""Speech regions (voice activity) and speech-gated loudness.

Dialogue-gated delivery specs (e.g. Netflix-style ``-27 LKFS dialogue``) measure loudness over
speech only. Audel approximates that with the Silero VAD bundled in faster-whisper (``[asr]``
extra, no network, no model download beyond the package) and then measures BS.1770 integrated
loudness over the speech regions with ffmpeg.

This is an **approximation** of dialogue gating. It is not Dolby Dialogue Intelligence, and a
delivery that contractually requires DI must be signed off with the licensed meter. The report
marks speech-gated results with ``basis: speech-gated`` and MEDIUM confidence, and falls back to
programme loudness (LOW confidence) when the VAD is unavailable.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from ..config import Settings
from ..logging import get_logger

_log = get_logger("vad")
_SR = 16000
_CHUNK_S = 60             # VAD in 1-minute chunks: bounded memory even for 24 channels


def speech_regions(path: Path, settings: Settings, *, stream: int = 0,
                   labels: list[str] | None = None, channels: int | None = None,
                   timeout_s: float | None = None,
                   layout: str = "") -> list[tuple[float, float]] | None:
    """Speech regions in seconds (decoded track time), or ``None`` when no VAD is installed.

    Every channel except LFE is heard on its own, from one streamed, 100 Hz high-passed decode
    (no temp file). A downmix drops some immersive channels and any fixed mix can be cancelled
    by antiphase content; individual channels can't. A detected region counts only where its
    channel is AUDIBLE in the mix: within 20 dB of the loudest channel over the same span (the
    detector ignores level, so a voice buried under music elsewhere must not turn the music into
    "dialogue"). The high-pass keeps subsonic content from distorting either test. A failure
    RAISES (BusyError for the host, DecodeError otherwise); never a silent "no speech"."""
    try:
        from faster_whisper.vad import VadOptions, get_speech_timestamps  # noqa: F401
    except ImportError:
        return None
    labels = labels or []
    n = channels or len(labels) or 1
    use = [i for i in range(n) if not (i < len(labels) and labels[i].upper().startswith("LFE"))]
    return merge_regions(_vad_pass(path, settings, stream, n, use or [0], timeout_s, layout),
                         1_000_000)


_AUDIBLE_DB = 20.0  # a region's channel must be within this of the loudest channel there


def _vad_pass(path: Path, settings: Settings, stream: int, n: int, use: list[int],
              timeout_s: float | None, layout: str = "") -> list[tuple[float, float]]:
    import time

    from faster_whisper.vad import VadOptions, get_speech_timestamps

    from ..errors import AudelError, BusyError, DecodeError, UnsafeSourceError
    from ..mediaguard import stream_pcm16

    end = time.monotonic() + timeout_s if timeout_s else None
    regions: list[tuple[float, float]] = []
    opts = VadOptions(min_silence_duration_ms=500, speech_pad_ms=100)
    try:
        offset = 0.0
        for frames in stream_pcm16(path, settings, stream=stream, channels=n, sample_rate=_SR,
                                   highpass_hz=100, chunk_s=_CHUNK_S, timeout_s=timeout_s,
                                   layout=layout):
            block = frames[:, use].astype(np.float32) / 32768.0
            for col, _c in enumerate(use):
                if end is not None and time.monotonic() > end:
                    # In-process inference has no ffmpeg timeout: check the file's budget.
                    raise UnsafeSourceError("analysis exceeded the per-file time budget")
                for ts in get_speech_timestamps(block[:, col], vad_options=opts,
                                                sampling_rate=_SR):
                    a, b = int(ts["start"]), int(ts["end"])
                    seg = block[a:b]
                    if seg.size == 0:
                        continue
                    level = 10 * np.log10(np.mean(seg * seg, axis=0) + 1e-12)
                    if level[col] >= level.max() - _AUDIBLE_DB:  # audible in the mix there
                        regions.append((offset + a / _SR, offset + b / _SR))
            offset += frames.shape[0] / _SR
    except (UnsafeSourceError, BusyError):
        raise
    except AudelError as e:
        raise DecodeError("speech detection could not decode the audio") from e
    except (OSError, MemoryError) as e:  # the host (fds, memory), not the media
        raise BusyError("speech detection could not run: the host is at capacity") from e
    except RuntimeError as e:
        if "can't start new thread" in str(e):
            raise BusyError("speech detection could not run: the host is at capacity") from e
        _log.warning("VAD failed: %s", type(e).__name__)
        raise DecodeError("speech detection failed") from None
    except Exception as e:  # noqa: BLE001 - reported to the grade, never a silent "no speech"
        _log.warning("VAD failed: %s", type(e).__name__)
        raise DecodeError("speech detection failed") from None
    return regions


MIN_SPEECH_S = 0.4  # less than one BS.1770 block of dialogue: there is nothing to measure


def gated_lufs_from_frames(frames, regions: list[tuple[float, float]]) -> float | None:
    """BS.1770 integrated loudness over the dialogue only, from the main pass's own momentary
    blocks (400 ms, every 100 ms): only blocks lying ENTIRELY inside speech count (no spill into
    adjacent music, no region cap), then the absolute (-70 LUFS) and relative (-10 LU) gates.
    ``None`` when there isn't at least one block of dialogue."""
    import math

    rs = sorted(regions)
    if sum(b - a for a, b in rs) < MIN_SPEECH_S:
        return None
    blocks: list[float] = []
    j = 0
    for t, mom, *_ in frames:
        if mom is None or not math.isfinite(mom) or mom <= -70:
            continue
        start = t - 0.4
        while j < len(rs) and rs[j][1] < t:
            j += 1
        if j < len(rs) and rs[j][0] <= start + 1e-6 and t <= rs[j][1] + 1e-6:
            blocks.append(mom)
    if not blocks:
        return None
    power = [10 ** (m / 10) for m in blocks]
    rel = 10 * math.log10(sum(power) / len(power)) - 10
    gated = [p for p, m in zip(power, blocks, strict=True) if m > rel]
    return round(10 * math.log10(sum(gated) / len(gated)), 2) if gated else None


def merge_regions(regions: list[tuple[float, float]], limit: int) -> list[tuple[float, float]]:
    """Sort, merge overlaps, then merge across the smallest gaps until at most ``limit`` remain."""
    rs = sorted((max(0.0, a), max(0.0, b)) for a, b in regions if b > a)
    merged: list[list[float]] = []
    for a, b in rs:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    excess = len(merged) - limit
    if excess > 0:
        # Merging across one gap leaves every other gap unchanged, so closing the ``excess``
        # smallest gaps in one pass equals merging them one at a time: O(n log n), not O(n^2).
        order = sorted(range(len(merged) - 1), key=lambda i: merged[i + 1][0] - merged[i][1])
        close = set(order[:excess])
        out = [merged[0]]
        for i in range(1, len(merged)):
            if i - 1 in close:
                out[-1][1] = merged[i][1]
            else:
                out.append(merged[i])
        merged = out
    return [(a, b) for a, b in merged]
