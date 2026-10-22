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

import wave
from pathlib import Path

import numpy as np

from ..config import Settings
from ..logging import get_logger
from ..mediaguard import decode_to_wav

_log = get_logger("vad")
_SR = 16000
_CHUNK_S = 600            # VAD in 10-minute chunks (bounded memory on a 3 h programme)


def speech_regions(path: Path, settings: Settings, *, stream: int = 0,
                   labels: list[str] | None = None, channel_rms: list[float | None] | None = None,
                   timeout_s: float | None = None) -> list[tuple[float, float]] | None:
    """Speech regions in seconds (decoded track time), or ``None`` when no VAD is installed.

    Every channel that matters is heard on its own (one decode, all channels kept): every
    non-LFE channel within 30 dB of the loudest. A downmix drops some immersive channels
    (7.1.4 tops, most of 22.2) and any fixed mix can be cancelled by antiphase content in some
    channel pairing; individual channels can't. A failure RAISES (BusyError for the host,
    DecodeError otherwise); it is never a silent "no speech"."""
    try:
        from faster_whisper.vad import VadOptions, get_speech_timestamps  # noqa: F401
    except ImportError:
        return None
    chans = _channels_to_hear(labels or [], channel_rms or [])
    return merge_regions(_vad_pass(path, settings, stream, chans, timeout_s), 1_000_000)


def _channels_to_hear(labels: list[str], rms: list[float | None]) -> list[int] | None:
    """Indexes of the channels worth listening to (``None`` = all of them)."""
    if not labels:
        return None
    levels = [r for r in rms if r is not None and r > -150]
    loudest = max(levels) if levels else None
    keep = []
    for i, lab in enumerate(labels):
        if lab.upper().startswith("LFE"):
            continue  # low-frequency effects: not dialogue, and BS.1770 leaves it out too
        r = rms[i] if i < len(rms) else None
        if loudest is not None and r is not None and r < loudest - 30:
            continue  # 30 dB under the loudest channel: can't carry the programme's dialogue
        keep.append(i)
    return keep or None


def _vad_pass(path: Path, settings: Settings, stream: int, chans: list[int] | None,
              timeout_s: float | None) -> list[tuple[float, float]]:
    from faster_whisper.vad import VadOptions, get_speech_timestamps

    from ..errors import BusyError, DecodeError

    wav = decode_to_wav(path, settings, sample_rate=_SR, stream=stream, mix="all",
                        timeout_s=timeout_s)
    regions: list[tuple[float, float]] = []
    opts = VadOptions(min_silence_duration_ms=500, speech_pad_ms=100)
    try:
        with wave.open(str(wav), "rb") as w:
            n = max(1, w.getnchannels())
            use = [c for c in (chans if chans is not None else range(n)) if c < n] or [0]
            offset = 0.0
            while True:
                raw = w.readframes(_SR * _CHUNK_S)
                if not raw:
                    break
                frames = np.frombuffer(raw, dtype="<i2").reshape(-1, n)
                for c in use:
                    audio = frames[:, c].astype(np.float32) / 32768.0
                    for ts in get_speech_timestamps(audio, vad_options=opts, sampling_rate=_SR):
                        regions.append((offset + ts["start"] / _SR, offset + ts["end"] / _SR))
                offset += frames.shape[0] / _SR
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
    finally:
        wav.unlink(missing_ok=True)
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
