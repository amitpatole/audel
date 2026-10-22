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
from ._parse import parse_ebur128

_log = get_logger("vad")
_SR = 16000
_CHUNK_S = 600            # VAD in 10-minute chunks (bounded memory on a 3 h programme)
_MAX_REGIONS = 200        # cap the ffmpeg select expression; nearest regions are merged first


def speech_regions(path: Path, settings: Settings, *, stream: int = 0, channels: int = 1,
                   timeout_s: float | None = None) -> list[tuple[float, float]] | None:
    """Speech regions in seconds, or ``None`` when no VAD is installed.

    Stereo (and wider) tracks are heard twice, as the mono mix and as the side (L minus R)
    signal, and the regions are united: dialogue in antiphase cancels in a mono mix but not in
    the side signal. A failure RAISES (BusyError for the host, DecodeError otherwise); it is
    never a silent "no speech"."""
    try:
        from faster_whisper.vad import VadOptions, get_speech_timestamps  # noqa: F401
    except ImportError:
        return None
    regions = _vad_pass(path, settings, stream, "mono", timeout_s)
    if channels >= 2:
        regions += _vad_pass(path, settings, stream, "side", timeout_s)
    return merge_regions(regions, _MAX_REGIONS)


def _vad_pass(path: Path, settings: Settings, stream: int, mix: str,
              timeout_s: float | None) -> list[tuple[float, float]]:
    from faster_whisper.vad import VadOptions, get_speech_timestamps

    from ..errors import BusyError, DecodeError

    wav = decode_to_wav(path, settings, sample_rate=_SR, stream=stream, mix=mix,
                        timeout_s=timeout_s)
    regions: list[tuple[float, float]] = []
    opts = VadOptions(min_silence_duration_ms=500, speech_pad_ms=100)
    try:
        with wave.open(str(wav), "rb") as w:
            offset = 0.0
            while True:
                raw = w.readframes(_SR * _CHUNK_S)
                if not raw:
                    break
                audio = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
                for ts in get_speech_timestamps(audio, vad_options=opts, sampling_rate=_SR):
                    regions.append((offset + ts["start"] / _SR, offset + ts["end"] / _SR))
                offset += audio.size / _SR
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


def speech_gated_lufs(path: Path, settings: Settings, regions: list[tuple[float, float]],
                      *, stream: int = 0, timeout_s: float | None = None) -> float | None:
    """BS.1770 integrated loudness of the speech regions only (original rate and channels)."""
    if not regions:
        return None
    expr = "+".join(f"between(t\\,{a:.3f}\\,{b:.3f})" for a, b in regions)
    from ..errors import AudelError, BusyError, DecodeError, UnsafeSourceError
    from ..mediaguard import pass_timeout, pcm_pipeline, probe

    info = probe(path, settings)
    st = next((x for x in info.streams if x.index == int(stream)), None)
    if st is None:
        return None
    try:
        err = pcm_pipeline(path, settings, stream=st.index, channels=st.channels or 1,
                           sample_rate=st.sample_rate if st.sample_rate >= 8000 else 48000,
                           layout=st.layout,
                           timeout_s=min(pass_timeout(settings, info.duration_s), timeout_s)
                           if timeout_s else pass_timeout(settings, info.duration_s),
                           analysis=["-af", f"aselect={expr},asetpts=N/SR/TB,ebur128=framelog=quiet",
                                     "-f", "null", "-"])
    except (BusyError, UnsafeSourceError):
        raise  # host capacity / time budget: never silently skip the speech-gated measurement
    except AudelError as e:
        raise DecodeError("speech-gated loudness could not be measured") from e
    return parse_ebur128(err).get("I")
