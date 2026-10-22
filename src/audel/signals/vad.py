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
from ..mediaguard import _tool, decode_to_wav, run, safe_input
from ._parse import parse_ebur128

_log = get_logger("vad")
_SR = 16000
_CHUNK_S = 600            # VAD in 10-minute chunks (bounded memory on a 3 h programme)
_MAX_REGIONS = 200        # cap the ffmpeg select expression; nearest regions are merged first


def speech_regions(path: Path, settings: Settings, *, stream: int = 0) -> list[tuple[float, float]] | None:
    """Speech regions in seconds, or ``None`` when no VAD is installed."""
    try:
        from faster_whisper.vad import VadOptions, get_speech_timestamps
    except ImportError:
        return None
    wav = decode_to_wav(path, settings, sample_rate=_SR, stream=stream)
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
    except Exception as e:  # noqa: BLE001 - VAD is best-effort; the caller falls back
        _log.warning("VAD failed: %s", type(e).__name__)
        return None
    finally:
        wav.unlink(missing_ok=True)
    return merge_regions(regions, _MAX_REGIONS)


def merge_regions(regions: list[tuple[float, float]], limit: int) -> list[tuple[float, float]]:
    """Sort, merge overlaps, then merge across the smallest gaps until at most ``limit`` remain."""
    rs = sorted((max(0.0, a), max(0.0, b)) for a, b in regions if b > a)
    merged: list[list[float]] = []
    for a, b in rs:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    while len(merged) > limit:
        gaps = [merged[i + 1][0] - merged[i][1] for i in range(len(merged) - 1)]
        i = int(np.argmin(gaps))
        merged[i][1] = merged[i + 1][1]
        del merged[i + 1]
    return [(a, b) for a, b in merged]


def speech_gated_lufs(path: Path, settings: Settings, regions: list[tuple[float, float]],
                      *, stream: int = 0) -> float | None:
    """BS.1770 integrated loudness of the speech regions only (original rate and channels)."""
    if not regions:
        return None
    expr = "+".join(f"between(t\\,{a:.3f}\\,{b:.3f})" for a, b in regions)
    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", *safe_input(path),
            "-map", f"0:a:{int(stream)}?", "-t", str(settings.max_duration_s),
            "-af", f"aselect={expr},asetpts=N/SR/TB,ebur128=framelog=quiet", "-f", "null", "-"]
    proc = run(argv, timeout_s=settings.decode_timeout_s)
    if proc.returncode != 0:
        return None
    return parse_ebur128(proc.stderr.decode("utf-8", "replace")).get("I")
