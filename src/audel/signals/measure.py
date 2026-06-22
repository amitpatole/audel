"""Deterministic acoustic measurement via ffmpeg's own analysis filters.

We deliberately measure with ffmpeg (``ebur128`` for ITU-R BS.1770 loudness/true-peak,
``astats`` for peak/RMS/DC/flatness, ``silencedetect`` for silent spans) rather than reimplement
DSP: it is correct, battle-tested, and keeps the deterministic path memory-safe (analysis streams
to ``-f null`` — no full waveform is loaded into Python). Every call goes through ``mediaguard``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Settings
from ..mediaguard import MediaInfo, _tool, run
from ..signals._parse import (
    parse_astats,
    parse_ebur128,
    parse_silences,
)


@dataclass
class Measurements:
    info: MediaInfo
    integrated_lufs: float | None = None
    lra: float | None = None
    true_peak_dbtp: float | None = None
    peak_dbfs: float | None = None
    rms_dbfs: float | None = None
    dc_offset: float | None = None
    flat_factor: float | None = None
    tail_rms_dbfs: float | None = None
    silences: list[tuple[float, float]] = field(default_factory=list)  # (start_s, end_s)


def measure(path, info: MediaInfo, settings: Settings) -> Measurements:
    """Run the analysis filter chain over an already path-validated, probed file."""
    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    silence_db = settings.silence_dbfs
    af = (
        f"ebur128=peak=true:framelog=quiet,"
        f"astats=metadata=0:measure_overall=Peak_level+RMS_level+DC_offset+Flat_factor,"
        f"silencedetect=noise={silence_db}dB:d=0.5"
    )
    # `-t max_duration_s` bounds how much is actually processed even if the container LIES about
    # its duration (the probe cap trusts metadata; this caps the real decode regardless).
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-i", str(path),
            "-map", "0:a:0?", "-t", str(settings.max_duration_s), "-af", af, "-f", "null", "-"]
    proc = run(argv, timeout_s=settings.decode_timeout_s)
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        from ..errors import DecodeError
        raise DecodeError(f"ffmpeg analysis failed (rc={proc.returncode}): {err[-300:]}")

    m = Measurements(info=info)
    eb = parse_ebur128(err)
    m.integrated_lufs, m.lra, m.true_peak_dbtp = eb.get("I"), eb.get("LRA"), eb.get("true_peak")
    ast = parse_astats(err)
    m.peak_dbfs, m.rms_dbfs = ast.get("peak"), ast.get("rms")
    m.dc_offset, m.flat_factor = ast.get("dc"), ast.get("flat")
    m.silences = parse_silences(err)

    # Truncation cue: RMS of the final 250 ms. A clip that ends loud (no trailing decay/silence)
    # is a likely mid-word cut. Bounded second pass via -sseof.
    tail = run([ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-sseof", "-0.25",
                "-i", str(path), "-map", "0:a:0?", "-af", "astats=metadata=0:measure_overall=RMS_level",
                "-f", "null", "-"], timeout_s=min(30.0, settings.decode_timeout_s))
    m.tail_rms_dbfs = parse_astats(tail.stderr.decode("utf-8", "replace")).get("rms")
    return m
