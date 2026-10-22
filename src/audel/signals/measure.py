"""Deterministic acoustic measurement via ffmpeg's own analysis filters.

We measure with ffmpeg (``ebur128`` for ITU-R BS.1770 loudness / true peak, ``astats`` for peak,
RMS and DC per channel, ``silencedetect`` for silent spans, band-passed windowed RMS series for
hum and noise floor) rather than reimplement DSP. It is correct, battle-tested, and keeps the
deterministic path memory-safe: analysis streams to ``-f null`` and only compact series come back.
Every call goes through :mod:`audel.mediaguard` (argv form, timeout, ``RLIMIT_*``, ``-t`` cap).

Per audio stream we run three bounded passes:

1. **Loudness + levels** — ebur128 with a 10 Hz frame log (momentary, short-term, frame true peak),
   per-channel and overall astats, silencedetect.
2. **Spectral / spatial** — 4 Hz windowed RMS of the full band and of narrow 50/60 Hz bands (mains
   hum, noise floor), plus mid/side RMS for the first channel pair (polarity / phase).
3. **Tail** — RMS of the last 250 ms (truncation cue).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Settings
from ..mediaguard import MediaInfo, StreamInfo, _tool, run
from ..signals._parse import (
    parse_astats,
    parse_astats_sections,
    parse_ebur128,
    parse_frames,
    parse_metadata_series,
    parse_silences,
)

SERIES_HZ = 4            # windowed-RMS rate for the spectral pass (0.25 s windows)
_SERIES_RATE = 8000      # the spectral pass resamples to 8 kHz mono (hum lives at 50-120 Hz)


@dataclass
class ChannelStats:
    label: str
    rms_dbfs: float | None = None
    peak_dbfs: float | None = None
    dc_offset: float | None = None


@dataclass
class TrackMeasurements:
    stream: StreamInfo
    integrated_lufs: float | None = None
    lra: float | None = None
    true_peak_dbtp: float | None = None
    peak_dbfs: float | None = None
    rms_dbfs: float | None = None
    dc_offset: float | None = None
    flat_factor: float | None = None
    tail_rms_dbfs: float | None = None
    silences: list[tuple[float, float]] = field(default_factory=list)
    # 10 Hz frame log: (t_s, momentary, short_term, frame true peak)
    frames: list[tuple[float, float | None, float | None, float | None]] = field(default_factory=list)
    channels: list[ChannelStats] = field(default_factory=list)
    mid_rms_dbfs: float | None = None
    side_rms_dbfs: float | None = None
    # SERIES_HZ windowed RMS (dBFS, -150 = digital silence)
    series_total: list[float] = field(default_factory=list)
    series_50: list[float] = field(default_factory=list)
    series_60: list[float] = field(default_factory=list)
    dialogue_lufs: float | None = None       # speech-gated integrated loudness, when computed
    dialogue_coverage: float | None = None   # fraction of the programme that is speech


@dataclass
class Measurements:
    """Primary-track fields at the top level (0.1 compatibility) plus every track."""

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
    tracks: list[TrackMeasurements] = field(default_factory=list)


def _main_pass(ffmpeg: str, path, idx: int, st: StreamInfo, settings: Settings) -> TrackMeasurements:
    af = (
        "ebur128=peak=true:framelog=verbose,"
        "astats=metadata=0:measure_perchannel=Peak_level+RMS_level+DC_offset"
        ":measure_overall=Peak_level+RMS_level+DC_offset+Flat_factor,"
        f"silencedetect=noise={settings.silence_dbfs}dB:d=0.5"
    )
    # `-t max_duration_s` bounds how much is actually processed even if the container LIES about
    # its duration (the probe cap trusts metadata; this caps the real decode regardless).
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-v", "verbose", "-threads", "1", "-i", str(path),
            "-map", f"0:a:{idx}?", "-t", str(settings.max_duration_s), "-af", af, "-f", "null", "-"]
    proc = run(argv, timeout_s=settings.decode_timeout_s)
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        from ..errors import DecodeError
        raise DecodeError(f"ffmpeg analysis failed (rc={proc.returncode}): {err[-300:]}")

    tm = TrackMeasurements(stream=st)
    eb = parse_ebur128(err)
    tm.integrated_lufs, tm.lra, tm.true_peak_dbtp = eb.get("I"), eb.get("LRA"), eb.get("true_peak")
    tm.frames = parse_frames(err)
    sections = parse_astats_sections(err)
    if sections:
        sec = sections[min(sections)]
        ov = sec["overall"]
        tm.peak_dbfs, tm.rms_dbfs = ov.get("peak"), ov.get("rms")
        tm.dc_offset, tm.flat_factor = ov.get("dc"), ov.get("flat")
        labels = st.channel_labels()
        for i, ch in enumerate(sec["channels"]):
            tm.channels.append(ChannelStats(label=labels[i] if i < len(labels) else f"ch{i + 1}",
                                            rms_dbfs=ch.get("rms"), peak_dbfs=ch.get("peak"),
                                            dc_offset=ch.get("dc")))
    else:  # older ffmpeg without section headers — fall back to the flat parse
        ast = parse_astats(err)
        tm.peak_dbfs, tm.rms_dbfs = ast.get("peak"), ast.get("rms")
        tm.dc_offset, tm.flat_factor = ast.get("dc"), ast.get("flat")
    tm.silences = parse_silences(err)
    return tm


def _spectral_pass(ffmpeg: str, path, idx: int, tm: TrackMeasurements, settings: Settings) -> None:
    n = _SERIES_RATE // SERIES_HZ
    series = ("astats=metadata=1:reset=1:measure_perchannel=none:measure_overall=RMS_level,"
              "ametadata=mode=print:key=lavfi.astats.Overall.RMS_level")

    def band(f: int) -> str:  # two cascaded high-Q band-passes isolate the mains fundamental
        return f"bandpass=f={f}:width_type=q:w=15,bandpass=f={f}:width_type=q:w=15"

    stereo = tm.stream.channels >= 2
    graph = [f"[0:a:{idx}]asplit=2[r1][r2]" if stereo else f"[0:a:{idx}]anull[r1]",
             f"[r1]aresample={_SERIES_RATE},aformat=channel_layouts=mono,"
             f"asetnsamples=n={n}:p=0,asplit=3[t][a][b]",
             f"[t]{series}[ot]", f"[a]{band(50)},{series}[o50]", f"[b]{band(60)},{series}[o60]"]
    outs = ["[ot]", "[o50]", "[o60]"]
    if stereo:
        # Mid = (L+R)/2, Side = (L-R)/2 over the first channel pair. Side ≫ mid = polarity problem.
        graph.append("[r2]pan=stereo|c0=0.5*c0+0.5*c1|c1=0.5*c0-0.5*c1,"
                     "astats=metadata=0:measure_perchannel=RMS_level:measure_overall=none[oms]")
        outs.append("[oms]")
    # Input-side -t: with several outputs an output-side -t would bound only the first one.
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-t", str(settings.max_duration_s),
            "-i", str(path), "-filter_complex", ";".join(graph)]
    for o in outs:
        argv += ["-map", o, "-f", "null", "-"]
    proc = run(argv, timeout_s=settings.decode_timeout_s)
    if proc.returncode != 0:
        return  # best-effort: the main pass already graded the essentials
    err = proc.stderr.decode("utf-8", "replace")
    ser = parse_metadata_series(err)
    keys = sorted(ser)  # instance numbers follow graph order: total, 50 Hz, 60 Hz
    if len(keys) >= 3:
        tm.series_total, tm.series_50, tm.series_60 = (ser[k] for k in keys[:3])
    if stereo:
        sec = parse_astats_sections(err)
        if sec:
            chans = sec[max(sec)]["channels"]
            if len(chans) >= 2:
                tm.mid_rms_dbfs, tm.side_rms_dbfs = chans[0].get("rms"), chans[1].get("rms")


def _tail_pass(ffmpeg: str, path, idx: int, tm: TrackMeasurements, settings: Settings) -> None:
    # Truncation cue: RMS of the final 250 ms. A clip that ends loud (no trailing decay/silence)
    # is a likely mid-word cut. Bounded second pass via -sseof.
    tail = run([ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-sseof", "-0.25",
                "-i", str(path), "-map", f"0:a:{idx}?",
                "-af", "astats=metadata=0:measure_overall=RMS_level:measure_perchannel=none",
                "-f", "null", "-"], timeout_s=min(30.0, settings.decode_timeout_s))
    tm.tail_rms_dbfs = parse_astats(tail.stderr.decode("utf-8", "replace")).get("rms")


def measure_track(path, st: StreamInfo, settings: Settings) -> TrackMeasurements:
    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    tm = _main_pass(ffmpeg, path, st.index, st, settings)
    if settings.hum_detection or st.channels >= 2:
        _spectral_pass(ffmpeg, path, st.index, tm, settings)
    _tail_pass(ffmpeg, path, st.index, tm, settings)
    return tm


def measure(path, info: MediaInfo, settings: Settings) -> Measurements:
    """Run the analysis passes over an already path-validated, probed file (every audio track)."""
    m = Measurements(info=info)
    if not info.has_audio:
        return m
    streams = list(info.streams) or [StreamInfo(index=0, codec=info.codec,
                                                sample_rate=info.sample_rate,
                                                channels=info.channels)]
    if not settings.analyze_all_tracks:
        streams = streams[:1]
    m.tracks = [measure_track(path, st, settings) for st in streams]
    p = m.tracks[0]
    m.integrated_lufs, m.lra, m.true_peak_dbtp = p.integrated_lufs, p.lra, p.true_peak_dbtp
    m.peak_dbfs, m.rms_dbfs, m.dc_offset, m.flat_factor = p.peak_dbfs, p.rms_dbfs, p.dc_offset, p.flat_factor
    m.silences, m.tail_rms_dbfs = p.silences, p.tail_rms_dbfs
    return m
