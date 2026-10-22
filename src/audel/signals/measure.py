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
from ..errors import AudelError, BusyError, UnsafeSourceError
from ..mediaguard import MediaInfo, StreamInfo, _tool, pass_timeout, pcm_pipeline
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
    decoded_s: float = 0.0                   # audio actually decoded (last loudness frame)
    decode_errors: int = 0                   # problems the decoder reported (corrupt data)
    gaps: list[tuple[float, float]] = field(default_factory=list)  # missing-packet gaps (s)
    start_s: float = 0.0                     # start on the programme timeline
    failed: str | None = None                # this track could not be decoded (reason)
    gap_scan_incomplete: bool = False        # the packet timeline couldn't be read in full
    dialogue_lufs: float | None = None       # speech-gated integrated loudness, when computed
    dialogue_coverage: float | None = None   # fraction of the programme that is speech
    dialogue_status: str | None = None       # ok / failed / no_speech (dialogue-gated specs)
    seek_base_s: float = 0.0                 # programme time -> ffmpeg input -ss offset
    gap_total_s: float = 0.0                 # ALL missing-packet time (gaps lists the first ones)
    extent_s: float = 0.0                    # how long the packet timeline says the track runs
    overlap_s: float = 0.0                   # decoded audio laid over earlier packets (duplicates)
    timestamp_jumps: int = 0                 # impossible timestamp jumps (a corrupt timeline)
    spectral_failed: bool = False            # hum / noise floor / phase checks couldn't run

    @property
    def end_s(self) -> float:
        """Where this track ends on the programme timeline (missing packets included)."""
        return self.stream.start_s + self.decoded_s + max(self.gap_total_s,
                                                          sum(b - a for a, b in self.gaps))

    def to_programme(self, t_s: float) -> float:
        """Map a time in the DECODED audio (restamped by sample count, so missing packets are
        closed up) onto the programme timeline: add the track start and every gap before it."""
        p = self.stream.start_s + t_s
        for a, b in self.gaps:  # sorted, programme time
            if p >= a:
                p += b - a
            else:
                break
        return p


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
    deadline: float | None = None  # the per-file deadline (later passes stay inside it)
    tracks: list[TrackMeasurements] = field(default_factory=list)
    declared_s: float | None = None          # set when the container's duration was wrong


def _rate(st: StreamInfo) -> int:
    return st.sample_rate if 8000 <= st.sample_rate <= 384_000 else 48000


def _pipe(path, st: StreamInfo, settings: Settings, analysis: list[str], dur_s: float, *,
          pre_input: list[str] | None = None, verbose: bool = False,
          deadline: float | None = None, stats: dict | None = None) -> str:
    import time

    timeout = pass_timeout(settings, dur_s)
    if deadline is not None:
        left = deadline - time.monotonic()
        if left <= 1:
            raise UnsafeSourceError("analysis exceeded the per-file time budget")
        timeout = min(timeout, left)
    return pcm_pipeline(path, settings, stream=st.index, channels=st.channels or 1,
                        sample_rate=_rate(st), layout=st.layout, analysis=analysis,
                        timeout_s=timeout, pre_input=pre_input, verbose=verbose, stats=stats,
                        abs_index=st.abs_index, codec=st.codec)


def _main_pass(ffmpeg: str, path, idx: int, st: StreamInfo, settings: Settings,
               dur_s: float = 0.0, deadline: float | None = None) -> TrackMeasurements:
    af = (
        "ebur128=peak=true:framelog=verbose,"
        "astats=metadata=0:measure_perchannel=Peak_level+RMS_level+DC_offset"
        ":measure_overall=Peak_level+RMS_level+DC_offset+Flat_factor,"
        f"silencedetect=noise={settings.silence_dbfs}dB:d=0.5"
    )
    # The untrusted file is decoded in a separate process; this analysis sees raw PCM only, so
    # container metadata can never appear in the text parsed below.
    stats: dict = {}
    err = _pipe(path, st, settings, ["-af", af, "-f", "null", "-"], dur_s, verbose=True,
                deadline=deadline, stats=stats)

    tm = TrackMeasurements(stream=st)
    eb = parse_ebur128(err)
    tm.integrated_lufs, tm.lra, tm.true_peak_dbtp = eb.get("I"), eb.get("LRA"), eb.get("true_peak")
    tm.frames = parse_frames(err, max_frames=int(settings.max_duration_s * 10) + 1000)
    tm.decode_errors = int(stats.get("decode_errors", 0))
    tm.decoded_s = max((f[0] for f in tm.frames), default=0.0)
    if tm.decoded_s >= settings.max_duration_s - 0.5:
        # Decoding reached the cap: audio beyond it would go unmeasured. Fail closed.
        raise UnsafeSourceError(
            f"audio decodes to at least {settings.max_duration_s:.0f}s, the maximum duration")
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


def _spectral_pass(ffmpeg: str, path, idx: int, tm: TrackMeasurements, settings: Settings,
                   dur_s: float = 0.0, deadline: float | None = None) -> None:
    n = _SERIES_RATE // SERIES_HZ
    series = ("astats=metadata=1:reset=1:measure_perchannel=none:measure_overall=RMS_level,"
              "ametadata=mode=print:key=lavfi.astats.Overall.RMS_level")

    def band(f: int) -> str:  # two cascaded high-Q band-passes isolate the mains fundamental
        return f"bandpass=f={f}:width_type=q:w=15,bandpass=f={f}:width_type=q:w=15"

    from ..mediaguard import lr_pair, mono_filter

    pair = lr_pair(tm.stream)
    stereo = pair is not None
    # Mono by channel index (any layout: ffmpeg's layout-based downmix rejects plain-channel
    # layouts, which silently skipped hum / phase / polarity on unlabelled files).
    graph = ["[0:a:0]asplit=2[r1][r2]" if stereo else "[0:a:0]anull[r1]",
             f"[r1]{mono_filter(tm.stream, power=True)},aresample={_SERIES_RATE},"
             f"asetnsamples=n={n}:p=0,asplit=3[t][a][b]",
             f"[t]{series}[ot]", f"[a]{band(50)},{series}[o50]", f"[b]{band(60)},{series}[o60]"]
    outs = ["[ot]", "[o50]", "[o60]"]
    if pair is not None:
        # Mid = (L+R)/2, Side = (L-R)/2 over the real FL / FR pair, wherever it sits in the
        # channel order. Side >> mid = polarity problem.
        a, b = pair
        graph.append(f"[r2]pan=stereo|c0=0.5*c{a}+0.5*c{b}|c1=0.5*c{a}-0.5*c{b},"
                     "astats=metadata=0:measure_perchannel=RMS_level:measure_overall=none[oms]")
        outs.append("[oms]")
    analysis = ["-filter_complex", ";".join(graph)]
    for o in outs:
        analysis += ["-map", o, "-f", "null", "-"]
    try:
        err = _pipe(path, tm.stream, settings, analysis, dur_s, deadline=deadline)
    except (UnsafeSourceError, BusyError):
        raise  # a busy host must not silently drop checks (it is retried, not graded partially)
    except AudelError:
        tm.spectral_failed = True  # reported: hum / noise / phase checks could not run
        return
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


def _tail_pass(ffmpeg: str, path, idx: int, tm: TrackMeasurements, settings: Settings,
               deadline: float | None = None) -> None:
    # Truncation cue: RMS of the final 250 ms of the DECODED audio (not the container's claimed
    # end, which a file can misstate). A clip that ends loud is a likely mid-word cut.
    # Container-time seek to this track's real end (its start on the timeline + decoded length).
    seek = (["-ss", f"{max(0.0, tm.seek_base_s + tm.end_s - 0.25):.3f}"]
            if tm.decoded_s > 0 else ["-sseof", "-0.25"])
    try:
        err = _pipe(path, tm.stream, settings,
                    ["-af", "astats=metadata=0:measure_overall=RMS_level:measure_perchannel=none",
                     "-f", "null", "-"], 1.0, pre_input=seek, deadline=deadline)
    except (UnsafeSourceError, BusyError):
        raise  # a busy host must not silently drop the truncation check
    except AudelError:
        return
    tm.tail_rms_dbfs = parse_astats(err).get("rms")


def measure_track(path, st: StreamInfo, settings: Settings, dur_s: float = 0.0,
                  deadline: float | None = None, *, timeline=None) -> TrackMeasurements:
    """Every analysis pass over one track. ``timeline(st)`` (from :func:`measure`) returns the
    track placed on the programme timeline: ``(stream, gaps, gap_scan_incomplete, seek_base)``.
    It is awaited only before the tail pass, so the packet scan overlaps the decode passes."""
    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    tm = _main_pass(ffmpeg, path, st.index, st, settings, dur_s, deadline)
    if settings.hum_detection or st.channels >= 2:
        _spectral_pass(ffmpeg, path, st.index, tm, settings, max(dur_s, tm.decoded_s), deadline)
    if timeline is not None:
        (tm.stream, gaps, tm.gap_scan_incomplete, tm.seek_base_s, tm.gap_total_s,
         tm.extent_s, tm.overlap_s, tm.timestamp_jumps) = timeline(st)
        tm.gaps = sorted(gaps)
    _tail_pass(ffmpeg, path, st.index, tm, settings, deadline)
    return tm


def _scan(path, st: StreamInfo, settings: Settings, deadline: float, stop=None,
          fold: bool = True, restarts: bool = False):
    """The packet scan, inside the per-file budget (it may not outlive the file's deadline)."""
    import time

    from ..mediaguard import scan_packets

    left = deadline - time.monotonic()
    if left <= 1:
        raise UnsafeSourceError("analysis exceeded the per-file time budget")
    return scan_packets(path, settings, st.abs_index, timeout_s=left, stop=stop, fold=fold,
                        restarts=restarts)


def _shared_clock(scans) -> None:
    """MPEG-TS: every PID shares one clock, but each scan folded only its OWN jumps. A track
    that starts after a splice must be placed on the reference track's folded clock (the
    earliest-starting track), or it lands a whole splice away."""
    live = [sc for sc in scans if sc is not None and sc.first_pts is not None]
    if len(live) < 2:
        return
    ref = min(live, key=lambda sc: sc.first_pts)
    for sc in live:
        if sc is ref:
            continue
        # The reference clock's segment this track starts in: the one with the greatest raw start
        # not after it (segments are in stream order, not timestamp order), tolerating ordinary
        # inter-PID skew around a splice (well under the 60 s fold rule).
        cands = [(raw, off) for raw, off in ref.segments if raw <= sc.first_pts + 30.0]
        shift = max(cands)[1] if cands else 0.0
        if shift:
            sc.first_pts -= shift
            if sc.last_end is not None:
                sc.last_end -= shift
            sc.gaps = [(a - shift, b - shift) for a, b in sc.gaps]


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
    if 0 < info.decode_cap_s < settings.max_duration_s:
        # Unknown length: each stream decodes at most its share of the budgets (fails closed).
        settings = settings.model_copy(update={"max_duration_s": info.decode_cap_s})
    import dataclasses
    import time

    # One deadline for the whole file (all tracks, all passes), sized by declared work; a missing
    # duration counts as the maximum.
    dur = info.duration_s if info.duration_s > 0 else settings.max_duration_s
    channel_s = sum(max(1, s.channels) for s in streams) * dur
    deadline = time.monotonic() + settings.decode_timeout_s + \
        channel_s * settings.decode_timeout_per_channel_s
    # Each track's start is its FIRST PACKET (ffprobe's start_time is an estimate that goes wrong
    # when the audio begins late in the file). The programme timeline starts at the CONTAINER
    # start, which video may set before the audio.
    import concurrent.futures as cf
    import threading

    pool = cf.ThreadPoolExecutor(max_workers=2, thread_name_prefix="audel-scan")
    stop = threading.Event()
    # Timestamp jumps are folded out only where splices are routine (MPEG-TS/PS); elsewhere a
    # jump is missing audio.
    futures: list = []
    try:
        for st in streams:
            futures.append(pool.submit(_scan, path, st, settings, deadline, stop,
                                       info.estimated_durations, info.chained))
    except RuntimeError:  # the host can't start another thread: retry later, leave nothing
        stop.set()
        pool.shutdown(wait=False, cancel_futures=True)
        raise BusyError("could not start analysis: the host is at capacity; retry later") from None
    placed: dict = {}

    def timeline(st: StreamInfo):
        if not placed:
            scans = []
            for f in futures:
                try:
                    scans.append(f.result(timeout=max(0.0, deadline - time.monotonic()) + 5))
                except cf.TimeoutError:
                    raise UnsafeSourceError("analysis exceeded the per-file time budget") from None
            if info.estimated_durations:
                _shared_clock(scans)
            starts = [sc.first_pts if sc is not None and sc.first_pts is not None else s.start_s
                      for s, sc in zip(streams, scans, strict=True)]
            first_audio = min(starts, default=0.0)
            origin = (info.format_start if info.format_start is not None
                      and info.format_start <= first_audio else first_audio)
            # ffmpeg's -ss counts from the container's (signed) start time.
            seek_base = origin - (info.format_start_raw or 0.0)
            placed[-1] = (origin,)
            for s, sc, start in zip(streams, scans, starts, strict=True):
                # Packet times are on the scan's continuous clock, anchored at the first packet.
                gaps = [(a - origin, b - origin) for a, b in sc.gaps] if sc is not None else []
                placed[s.index] = (dataclasses.replace(s, start_s=max(0.0, start - origin)), gaps,
                                   sc is not None and not sc.complete, seek_base,
                                   sc.gap_total_s if sc is not None else 0.0,
                                   # AVI times compressed audio by byte position (a nominal
                                   # rate), so its extent is no measure of the audio.
                                   sc.extent_s if sc is not None and sc.complete
                                   and not (info.byte_clock and not s.codec.startswith("pcm"))
                                   else 0.0,
                                   sc.overlap_s if sc is not None else 0.0,
                                   sc.jumps if sc is not None else 0)
                if info.packets_declare_end and sc is not None and sc.last_end is not None \
                        and sc.complete:
                    # TS durations are bitrate estimates, ASF copies the file's onto every
                    # stream: the packets are the declaration.
                    placed[("end", s.index)] = sc.last_end - origin
        return placed[st.index]

    m.tracks = []
    m.deadline = deadline
    try:
        for st in streams:
            try:
                m.tracks.append(measure_track(path, st, settings, info.duration_s, deadline,
                                              timeline=timeline))
            except UnsafeSourceError:
                raise  # caps / budgets / deadline: the whole file is refused (fail closed)
            except BusyError:
                raise  # the host, not the media: never report a track as undecodable for it
            except AudelError as e:
                # One undecodable track must not discard the others' results: grade what
                # decodes and report this track by name.
                from ..errors import sanitize_message

                m.tracks.append(TrackMeasurements(stream=st,
                                                  failed=sanitize_message(str(e), limit=160)))
        timeline(streams[0])  # place every track (also those that failed to decode)
    except BaseException:
        stop.set()  # every early exit: running scans are killed, queued ones never start
        raise
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    origin = placed[-1][0]
    for t in m.tracks:
        if t.failed:
            t.stream = placed[t.stream.index][0]
    if all(t.failed for t in m.tracks):
        from ..errors import DecodeError

        raise DecodeError(m.tracks[0].failed or "no audio track could be decoded")
    decoded = max((t.end_s for t in m.tracks if not t.failed), default=0.0)
    # Compare against what the container declares for its AUDIO: where the streams themselves
    # say they end (ffprobe's start + duration, one consistent estimate; video may run longer),
    # when every graded track declares one, else the container's duration.
    live = [t for t in m.tracks if not t.failed]
    if live and info.packets_declare_end and all(("end", t.stream.index) in placed for t in live):
        declared = max(placed[("end", t.stream.index)] for t in live)
    elif info.byte_clock and not all(t.stream.codec.startswith("pcm") for t in live):
        declared = 0.0  # AVI sizes compressed audio by a nominal byte rate: not a real claim
    elif live and all(t.stream.declared_end_s is not None for t in live):
        declared = max((t.stream.declared_end_s or 0.0) - origin for t in live)
    elif info.has_video:
        declared = 0.0  # the container's duration includes the picture: not the audio's claim
    else:
        declared = info.duration_s
    if decoded > 0 and (declared <= 0 or abs(decoded - declared) > max(1.0, 0.02 * declared)):
        # Grade the audio that is actually there. A container that DECLARED a wrong length is
        # reported; one that declared none is not.
        if declared > 0:
            m.declared_s = declared
        m.info = dataclasses.replace(info, duration_s=decoded)
    p = next((t for t in m.tracks if not t.failed), m.tracks[0])
    m.integrated_lufs, m.lra, m.true_peak_dbtp = p.integrated_lufs, p.lra, p.true_peak_dbtp
    m.peak_dbfs, m.rms_dbfs, m.dc_offset, m.flat_factor = p.peak_dbfs, p.rms_dbfs, p.dc_offset, p.flat_factor
    m.silences, m.tail_rms_dbfs = p.silences, p.tail_rms_dbfs
    return m
