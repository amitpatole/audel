"""Decode-surface guards — the audio analog of AgentVision's ``imageguard``.

Untrusted media is the highest-risk input Audel takes. Every ffmpeg/ffprobe invocation goes
through here: sources are charset/shape-validated (path traversal, option-injection), byte- and
duration-capped **before** any decode (a tiny file declaring a multi-hour stream is a
decompression bomb), and the subprocess is run in argv form (no shell) under wall-clock timeouts
and ``RLIMIT_*`` (address space / CPU / file size / process count) so a malicious file cannot
exhaust the host. Fails closed: anything unparseable or over a cap raises ``UnsafeSourceError``.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .errors import BusyError, DecodeError, MissingDependencyError, UnsafeSourceError
from .logging import get_logger

_log = get_logger("mediaguard")

# Hard ceilings for any decode subprocess (independent of declared media size). RLIMIT_AS is set
# generously (it bounds *virtual* address space — too low spuriously kills ffmpeg's thread stacks/
# mmap); the real decompression-bomb defense is the pre-decode byte/duration/sample-rate caps plus
# the wall-clock timeout and CPU limit. Analysis runs single-threaded (`-threads 1`) to keep
# resource use small and predictable.
_RLIMIT_AS_BYTES = 4 * 1024 * 1024 * 1024   # 4 GiB virtual address space (headroom)
_RLIMIT_FSIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB max single file write
_RLIMIT_CPU_PAD_S = 30                         # CPU-seconds headroom over the wall timeout
# NOTE: RLIMIT_NPROC is deliberately NOT used — it caps the *whole UID's* process count (not this
# subprocess's threads), so it spuriously fails under normal multi-process load. A fork bomb is not
# a real vector here: we exec one fixed binary (ffmpeg/ffprobe) with fixed argv over an
# attacker-controlled *file*, never an attacker-controlled command. CPU + wall timeout + AS + FSIZE
# bound the actual DoS surface.


# Channel labels for the common layouts ffprobe reports (FFmpeg channel order).
CHANNEL_LABELS: dict[str, list[str]] = {
    "mono": ["FC"],
    "stereo": ["FL", "FR"],
    "2.1": ["FL", "FR", "LFE"],
    "3.0": ["FL", "FR", "FC"],
    "quad": ["FL", "FR", "BL", "BR"],
    "4.0": ["FL", "FR", "FC", "BC"],
    "5.0": ["FL", "FR", "FC", "BL", "BR"],
    "5.0(side)": ["FL", "FR", "FC", "SL", "SR"],
    "5.1": ["FL", "FR", "FC", "LFE", "BL", "BR"],
    "5.1(side)": ["FL", "FR", "FC", "LFE", "SL", "SR"],
    "7.1": ["FL", "FR", "FC", "LFE", "BL", "BR", "SL", "SR"],
    "downmix": ["DL", "DR"],
    "3.1": ["FL", "FR", "FC", "LFE"],
    "quad(side)": ["FL", "FR", "SL", "SR"],
    "4.1": ["FL", "FR", "FC", "LFE", "BC"],
    "6.0": ["FL", "FR", "FC", "BC", "SL", "SR"],
    "6.0(front)": ["FL", "FR", "FLC", "FRC", "SL", "SR"],
    "hexagonal": ["FL", "FR", "FC", "BL", "BR", "BC"],
    "6.1": ["FL", "FR", "FC", "LFE", "BC", "SL", "SR"],
    "6.1(back)": ["FL", "FR", "FC", "LFE", "BL", "BR", "BC"],
    "7.0": ["FL", "FR", "FC", "BL", "BR", "SL", "SR"],
    "7.0(front)": ["FL", "FR", "FC", "FLC", "FRC", "SL", "SR"],
    "7.1(wide)": ["FL", "FR", "FC", "LFE", "BL", "BR", "FLC", "FRC"],
    "7.1(wide-side)": ["FL", "FR", "FC", "LFE", "FLC", "FRC", "SL", "SR"],
    "octagonal": ["FL", "FR", "FC", "BL", "BR", "BC", "SL", "SR"],
}


def _ffmpeg_layout_table() -> dict[str, list[str]]:
    """FFmpeg's own standard-layout table (``ffmpeg -layouts``), parsed once; falls back to the
    built-in table. Using FFmpeg's table keeps labels in FFmpeg's channel order for every layout
    it knows (immersive 5.1.4 / 7.1.4 / 22.2 ...), so an LFE is always recognised as one."""
    global _LAYOUT_CACHE
    if _LAYOUT_CACHE is not None:
        return _LAYOUT_CACHE
    table = dict(CHANNEL_LABELS)
    try:
        path = shutil.which("ffmpeg")
        if path:
            out = subprocess.run([path, "-hide_banner", "-layouts"], capture_output=True,
                                 text=True, timeout=10, check=False).stdout
            section = out.split("Standard channel layouts:", 1)[-1]
            for line in section.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0] != "NAME" and "+" in parts[1] or (
                        len(parts) == 2 and parts[0] == "mono"):
                    table[parts[0]] = parts[1].split("+")
    except (OSError, subprocess.SubprocessError):
        pass
    _LAYOUT_CACHE = table
    return table


_LAYOUT_CACHE: dict[str, list[str]] | None = None


def _mask_inner(layout: str) -> str:
    """ffprobe prints a non-standard channel mask as ``N channels (A+B+...)``: return ``A+B+...``."""
    import re

    m = re.fullmatch(r"\d+ channels \(([A-Za-z0-9+]+)\)", layout or "")
    return m.group(1) if m else layout


def layout_channels(layout: str) -> list[str] | None:
    """Channel names of a layout: FFmpeg's table, or a ``FL+FR+LFE+...`` custom layout."""
    layout = _mask_inner(layout)
    if not layout:
        return None
    if "+" in layout:
        names = [n for n in layout.split("+") if n]
        return names if all(n.isalnum() for n in names) else None
    return _ffmpeg_layout_table().get(layout)


# FFmpeg's default layout per channel count (used when the container carries no channel mask).
_DEFAULT_LAYOUT = {1: "mono", 2: "stereo", 3: "2.1", 6: "5.1", 8: "7.1"}


@dataclass(frozen=True)
class StreamInfo:
    """One audio stream (``index`` is the audio-relative index, i.e. ffmpeg's ``0:a:<index>``)."""

    index: int
    codec: str
    sample_rate: int
    channels: int
    layout: str = ""
    language: str | None = None
    title: str | None = None
    abs_index: int = -1      # the container's stream index (ffmpeg's #0:K)
    start_s: float = 0.0     # where this track starts on the programme timeline
    declared_end_s: float | None = None  # container time the stream DECLARES it ends (start+duration)

    def channel_labels(self) -> list[str]:
        layout = self.layout or _DEFAULT_LAYOUT.get(self.channels, "")
        labels = layout_channels(layout)
        if labels and len(labels) == self.channels:
            return list(labels)
        return [f"ch{i + 1}" for i in range(self.channels)]


# Demuxers Audel will let ffmpeg/ffprobe use on untrusted input. Container formats that make
# ffmpeg open OTHER files or URLs (HLS/DASH playlists, ffconcat, image sequences, tee, subfile...)
# are deliberately absent: a small playlist upload must never become a host-file read.
DEMUXER_ALLOWLIST = (
    "wav,w64,rf64,mp3,flac,ogg,matroska,webm,mov,mp4,m4a,3gp,aac,ac3,eac3,aiff,caf,mxf,mpegts,"
    "avi,asf,amr,dts,truehd,mlp,wv,ape,tta,mpeg,flv,au,opus"
)
# Media extensions a server-named temp file may keep (helps demuxer detection; nothing else).
MEDIA_SUFFIXES = frozenset({
    ".wav", ".w64", ".rf64", ".mp3", ".flac", ".ogg", ".oga", ".opus", ".mkv", ".mka", ".webm",
    ".mov", ".mp4", ".m4a", ".m4v", ".3gp", ".aac", ".ac3", ".eac3", ".aif", ".aiff", ".caf",
    ".mxf", ".ts", ".m2ts", ".mts", ".avi", ".wma", ".wmv", ".asf", ".amr", ".dts", ".thd",
    ".wv", ".ape", ".tta", ".mpg", ".mpeg", ".flv", ".au",
})


def safe_input(path) -> list[str]:
    """``-i`` for untrusted media: local-file protocol only, allowlisted demuxers only."""
    return ["-protocol_whitelist", "file", "-format_whitelist", DEMUXER_ALLOWLIST, "-i", str(path)]


def media_suffix(name: str | None) -> str:
    """The lowercase extension of ``name`` if it is a known media extension, else ``""``."""
    suf = Path(name or "").suffix.lower()[:10]
    return suf if suf in MEDIA_SUFFIXES else ""


@dataclass(frozen=True)
class MediaInfo:
    duration_s: float
    sample_rate: int
    channels: int
    codec: str
    has_audio: bool
    streams: tuple[StreamInfo, ...] = ()
    format_start: float | None = None  # container start time (the programme timeline origin)
    format_start_raw: float | None = None  # signed container start (seek arithmetic only)
    has_video: bool = False            # a real picture stream (not cover art)
    container_shortfall_s: float = 0.0  # header-declared audio missing (WAV/W64/AIFF/CAF)
    estimated_durations: bool = False   # MPEG-TS/PS: stream durations are bitrate estimates
    packets_declare_end: bool = False   # per-stream durations unreliable (TS/PS estimates, ASF
                                        # copies the file's): the packets are the declaration


def _tool(name: str, override: str | None = None) -> str:
    path = override or shutil.which(name)
    if not path:
        raise MissingDependencyError(f"{name} not found on PATH; install ffmpeg to decode audio.")
    return path


def _rlimit_setter(cpu_s: int):
    def _apply() -> None:  # pragma: no cover - runs in the forked child before exec (POSIX only)
        limits = [
            (resource.RLIMIT_AS, _RLIMIT_AS_BYTES),
            (resource.RLIMIT_FSIZE, _RLIMIT_FSIZE_BYTES),
            (resource.RLIMIT_CPU, cpu_s),
        ]
        for what, soft in limits:
            try:
                hard = resource.getrlimit(what)[1]
                cap = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
                resource.setrlimit(what, (cap, hard))
            except (ValueError, OSError):
                pass
    return _apply


def _popen(argv: list[str], **kw) -> subprocess.Popen:
    """Start a tool process. A host at its process / memory limit (EAGAIN, ENOMEM) is a capacity
    problem, not a property of the media: raise BusyError (HTTP 429), never a bare 500."""
    try:
        return subprocess.Popen(argv, **kw)
    except OSError:
        raise BusyError("could not start the decoder: the host is at capacity; retry later") from None


def run(argv: list[str], *, timeout_s: float, max_stdout_bytes: int | None = None) -> subprocess.CompletedProcess:
    """Run an ffmpeg/ffprobe argv with no shell, hard timeout, and child resource limits.

    ``argv[0]`` must be an absolute tool path (from :func:`_tool`). Output is captured; stdout is
    truncated to ``max_stdout_bytes`` when given (bounds raw-PCM decode buffers).
    """
    pre = _rlimit_setter(int(timeout_s) + _RLIMIT_CPU_PAD_S) if os.name == "posix" else None
    p = _popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, preexec_fn=pre)
    assert p.stdout is not None and p.stderr is not None
    out = _BoundedReader(p.stdout, max_stdout_bytes or 16 * 1024 * 1024)
    err = _BoundedReader(p.stderr, 1024 * 1024, tail=True)  # bounded: a flood can't grow memory
    try:
        p.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        p.kill()
        p.wait()
        raise UnsafeSourceError(f"decode exceeded {timeout_s}s timeout (possible resource bomb)") from e
    except BaseException:
        p.kill()
        p.wait()
        raise
    return subprocess.CompletedProcess(argv, p.returncode, out.join(5), err.join(5))


class _BoundedReader:
    """Drain a pipe in a thread, keeping at most ``cap`` bytes (head) so a flood of tool output
    can never grow memory. ``tail`` keeps the LAST bytes instead (for error context)."""

    def __init__(self, pipe, cap: int, tail: bool = False) -> None:
        import threading

        self._pipe, self._cap, self._tail = pipe, cap, tail
        self.data = bytearray()
        self.truncated = False
        self.lines = 0
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        try:
            while True:
                chunk = self._pipe.read(65536)
                if not chunk:
                    break
                self.lines += chunk.count(b"\n")
                if self._tail:
                    self.data += chunk
                    if len(self.data) > self._cap:
                        del self.data[:len(self.data) - self._cap]
                        self.truncated = True
                elif len(self.data) < self._cap:
                    self.data += chunk[: self._cap - len(self.data)]
                else:
                    self.truncated = True
        except (OSError, ValueError):
            pass

    def join(self, timeout: float | None = None) -> bytes:
        self._t.join(timeout)
        return bytes(self.data)


def pass_timeout(settings: Settings, duration_s: float) -> float:
    """Wall-clock budget for one analysis pass, scaled by DECLARED duration so a legitimate
    3-hour master can finish while a bomb is still bounded (duration is capped before decode)."""
    return settings.decode_timeout_s + max(0.0, duration_s) * settings.decode_timeout_per_audio_s


def pcm_pipeline(path: Path, settings: Settings, *, stream: int, channels: int,
                 sample_rate: int, analysis: list[str], timeout_s: float,
                 pre_input: list[str] | None = None, layout: str = "",
                 verbose: bool = False, max_stderr: int = 128 * 1024 * 1024,
                 stats: dict | None = None, abs_index: int = -1) -> str:
    """Decode the untrusted file to raw float PCM in one process and ANALYSE it in another.

    The analysing ffmpeg only ever sees a raw PCM stream (no container, no metadata, no tags), so
    nothing attacker-controlled can appear in the stderr we parse for measurements. The decoding
    ffmpeg runs quietly (``-v error``) with only a 64 KB stderr tail kept. Both processes run in
    argv form under RLIMITs and share one wall-clock deadline; on timeout both are killed.
    Returns the analysing process's stderr (trusted text).
    """
    import time

    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    ch = max(1, int(channels))
    # Loudness/true-peak meters oversample internally; analysing above 48 kHz only multiplies
    # the cost an upload can impose, so the analysis rate is capped.
    sr = max(1, min(int(sample_rate), ANALYSIS_MAX_RATE))
    lay = channel_layout_arg(layout, ch)
    # -reinit_filter 0: a stream that changes sample rate / channel count mid-file is REFUSED
    # rather than silently resampled to its first frame's format (which hid most of the audio).
    # -ch_layout keeps the stream's own channel order (an -ac N remix would relabel channels).
    # The decoder runs at -v verbose so it prints its own per-stream summary ("N decode errors")
    # for the mapped stream only; error lines from OTHER streams (probing decodes them all) are
    # never counted. -err_detect crccheck makes CRC-protected codecs report corruption.
    decode = [ffmpeg, "-nostdin", "-hide_banner", "-v", "verbose", "-threads", "1",
              "-reinit_filter", "0", "-err_detect", "crccheck+explode",
              *(pre_input or []), *safe_input(path),
              "-map", f"0:a:{int(stream)}",
              # Restamp by SAMPLE COUNT before the -t cap: a forward timestamp jump must not end
              # decoding early (and leave the audio after it unmeasured).
              "-af", "asetpts=N/SR/TB", "-t", str(settings.max_duration_s),
              "-vn", "-sn", "-dn", "-map_metadata", "-1",
              # a named layout is kept as-is; an unordered one passes through untouched
              *([] if lay.startswith("USR") else ["-ch_layout", lay]), "-ar", str(sr),
              "-f", "f32le", "-acodec", "pcm_f32le", "pipe:1"]
    analyse = [ffmpeg, "-nostdin", "-hide_banner", "-v", "verbose" if verbose else "info",
               "-threads", "1", "-f", "f32le", "-ar", str(sr), "-ch_layout", lay,
               "-i", "pipe:0", *analysis]
    pre = _rlimit_setter(int(timeout_s) + _RLIMIT_CPU_PAD_S) if os.name == "posix" else None
    p1 = _popen(decode, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, preexec_fn=pre)
    try:
        p2 = _popen(analyse, stdin=p1.stdout, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, preexec_fn=pre)
    except BaseException:
        p1.kill()
        p1.wait()
        raise
    assert p1.stdout is not None and p1.stderr is not None and p2.stderr is not None
    p1.stdout.close()  # p2 owns the read end now (so p1 gets SIGPIPE if p2 exits)
    err1 = _BoundedReader(p1.stderr, 64 * 1024, tail=True)
    err2 = _BoundedReader(p2.stderr, max_stderr)
    deadline = time.monotonic() + timeout_s
    try:
        for proc in (p2, p1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(analyse, timeout_s)
            proc.wait(timeout=remaining)
    except subprocess.TimeoutExpired as e:
        for proc in (p1, p2):
            proc.kill()
        for proc in (p1, p2):
            proc.wait()
        raise UnsafeSourceError(f"analysis exceeded {timeout_s:.0f}s (possible resource bomb)") from e
    except BaseException:
        for proc in (p1, p2):
            proc.kill()
            proc.wait()
        raise
    tail1 = err1.join(5).decode("utf-8", "replace")
    out2 = err2.join(5).decode("utf-8", "replace")
    if stats is not None:
        stats["decode_errors"] = _stream_decode_errors(tail1, abs_index)
    for pipe in (p1.stderr, p2.stderr):
        try:
            pipe.close()
        except OSError:
            pass
    if p2.returncode != 0:
        raise DecodeError(f"analysis failed (rc={p2.returncode})")
    # A decoder stopped by a closed pipe (analysis finished early) exits 224 / -13: not an error.
    if p1.returncode not in (0, None, 224, -13):
        raise DecodeError(f"could not decode audio: {tail1[-200:]}")
    return out2


ANALYSIS_MAX_RATE = 48000


def _stream_decode_errors(text: str, abs_index: int) -> int:
    """ffmpeg's own count for ONE stream, from its anchored end-of-run summary line
    (``[in#0/...]   Input stream #0:K (audio): ... N decode errors``). Metadata dump lines are
    indented and can't start a line with ``[in#0/``, so tag text can't forge this."""
    import re

    k = abs_index if abs_index >= 0 else r"\d+"
    rx = re.compile(r"^\[in#0/[^\]\n]+\]\s+Input stream #0:" + str(k)
                    + r" \(audio\):[^\n]*?(\d+) decode errors", re.MULTILINE)
    found = rx.findall(text)
    return int(found[-1]) if found else 0


_MAX_PACKET_GAP_S = 60.0


@dataclass
class PacketScan:
    """A stream's packet timeline, in the container's time base. In MPEG-TS/PS a timestamp jump
    (a splice, a wrap) is folded out, so times are on a CONTINUOUS clock; ``segments`` records
    where each fold happened (raw pts, offset) so other tracks can share the same clock."""

    first_pts: float | None = None
    last_end: float | None = None      # where the last packet ends, on the same clock
    gaps: list[tuple[float, float]] = field(default_factory=list)  # first ``limit`` gaps
    gap_total_s: float = 0.0           # ALL missing time, including gaps past ``limit``
    gap_count: int = 0
    segments: list[tuple[float, float]] = field(default_factory=list)
    complete: bool = True

    @property
    def extent_s(self) -> float:
        if self.first_pts is None or self.last_end is None:
            return 0.0
        return max(0.0, self.last_end - self.first_pts)


class _GapScanner:
    """Streaming missing-packet detector with bounded memory.

    * a hole BETWEEN packets (the next packet starts after the previous one ended), and
    * one packet far longer than the stream's normal packet (MP4/MOV store a hole as one long
      sample duration). The final packet is exempt: it is legitimately short or long.
    Packets without a duration are taken at the stream's typical length (TrueHD in MKV).

    Timestamp jumps: a BACKWARD jump re-anchors the clock in every container. A huge FORWARD
    jump is folded out only when ``fold`` (MPEG-TS/PS, where splices are routine); elsewhere it is
    missing audio and reported as a gap. A jump that returns to the old clock within a few
    packets was a stray packet (a decoy), so the gap is measured against the old clock."""

    _CALIBRATE = 4096
    _OUTLIER_WINDOW = 8

    def __init__(self, min_gap_s: float, limit: int, *, fold: bool = True,
                 max_gap_s: float = 86400.0) -> None:
        self.min_gap, self.limit, self.fold, self.max_gap = min_gap_s, limit, fold, max_gap_s
        self.scan = PacketScan()
        self.typical: float | None = None
        self._head: list[tuple[float, float | None]] = []
        self._offset = 0.0
        self._prev_end: float | None = None
        self._pending: tuple[float, float | None] | None = None
        self._anchor: dict | None = None  # the clock before the last jump, while it is suspect

    def add(self, pts: float, dur: float | None) -> None:
        if self.scan.first_pts is None:
            self.scan.first_pts = pts
        if self.typical is None:
            self._head.append((pts, dur))
            if len(self._head) >= self._CALIBRATE:
                self._calibrate(exclude_last=False)
            return
        self._feed(pts, dur)

    def finish(self) -> PacketScan:
        if self.typical is None:
            self._calibrate(exclude_last=True)
        self.scan.gaps.sort()
        self.scan.last_end = self._prev_end
        return self.scan

    def _calibrate(self, *, exclude_last: bool) -> None:
        import statistics

        head = self._head[:-1] if exclude_last and len(self._head) >= 2 else self._head
        known = [d for _, d in head if d is not None and d > 0]
        if known and len(known) * 2 >= len(head):
            self.typical = statistics.median(known)
        else:
            deltas = [b[0] - a[0] for a, b in zip(head, head[1:], strict=False) if b[0] > a[0]]
            self.typical = statistics.median(deltas) if deltas else 0.0
        pending, self._head = self._head, []
        for pts, dur in pending:
            self._feed(pts, dur)

    def _feed(self, pts: float, dur: float | None) -> None:
        typical = self.typical or 0.0
        tol = max(0.05, 2 * typical)
        d = dur if dur is not None and dur >= 0 else typical
        if self._anchor is not None:
            a = self._anchor
            back = pts - a["offset"] - a["prev_end"]
            if -tol <= back <= _MAX_PACKET_GAP_S:
                # Back on the clock from before the jump: the jumped packet(s) were strays.
                self._offset, self._prev_end = a["offset"], a["prev_end"]
                self._pending, self._anchor = None, None
                if self.scan.segments:
                    self.scan.segments.pop()
            else:
                a["left"] -= 1
                if a["left"] <= 0:
                    self._anchor = None  # a real discontinuity
        c = pts - self._offset
        jumped = False
        if self._prev_end is not None:
            delta = c - self._prev_end
            if delta < -tol or (self.fold and delta > _MAX_PACKET_GAP_S):
                if self._anchor is None:
                    self._anchor = {"offset": self._offset, "prev_end": self._prev_end,
                                    "left": self._OUTLIER_WINDOW}
                self._offset += delta
                c, jumped = self._prev_end, True
                self.scan.segments.append((pts, self._offset))
            elif delta > self.min_gap:
                self._gap(self._prev_end, c)
        if self._pending is not None:  # long-packet rule, for every packet but the final one
            pc, pd = self._pending
            if pd is not None and typical > 0 and pd - typical > self.min_gap \
                    and (pd <= _MAX_PACKET_GAP_S or not self.fold):
                self._gap(pc + typical, pc + pd)
        self._pending = (c, dur)
        end = c + d
        self._prev_end = end if (self._prev_end is None or jumped) else max(self._prev_end, end)

    def _gap(self, a: float, b: float) -> None:
        b = min(b, a + self.max_gap)
        self.scan.gap_total_s += b - a
        self.scan.gap_count += 1
        if len(self.scan.gaps) < self.limit:
            self.scan.gaps.append((a, b))


def _parse_packet(line: bytes) -> tuple[float, float | None] | None:
    parts = line.strip().split(b",")
    try:
        pts = float(parts[0])
    except (ValueError, IndexError):
        return None
    if pts != pts or pts in (float("inf"), float("-inf")):
        return None
    dur: float | None
    try:
        dur = float(parts[1]) if len(parts) > 1 else None
    except ValueError:
        dur = None
    if dur is not None and (dur != dur or dur < 0 or dur == float("inf")):
        dur = None
    return pts, dur


def scan_packets(path: Path, settings: Settings, abs_index: int, *, min_gap_s: float = 0.1,
                 limit: int = 2000, timeout_s: float | None = None, stop=None,
                 fold: bool = True) -> PacketScan | None:
    """Read a stream's packet timeline (``None`` when the stream has no container index).

    Streamed line by line, so memory stays flat however many packets a file has; the wall
    timeout and RLIMITs bound the cost. ``complete`` is False when the scan was cut short."""
    import threading
    import time

    if abs_index < 0:
        return None
    ffprobe = _tool("ffprobe", settings.ffmpeg_path and str(Path(settings.ffmpeg_path).with_name("ffprobe")))
    argv = [ffprobe, "-v", "error", "-select_streams", str(abs_index),
            "-show_entries", "packet=pts_time,duration_time", "-of", "csv=p=0", *safe_input(path)]
    timeout = timeout_s or min(120.0, settings.decode_timeout_s)
    pre = _rlimit_setter(int(timeout) + _RLIMIT_CPU_PAD_S) if os.name == "posix" else None
    try:
        proc = _popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, preexec_fn=pre)
    except BusyError:
        return PacketScan(complete=False)  # reported as an incomplete scan, the grade goes on
    assert proc.stdout is not None
    expired = threading.Event()
    done = threading.Event()
    limit_at = time.monotonic() + timeout

    def _watch() -> None:
        # Kill on the deadline OR when the caller gives up, even while ffprobe prints nothing.
        while not done.wait(0.2):
            if time.monotonic() >= limit_at or (stop is not None and stop.is_set()):
                expired.set()
                proc.kill()
                return

    watcher = threading.Thread(target=_watch, daemon=True, name="audel-scan-watch")
    watcher.start()
    sc = _GapScanner(min_gap_s, limit, fold=fold, max_gap_s=settings.max_duration_s)
    try:
        for line in iter(lambda: proc.stdout.readline(256), b""):  # type: ignore[union-attr]
            if stop is not None and stop.is_set():
                expired.set()  # the caller gave up on this file: end the scan now
                break
            pkt = _parse_packet(line)
            if pkt is not None:
                sc.add(*pkt)  # read to the end: every gap counts toward the track's length
        result = sc.finish()
    finally:
        done.set()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
    result.complete = not expired.is_set() and proc.returncode == 0
    return result


def channel_layout_arg(layout: str, channels: int) -> str:
    """The -ch_layout to decode and analyse with: the stream's own layout name when ffmpeg knows
    it (probe output, charset-filtered), else a custom layout of N named channels (ffmpeg's
    loudness meter rejects 'unknown' layouts; a remix to a default layout would mislabel)."""
    import re

    n = max(1, int(channels))
    layout = _mask_inner(layout)
    if layout and layout != "unknown" and re.fullmatch(r"[A-Za-z0-9.()+_-]{1,200}", layout):
        known = layout_channels(layout)
        if known is None or len(known) == n:
            return layout
    if n == 1:
        return "mono"
    if n == 2:
        return "stereo"
    return "+".join(f"USR{i}" for i in range(n))


def validate_source(source: str | os.PathLike, settings: Settings, *, allow_local_files: bool | None = None) -> Path:
    """Validate a local media path before it reaches ffmpeg. Returns a resolved Path or raises.

    Defends path traversal (resolve + must be an existing regular file), option injection (reject
    a leading '-' / control chars), and DoS (byte cap before decode).
    """
    if source is None or str(source).strip() == "":
        raise UnsafeSourceError("empty source")
    raw = str(source)
    if raw.startswith("-"):
        # Even though we always pass `-i <path>`, refuse '-'-leading names defensively so a source
        # can never be reparsed as an ffmpeg option.
        raise UnsafeSourceError("source may not begin with '-' (option-injection guard)")
    if any(ord(c) < 32 for c in raw):
        raise UnsafeSourceError("source contains control characters")
    if (allow_local_files if allow_local_files is not None else settings.allow_local_files) is False:
        raise UnsafeSourceError("local file sources are disabled in this context")

    path = Path(raw).expanduser()
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise UnsafeSourceError(f"source not found or unresolvable: {raw}") from e
    if not path.is_file():
        raise UnsafeSourceError(f"source is not a regular file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise UnsafeSourceError("source is empty")
    if size > settings.max_media_bytes:
        raise UnsafeSourceError(
            f"source is {size} bytes, over the {settings.max_media_bytes}-byte cap (decode refused)"
        )
    return path


def probe(path: Path, settings: Settings) -> MediaInfo:
    """ffprobe the (already path-validated) file and enforce duration/sample-rate caps.

    The declared duration/sample-rate are read from container metadata BEFORE any full decode, so a
    file advertising an enormous stream is refused up front (the timeout + RLIMITs backstop a file
    that lies and actually decodes large).
    """
    ffprobe = _tool("ffprobe", settings.ffmpeg_path and str(Path(settings.ffmpeg_path).with_name("ffprobe")))
    argv = [
        ffprobe, "-v", "error", "-print_format", "json",
        "-show_entries",
        "format=duration,format_name,start_time:stream=index,codec_type,codec_name,sample_rate,channels,"
        "channel_layout,start_time,duration:stream_tags=language,title:stream_disposition=attached_pic",
        *safe_input(path),
    ]
    proc = run(argv, timeout_s=min(30.0, settings.decode_timeout_s))
    if proc.returncode != 0:
        raise DecodeError(f"ffprobe failed: {proc.stderr.decode('utf-8', 'replace')[:300]}")
    try:
        meta = json.loads(proc.stdout or b"{}")
    except json.JSONDecodeError as e:
        raise DecodeError("ffprobe returned unparseable metadata") from e

    astreams = [s for s in meta.get("streams", []) if s.get("codec_type") == "audio"]
    has_audio = bool(astreams)
    a = astreams[0] if astreams else {}
    try:
        duration_s = float(meta.get("format", {}).get("duration") or 0.0)
    except (TypeError, ValueError):
        duration_s = 0.0
    fmt = str(meta.get("format", {}).get("format_name") or "")
    format_start: float | None
    try:
        raw_start = meta.get("format", {}).get("start_time")
        format_start = float(raw_start) if raw_start not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        format_start = None
    if format_start is not None and (format_start != format_start
                                     or abs(format_start) == float("inf")):
        format_start = None
    format_start_raw = format_start  # signed: ffmpeg's -ss counts from it (negative after a wrap)
    if format_start is not None and format_start < 0:
        format_start = None             # never a timeline origin
    has_video = any(
        st.get("codec_type") == "video"
        and not (isinstance(st.get("disposition"), dict) and st["disposition"].get("attached_pic"))
        for st in meta.get("streams", []))
    if "mpegts" in fmt and duration_s > settings.max_duration_s:
        # MPEG-TS duration is a PTS estimate: a timestamp splice can inflate it. Treat it as
        # unknown (budgets then assume the maximum) and let the decode cap fail closed instead.
        duration_s = 0.0
    try:
        sample_rate = int(a.get("sample_rate") or 0)
    except (TypeError, ValueError):
        sample_rate = 0
    try:
        channels = int(a.get("channels") or 0)
    except (TypeError, ValueError):
        channels = 0
    codec = str(a.get("codec_name") or "")

    if duration_s > settings.max_duration_s:
        raise UnsafeSourceError(
            f"declared duration {duration_s:.0f}s exceeds the {settings.max_duration_s:.0f}s cap"
        )
    if sample_rate > settings.max_sample_rate:
        raise UnsafeSourceError(f"sample rate {sample_rate} exceeds the {settings.max_sample_rate} cap")
    # A missing / zero declared duration counts as the maximum: it cannot dodge the budgets.
    budget_dur = duration_s if duration_s > 0 else settings.max_duration_s
    if budget_dur * max(1, len(astreams)) > settings.max_total_audio_s:
        raise UnsafeSourceError(
            f"{len(astreams)} audio stream(s) x {budget_dur:.0f}s exceeds the "
            f"{settings.max_total_audio_s:.0f}s total-audio budget")
    total_channels = sum(max(1, _int(st.get("channels"))) for st in astreams)
    if budget_dur * total_channels > settings.max_total_channel_s:
        raise UnsafeSourceError(
            f"{total_channels} channel(s) x {budget_dur:.0f}s exceeds the "
            f"{settings.max_total_channel_s:.0f} channel-second budget")
    if len(astreams) > settings.max_audio_streams:
        raise UnsafeSourceError(
            f"{len(astreams)} audio streams exceeds the {settings.max_audio_streams}-stream cap")
    streams: list[StreamInfo] = []
    for i, st in enumerate(astreams):
        sr, ch = _int(st.get("sample_rate")), _int(st.get("channels"))
        if sr > settings.max_sample_rate:
            raise UnsafeSourceError(f"stream {i} sample rate {sr} exceeds the {settings.max_sample_rate} cap")
        if ch > settings.max_channels:
            raise UnsafeSourceError(f"stream {i} channel count {ch} exceeds the {settings.max_channels} cap")
        tags = st.get("tags") if isinstance(st.get("tags"), dict) else {}
        try:
            start = max(0.0, float(st.get("start_time") or 0.0))
        except (TypeError, ValueError):
            start = 0.0
        try:
            sdur: float | None = float(st.get("duration"))
        except (TypeError, ValueError):
            sdur = None
        if sdur is not None and not (0 < sdur < float("inf")):
            sdur = None
        streams.append(StreamInfo(
            declared_end_s=(start + sdur) if sdur is not None and start == start else None,
            index=i, codec=_tag(st.get("codec_name")), sample_rate=sr, channels=ch,
            layout=_tag(st.get("channel_layout")), language=_tag(tags.get("language")) or None,
            title=_tag(tags.get("title")) or None, abs_index=_int(st.get("index", -1)),
            start_s=start if start == start else 0.0))
    if channels > settings.max_channels:
        raise UnsafeSourceError(f"channel count {channels} exceeds the {settings.max_channels} cap")
    shortfall = (container_shortfall_s(path, settings.max_duration_s)
                 if fmt.split(",")[0] in ("wav", "w64", "aiff", "caf") else 0.0)
    return MediaInfo(duration_s=duration_s, sample_rate=sample_rate, channels=channels,
                     codec=codec, has_audio=has_audio, streams=tuple(streams),
                     format_start=format_start, format_start_raw=format_start_raw,
                     has_video=has_video, container_shortfall_s=shortfall,
                     estimated_durations=fmt.split(",")[0] in ("mpegts", "mpeg", "mpegvideo"),
                     packets_declare_end=fmt.split(",")[0] in ("mpegts", "mpeg", "mpegvideo",
                                                               "asf"))


_W64_RIFF = bytes.fromhex("726966662e91cf11a5d628db04c10000")
_W64_DATA = bytes.fromhex("64617461f3acd3118cd100c04f8edb8a")
_W64_FMT = bytes.fromhex("666d7420f3acd3118cd100c04f8edb8a")
_MAX_CHUNKS = 4096          # header walk bound (chunk headers only, never the audio)
_UNKNOWN_32 = 0x7F000000    # streaming writers' placeholders (0x7FFF0000, 0x80000000, 0xFFFFFFFF)


def container_shortfall_s(path: Path, max_s: float) -> float:
    """Seconds of audio the header DECLARES but the file does not contain (a transfer cut short).

    ffprobe sizes these formats from the bytes present, so a truncated file otherwise looks
    complete. Covers RIFF/RF64/BW64 WAV, Sony W64, AIFF/AIFC and CAF. A streamed file that
    declares an unknown length (0, or a placeholder) is not judged. Bounded: chunk headers only,
    at most ``_MAX_CHUNKS``, and the result is clamped to ``max_s``."""
    import struct

    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(16)
            if head[:4] in (b"RIFF", b"RF64", b"BW64") and head[8:12] == b"WAVE":
                got = _riff(fh, head[:4] != b"RIFF", size)
            elif head[:16] == _W64_RIFF:
                got = _w64(fh, size)
            elif head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
                got = _aiff(fh, size)
            elif head[:4] == b"caff":
                got = _caf(fh, size)
            else:
                return 0.0
    except (OSError, struct.error, ValueError, OverflowError):
        return 0.0
    if got is None:
        return 0.0
    declared, present, byte_rate = got
    if declared <= 0 or byte_rate <= 0 or present >= declared:
        return 0.0
    return min(max_s, (declared - present) / byte_rate)


def _riff(fh, sixty_four: bool, size: int):
    import struct

    ds64 = None
    byte_rate = 0
    pos = 12
    for _ in range(_MAX_CHUNKS):
        fh.seek(pos)
        hdr = fh.read(8)
        if len(hdr) < 8:
            return None
        cid, csz = hdr[:4], struct.unpack("<I", hdr[4:])[0]
        if cid == b"ds64":
            body = fh.read(min(csz, 28))
            if len(body) >= 16:
                ds64 = struct.unpack("<Q", body[8:16])[0]
        elif cid == b"fmt ":
            body = fh.read(min(csz, 40))
            if len(body) >= 12:
                tag = struct.unpack("<H", body[:2])[0]
                if tag == 0xFFFE and len(body) >= 26:
                    tag = struct.unpack("<H", body[24:26])[0]  # extensible: the subformat
                # Only constant-rate formats are judged (PCM, float, A-law, mu-law): for ADPCM or
                # MP3-in-WAV the byte rate is nominal, so the shortfall can't be sized.
                byte_rate = struct.unpack("<I", body[8:12])[0] if tag in (1, 3, 6, 7) else 0
        elif cid == b"data":
            if sixty_four and csz == 0xFFFFFFFF:
                declared = ds64 or 0
                if declared >= 1 << 62:
                    return None
            else:
                declared = csz
                if declared >= _UNKNOWN_32:
                    return None
            return declared, max(0, size - (pos + 8)), byte_rate
        pos += 8 + csz + (csz & 1)
        if pos >= size:
            return None
    return None


def _w64(fh, size: int):
    import struct

    byte_rate = 0
    pos = 40  # riff GUID(16) + size(8) + wave GUID(16)
    for _ in range(_MAX_CHUNKS):
        fh.seek(pos)
        hdr = fh.read(24)
        if len(hdr) < 24:
            return None
        guid, csz = hdr[:16], struct.unpack("<Q", hdr[16:])[0]
        if guid == _W64_FMT:
            body = fh.read(16)
            if len(body) >= 12:
                byte_rate = struct.unpack("<I", body[8:12])[0]
        elif guid == _W64_DATA:
            if csz <= 24 or csz >= 1 << 62:
                return None
            return csz - 24, max(0, size - (pos + 24)), byte_rate
        if csz < 24:
            return None
        pos += csz + ((8 - csz % 8) % 8)
        if pos >= size:
            return None
    return None


def _ext80(b: bytes) -> float:
    """IEEE 754 80-bit extended (AIFF sample rate)."""
    import struct

    exp, mant = struct.unpack(">HQ", b[:10])
    sign = -1 if exp & 0x8000 else 1
    exp &= 0x7FFF
    if exp == 0 or exp == 0x7FFF:
        return 0.0
    return sign * mant * 2.0 ** (exp - 16383 - 63)


_AIFC_PCM = {b"NONE", b"sowt", b"twos", b"fl32", b"FL32", b"fl64", b"FL64", b"in24", b"in32",
             b"raw ", b"alaw", b"ALAW", b"ulaw", b"ULAW"}
_AIFC_8BIT = {b"alaw", b"ALAW", b"ulaw", b"ULAW"}  # COMM says 16 bits; stored as one byte


def _aiff(fh, size: int):
    import struct

    frames = ch = bits = 0
    rate = 0.0
    pcm = True
    ssnd_data = None
    pos = 12
    for _ in range(_MAX_CHUNKS):
        fh.seek(pos)
        hdr = fh.read(8)
        if len(hdr) < 8:
            break
        cid, csz = hdr[:4], struct.unpack(">I", hdr[4:])[0]
        if cid == b"COMM":
            body = fh.read(min(csz, 22))
            if len(body) >= 18:
                ch, frames, bits = struct.unpack(">hIh", body[:8])
                rate = _ext80(body[8:18])
                if len(body) >= 22:
                    pcm = body[18:22] in _AIFC_PCM
                    if body[18:22] in _AIFC_8BIT:
                        bits = 8
        elif cid == b"SSND":
            off = fh.read(4)
            ssnd_data = pos + 16 + (struct.unpack(">I", off)[0] if len(off) == 4 else 0)
        pos += 8 + csz + (csz & 1)
        if pos >= size:
            break
    if not pcm or ssnd_data is None or frames <= 0 or ch <= 0 or bits <= 0 or rate <= 0:
        return None
    bpf = ch * ((bits + 7) // 8)
    return frames * bpf, max(0, size - ssnd_data), int(bpf * rate)


def _caf(fh, size: int):
    import struct

    rate = 0.0
    bpp = fpp = 0
    pos = 8
    for _ in range(_MAX_CHUNKS):
        fh.seek(pos)
        hdr = fh.read(12)
        if len(hdr) < 12:
            return None
        cid, csz = hdr[:4], struct.unpack(">q", hdr[4:])[0]
        if cid == b"desc":
            body = fh.read(32)
            if len(body) >= 24:
                rate = struct.unpack(">d", body[:8])[0]
                bpp, fpp = struct.unpack(">II", body[16:24])
        elif cid == b"data":
            if csz < 4 or bpp <= 0 or fpp <= 0 or not (rate > 0):
                return None  # -1 = streamed / unknown length; VBR codecs are not judged
            return csz - 4, max(0, size - (pos + 16)), int(bpp / fpp * rate)
        if csz < 0:
            return None
        pos += 12 + csz
        if pos >= size:
            return None
    return None


def _int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


_TAG_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-()/:+")


def _tag(v) -> str:
    """Container metadata is attacker-controlled: keep it short and printable before it reaches a
    report, a log line or an HTML page."""
    s = str(v or "")[:64]
    return "".join(c for c in s if c in _TAG_OK)


def probe_streams(path: Path, settings: Settings) -> dict:
    """Per-stream durations/start times (audio + video) for A/V desync analysis. Best-effort."""
    ffprobe = _tool("ffprobe", settings.ffmpeg_path and str(Path(settings.ffmpeg_path).with_name("ffprobe")))
    argv = [ffprobe, "-v", "error", "-print_format", "json",
            "-show_entries", "stream=codec_type,duration,start_time", *safe_input(path)]
    proc = run(argv, timeout_s=min(30.0, settings.decode_timeout_s))
    out: dict = {"audio": None, "video": None}
    if proc.returncode != 0:
        return out
    try:
        meta = json.loads(proc.stdout or b"{}")
    except json.JSONDecodeError:
        return out
    for s in meta.get("streams", []):
        kind = s.get("codec_type")
        if kind in ("audio", "video") and out.get(kind) is None:
            def _f(v):
                try:
                    return float(v)
                except (TypeError, ValueError):
                    return None
            out[kind] = {"duration": _f(s.get("duration")), "start": _f(s.get("start_time"))}
    return out


def decode_to_wav(path: Path, settings: Settings, *, sample_rate: int = 16000,
                  stream: int = 0) -> Path:
    """Decode a validated file to a DURATION-BOUNDED 16 kHz mono WAV in a temp file (caller deletes).

    This is what the ASR path transcribes — never the raw input — so whisper can never be made to
    process more than ``max_duration_s`` of audio even if the container lies about its length.
    """
    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    fd, name = tempfile.mkstemp(suffix=".wav", prefix="audel-asr-", dir=_tmp_dir(settings))
    os.close(fd)
    out = Path(name)
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-reinit_filter", "0",
            *safe_input(path),
            "-map", f"0:a:{int(stream)}?", "-af", "asetpts=N/SR/TB",
            "-t", str(settings.max_duration_s),
            "-ar", str(sample_rate), "-ac", "1", "-f", "wav", "-y", str(out)]
    try:
        proc = run(argv, timeout_s=pass_timeout(settings, settings.max_duration_s))
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    if proc.returncode != 0 or out.stat().st_size == 0:
        out.unlink(missing_ok=True)
        raise DecodeError(f"could not decode audio for ASR: {proc.stderr.decode('utf-8', 'replace')[-200:]}")
    return out


def excerpt_wav(path: Path, settings: Settings, *, start_s: float, dur_s: float,
                stream: int = 0, sample_rate: int = 16000) -> Path:
    """A short, bounded 16 kHz mono WAV excerpt (caller deletes) — what an audio-capable model
    hears. Duration is clamped to 60 s whatever the caller asks for."""
    ffmpeg = _tool("ffmpeg", settings.ffmpeg_path)
    dur = max(0.5, min(60.0, float(dur_s)))
    fd, name = tempfile.mkstemp(suffix=".wav", prefix="audel-excerpt-", dir=_tmp_dir(settings))
    os.close(fd)
    out = Path(name)
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-reinit_filter", "0",
            "-ss", f"{max(0.0, start_s):.3f}", *safe_input(path), "-map", f"0:a:{int(stream)}?", "-t", f"{dur:.3f}",
            "-ar", str(sample_rate), "-ac", "1", "-f", "wav", "-y", str(out)]
    try:
        proc = run(argv, timeout_s=min(60.0, settings.decode_timeout_s))
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    if proc.returncode != 0 or out.stat().st_size == 0:
        out.unlink(missing_ok=True)
        raise DecodeError("could not cut an audio excerpt")
    return out


def _tmp_dir(settings: Settings) -> str:
    """Temp files go under the private workspace (0700, reaped by ``audel purge``)."""
    from .workspace import Workspace

    return str(Workspace(settings).tmp)
