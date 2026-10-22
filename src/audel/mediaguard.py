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
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .errors import DecodeError, MissingDependencyError, UnsafeSourceError
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


def layout_channels(layout: str) -> list[str] | None:
    """Channel names of a layout: FFmpeg's table, or a ``FL+FR+LFE+...`` custom layout."""
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


def run(argv: list[str], *, timeout_s: float, max_stdout_bytes: int | None = None) -> subprocess.CompletedProcess:
    """Run an ffmpeg/ffprobe argv with no shell, hard timeout, and child resource limits.

    ``argv[0]`` must be an absolute tool path (from :func:`_tool`). Output is captured; stdout is
    truncated to ``max_stdout_bytes`` when given (bounds raw-PCM decode buffers).
    """
    pre = _rlimit_setter(int(timeout_s) + _RLIMIT_CPU_PAD_S) if os.name == "posix" else None
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
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
                 stats: dict | None = None) -> str:
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
    decode = [ffmpeg, "-nostdin", "-hide_banner", "-v", "error", "-threads", "1",
              "-reinit_filter", "0", *(pre_input or []), *safe_input(path),
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
    p1 = subprocess.Popen(decode, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, preexec_fn=pre)
    try:
        p2 = subprocess.Popen(analyse, stdin=p1.stdout, stdout=subprocess.DEVNULL,
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
        # The decoder runs at -v error: every line it printed is a decoding problem (corrupt or
        # missing data), even when it still exits 0.
        stats["decode_errors"] = err1.lines
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


def channel_layout_arg(layout: str, channels: int) -> str:
    """The -ch_layout to decode and analyse with: the stream's own layout name when ffmpeg knows
    it (probe output, charset-filtered), else a custom layout of N named channels (ffmpeg's
    loudness meter rejects 'unknown' layouts; a remix to a default layout would mislabel)."""
    import re

    n = max(1, int(channels))
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
        "format=duration:stream=codec_type,codec_name,sample_rate,channels,channel_layout"
        ":stream_tags=language,title",
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
        streams.append(StreamInfo(
            index=i, codec=_tag(st.get("codec_name")), sample_rate=sr, channels=ch,
            layout=_tag(st.get("channel_layout")), language=_tag(tags.get("language")) or None,
            title=_tag(tags.get("title")) or None))
    if channels > settings.max_channels:
        raise UnsafeSourceError(f"channel count {channels} exceeds the {settings.max_channels} cap")
    return MediaInfo(duration_s=duration_s, sample_rate=sample_rate, channels=channels,
                     codec=codec, has_audio=has_audio, streams=tuple(streams))


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
