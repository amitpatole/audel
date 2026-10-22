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
}


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
        labels = CHANNEL_LABELS.get(layout)
        if labels and len(labels) == self.channels:
            return list(labels)
        return [f"ch{i + 1}" for i in range(self.channels)]


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
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_s,
            preexec_fn=_rlimit_setter(int(timeout_s) + _RLIMIT_CPU_PAD_S) if os.name == "posix" else None,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise UnsafeSourceError(f"decode exceeded {timeout_s}s timeout (possible resource bomb)") from e
    if max_stdout_bytes is not None and len(proc.stdout) > max_stdout_bytes:
        proc = subprocess.CompletedProcess(proc.args, proc.returncode,
                                           proc.stdout[:max_stdout_bytes], proc.stderr)
    return proc


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
        "-i", str(path),
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
            "-show_entries", "stream=codec_type,duration,start_time", "-i", str(path)]
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
    fd, name = tempfile.mkstemp(suffix=".wav", prefix="audel-asr-")
    os.close(fd)
    out = Path(name)
    argv = [ffmpeg, "-nostdin", "-hide_banner", "-threads", "1", "-i", str(path),
            "-map", f"0:a:{int(stream)}?", "-t", str(settings.max_duration_s),
            "-ar", str(sample_rate), "-ac", "1", "-f", "wav", "-y", str(out)]
    proc = run(argv, timeout_s=settings.decode_timeout_s)
    if proc.returncode != 0 or out.stat().st_size == 0:
        out.unlink(missing_ok=True)
        raise DecodeError(f"could not decode audio for ASR: {proc.stderr.decode('utf-8', 'replace')[-200:]}")
    return out
