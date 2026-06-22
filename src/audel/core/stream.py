"""Realtime streaming verification (Phase 7) — grade a LIVE audio stream as it arrives.

For a finished file you call :func:`audel.check`; for a live voice-agent / call / TTS stream you
feed PCM chunks to a :class:`StreamMonitor` and it grades incrementally — flagging dead air,
clipping, and mid-stream dropouts in near-real-time, then distilling a final time-grounded
:class:`~audel.models.Report` on :meth:`StreamMonitor.finalize`.

Dependency-light: pure numpy frame math (no ffmpeg per chunk). **Bounded by construction** — only
running scalars + a fixed-length rolling window are kept, never the whole stream; a single
oversized ``feed`` is refused (backpressure), and the recorded-span list is capped. So memory is
O(window), independent of how much audio is pushed.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

import numpy as np

from ..config import Settings, load_settings
from ..errors import UnsafeSourceError
from ..models import (
    Confidence,
    Issue,
    IssueKind,
    IssueSource,
    Report,
    Severity,
    Span,
    Verdict,
    verdict_from_issues,
)

_CLIP_FLOOR = 0.997  # |sample| at/above this (full-scale) counts as clipped


@dataclass
class StreamUpdate:
    """The incremental reading returned by each :meth:`StreamMonitor.feed`."""

    t_ms: int                 # cumulative stream time at the end of this chunk
    rms_dbfs: float           # RMS over the rolling window (−inf when silent)
    peak_dbfs: float          # peak over this chunk
    clipping: bool            # this chunk hit full-scale
    silent: bool              # this chunk is below the silence floor
    verdict: Verdict          # running verdict so far


@dataclass
class _Span:
    start_ms: int
    end_ms: int


class StreamMonitor:
    """Incrementally grade a mono/interleaved PCM stream. Feed float32 [-1,1], int16, or raw
    int16-LE ``bytes``; multi-channel input is downmixed to mono. All buffers are bounded."""

    def __init__(self, *, sample_rate: int, channels: int = 1, settings: Settings | None = None):
        self.settings = settings or load_settings()
        if not (8000 <= int(sample_rate) <= self.settings.max_sample_rate):
            raise UnsafeSourceError(
                f"sample_rate {sample_rate} outside [8000, {self.settings.max_sample_rate}]")
        if not (1 <= int(channels) <= self.settings.max_channels):
            raise UnsafeSourceError(f"channels {channels} outside [1, {self.settings.max_channels}]")
        self.sample_rate = int(sample_rate)
        self.channels = int(channels)
        self._max_chunk_frames = int(self.settings.max_stream_chunk_s * self.sample_rate)
        win = max(1, int(self.settings.stream_window_s * self.sample_rate))
        # rolling window of recent samples (fixed-length ring → O(window) memory)
        self._window: deque[float] = deque(maxlen=win)

        # running cumulative stats (scalars — never grow with stream length)
        self._frames = 0
        self._clipped = 0
        self._sumsq = 0.0
        self._silent_run_frames = 0
        self._cur_silent_start: int | None = None
        self._spans: list[_Span] = []           # capped at settings.max_stream_spans
        self._spans_truncated = False
        self._closed = False

    # ---- ingest ---------------------------------------------------------------

    def _to_mono_float(self, pcm) -> np.ndarray:
        if isinstance(pcm, (bytes, bytearray, memoryview)):
            buf = bytes(pcm)
            if len(buf) % 2 != 0:
                raise UnsafeSourceError("int16-LE byte chunk is not 2-byte aligned")
            arr = np.frombuffer(buf, dtype="<i2").astype(np.float32) / 32768.0
        else:
            arr = np.asarray(pcm)
            if arr.dtype == np.int16:
                arr = arr.astype(np.float32) / 32768.0
            elif np.issubdtype(arr.dtype, np.floating):
                arr = arr.astype(np.float32)
            else:
                raise UnsafeSourceError(f"unsupported PCM dtype {arr.dtype} (want float[-1,1]/int16)")
        if arr.ndim == 2:                         # (frames, channels) → mono
            arr = arr.mean(axis=1)
        elif arr.ndim == 1 and self.channels > 1 and arr.size % self.channels == 0:
            arr = arr.reshape(-1, self.channels).mean(axis=1)  # interleaved → mono
        elif arr.ndim != 1:
            raise UnsafeSourceError(f"PCM must be 1-D or 2-D, got {arr.ndim}-D")
        if not np.all(np.isfinite(arr)):          # NaN/Inf would poison every downstream stat
            raise UnsafeSourceError("PCM contains non-finite samples")
        return arr

    def feed(self, pcm) -> StreamUpdate:
        """Ingest one chunk, update running stats, and return the incremental reading."""
        if self._closed:
            raise UnsafeSourceError("monitor is finalized; create a new StreamMonitor")
        mono = self._to_mono_float(pcm)
        if mono.size > self._max_chunk_frames:    # backpressure: refuse a too-large single feed
            raise UnsafeSourceError(
                f"chunk has {mono.size} frames, over the {self._max_chunk_frames} cap "
                f"({self.settings.max_stream_chunk_s}s) — push smaller chunks")
        if mono.size == 0:
            return self._reading(peak=0.0, clip=False)

        np.clip(mono, -1.0, 1.0, out=mono)        # defang out-of-range floats before stats
        self._window.extend(mono.tolist())
        self._frames += mono.size
        self._sumsq += float(np.dot(mono, mono))
        self._clipped += int(np.count_nonzero(np.abs(mono) >= _CLIP_FLOOR))
        peak = float(np.max(np.abs(mono)))

        chunk_rms = math.sqrt(float(np.dot(mono, mono)) / mono.size)
        silent = self._dbfs(chunk_rms) <= self.settings.silence_dbfs
        self._track_silence(silent, mono.size)
        return self._reading(peak=peak, clip=bool(self._clipped and peak >= _CLIP_FLOOR))

    # ---- silence / dropout tracking (bounded) ---------------------------------

    def _track_silence(self, silent: bool, n: int) -> None:
        if silent:
            if self._cur_silent_start is None:
                self._cur_silent_start = self._frames - n
            self._silent_run_frames += n
        else:
            self._close_silent_span()

    def _close_silent_span(self) -> None:
        if self._cur_silent_start is None:
            return
        start_ms = int(self._cur_silent_start * 1000 / self.sample_rate)
        end_ms = int(self._frames * 1000 / self.sample_rate)
        if (end_ms - start_ms) >= self.settings.stream_dropout_min_s * 1000:
            if len(self._spans) < self.settings.max_stream_spans:
                self._spans.append(_Span(start_ms, end_ms))
            else:
                self._spans_truncated = True      # bound memory; record that we stopped logging
        self._cur_silent_start = None

    # ---- readings / status ----------------------------------------------------

    @staticmethod
    def _dbfs(amp: float) -> float:
        return 20.0 * math.log10(amp) if amp > 0 else -math.inf

    def _window_rms_dbfs(self) -> float:
        if not self._window:
            return -math.inf
        w = np.fromiter(self._window, dtype=np.float32)
        return self._dbfs(math.sqrt(float(np.dot(w, w)) / w.size))

    def _running_verdict(self) -> Verdict:
        if self._frames == 0:
            return Verdict.WARN
        if self._clip_ratio() > 0.001:
            return Verdict.FAIL
        if self._all_silent():
            return Verdict.FAIL
        return Verdict.PASS

    def _reading(self, *, peak: float, clip: bool) -> StreamUpdate:
        return StreamUpdate(
            t_ms=self.total_ms, rms_dbfs=self._window_rms_dbfs(), peak_dbfs=self._dbfs(peak),
            clipping=clip, silent=self._dbfs(peak) <= self.settings.silence_dbfs,
            verdict=self._running_verdict())

    @property
    def total_ms(self) -> int:
        return int(self._frames * 1000 / self.sample_rate)

    def _clip_ratio(self) -> float:
        return self._clipped / self._frames if self._frames else 0.0

    def _all_silent(self) -> bool:
        return self._frames > 0 and self._silent_run_frames >= self._frames

    def status(self) -> dict:
        """`hear_status` metrics — a JSON snapshot for a live dashboard. All values are bounded."""
        return {
            "total_ms": self.total_ms,
            "buffered_ms": int(len(self._window) * 1000 / self.sample_rate),
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "clipped_samples": self._clipped,
            "clip_ratio": round(self._clip_ratio(), 6),
            "dropouts": len(self._spans),
            "dropouts_truncated": self._spans_truncated,
            "verdict": self._running_verdict().value,
        }

    # ---- finalize -------------------------------------------------------------

    def finalize(self) -> Report:
        """Close the stream and distill a final, time-grounded Report from the running stats."""
        self._close_silent_span()
        self._closed = True
        issues: list[Issue] = []
        dur_ms = self.total_ms

        if self._frames == 0:
            issues.append(Issue.make(IssueKind.MISSING_AUDIO, Severity.CRITICAL,
                                     "stream carried no audio", source=IssueSource.DSP))
        elif self._all_silent():
            issues.append(Issue.make(IssueKind.SILENCE, Severity.CRITICAL,
                                     "stream was silent for its entire duration",
                                     span=Span(start_ms=0, end_ms=dur_ms), source=IssueSource.DSP))
        else:
            ratio = self._clip_ratio()
            if ratio > 0.001:
                issues.append(Issue.make(
                    IssueKind.CLIPPING, Severity.ERROR,
                    f"{ratio*100:.2f}% of samples hit full-scale (clipping)",
                    source=IssueSource.DSP, detail={"clip_ratio": round(ratio, 6)}))
            for sp in self._spans:                # interior dropouts (edge silence ignored by min)
                if sp.start_ms <= 0 or sp.end_ms >= dur_ms:
                    continue
                issues.append(Issue.make(
                    IssueKind.DROPOUT, Severity.ERROR,
                    f"audio dropout: {sp.end_ms - sp.start_ms}ms of silence mid-stream",
                    span=Span(start_ms=sp.start_ms, end_ms=sp.end_ms), source=IssueSource.DSP,
                    confidence=Confidence.MEDIUM))
            if self._spans_truncated:
                issues.append(Issue.make(
                    IssueKind.OTHER, Severity.INFO,
                    f"dropout logging capped at {self.settings.max_stream_spans} spans "
                    "(stream had more; memory bounded)", source=IssueSource.DSP))

        verdict = verdict_from_issues(issues)  # type: ignore[arg-type]
        summary = ("stream graded ok" if verdict == Verdict.PASS
                   else f"{len(issues)} stream issue(s): "
                        + ", ".join(sorted({i.kind.value for i in issues})))
        return Report(verdict=verdict, summary=summary, issues=issues,  # type: ignore[arg-type]
                      backend="stream-dsp", sample_rate=self.sample_rate, channels=self.channels,
                      duration_ms=dur_ms, capabilities=[IssueKind.SILENCE, IssueKind.CLIPPING,
                                                        IssueKind.DROPOUT, IssueKind.MISSING_AUDIO])
