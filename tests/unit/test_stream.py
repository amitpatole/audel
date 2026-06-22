"""Phase 7 — realtime StreamMonitor grades a live PCM stream incrementally and finalizes a Report.

Pure numpy fixtures (no ffmpeg): the monitor's math is independent of the decode path."""

from __future__ import annotations

import numpy as np

from audel import IssueKind, Verdict
from audel.config import Settings
from audel.core.stream import StreamMonitor

SR = 16000


def _sine(seconds: float, *, freq: float = 440.0, amp: float = 0.3) -> np.ndarray:
    t = np.arange(int(SR * seconds)) / SR
    return (amp * np.sin(2 * np.pi * freq * t)).astype(np.float32)


def _feed_chunks(mon: StreamMonitor, sig: np.ndarray, chunk_s: float = 0.05):
    n = int(SR * chunk_s)
    last = None
    for i in range(0, len(sig), n):
        last = mon.feed(sig[i:i + n])
    return last


def _mon(**kw) -> StreamMonitor:
    return StreamMonitor(sample_rate=SR, channels=1, settings=Settings(cache_dir=kw.pop("cd", None) or "/tmp", **kw))


def test_good_stream_passes():
    mon = StreamMonitor(sample_rate=SR)
    update = _feed_chunks(mon, _sine(1.0))
    assert update.verdict == Verdict.PASS and not update.silent
    report = mon.finalize()
    assert report.verdict == Verdict.PASS and report.duration_ms >= 990


def test_fully_silent_stream_fails_with_silence():
    mon = StreamMonitor(sample_rate=SR)
    _feed_chunks(mon, np.zeros(SR, dtype=np.float32))
    report = mon.finalize()
    assert report.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.SILENCE for i in report.issues)


def test_clipping_stream_fails():
    mon = StreamMonitor(sample_rate=SR)
    clipped = np.ones(SR, dtype=np.float32)  # full-scale = clipping
    update = _feed_chunks(mon, clipped)
    assert update.clipping and update.verdict == Verdict.FAIL
    report = mon.finalize()
    assert any(i.kind == IssueKind.CLIPPING for i in report.issues)


def test_interior_dropout_flagged():
    sig = np.concatenate([_sine(0.5), np.zeros(int(SR * 0.3), np.float32), _sine(0.5)])
    mon = StreamMonitor(sample_rate=SR)
    _feed_chunks(mon, sig, chunk_s=0.05)
    report = mon.finalize()
    drop = [i for i in report.issues if i.kind == IssueKind.DROPOUT]
    assert drop and drop[0].span is not None
    assert 400 <= drop[0].span.start_ms <= 600  # gap began ~0.5s in


def test_no_audio_fed_is_missing_audio():
    report = StreamMonitor(sample_rate=SR).finalize()
    assert report.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.MISSING_AUDIO for i in report.issues)


def test_int16_and_bytes_inputs_match_float():
    sig = _sine(0.5)
    as_i16 = (sig * 32768).astype(np.int16)
    m_float, m_i16, m_bytes = StreamMonitor(sample_rate=SR), StreamMonitor(sample_rate=SR), StreamMonitor(sample_rate=SR)
    m_float.feed(sig)
    m_i16.feed(as_i16)
    m_bytes.feed(as_i16.tobytes())
    # all three ingest the same audio -> same verdict and (near) same duration
    assert m_float.finalize().verdict == m_i16.finalize().verdict == m_bytes.finalize().verdict
    assert m_i16.total_ms == m_bytes.total_ms


def test_status_metrics_are_bounded_and_sane():
    mon = StreamMonitor(sample_rate=SR)
    _feed_chunks(mon, _sine(2.0))
    st = mon.status()
    assert st["total_ms"] >= 1990 and st["sample_rate"] == SR
    assert st["buffered_ms"] <= int(Settings(cache_dir="/tmp").stream_window_s * 1000) + 1
    assert st["verdict"] == "pass" and st["dropouts"] == 0


def test_multichannel_downmix():
    stereo = np.stack([_sine(0.5), _sine(0.5, freq=660)], axis=1)  # (frames, 2)
    mon = StreamMonitor(sample_rate=SR, channels=2)
    mon.feed(stereo)
    assert mon.finalize().verdict == Verdict.PASS
