"""Phase 7 security: the streaming monitor is bounded by construction, applies backpressure, and
validates untrusted PCM (dtype/shape/finiteness/alignment) — memory stays O(window) for any input."""

from __future__ import annotations

import numpy as np
import pytest

from audel.config import Settings
from audel.core.stream import StreamMonitor
from audel.errors import UnsafeSourceError

SR = 16000


def _mon(**settings_kw) -> StreamMonitor:
    return StreamMonitor(sample_rate=SR, settings=Settings(cache_dir="/tmp", **settings_kw))


# ---- input validation (untrusted PCM) -----------------------------------------

def test_sample_rate_and_channels_capped():
    with pytest.raises(UnsafeSourceError):
        StreamMonitor(sample_rate=100)                       # below floor
    with pytest.raises(UnsafeSourceError):
        StreamMonitor(sample_rate=10_000_000)                # above max_sample_rate
    with pytest.raises(UnsafeSourceError):
        StreamMonitor(sample_rate=SR, channels=9999)         # above max_channels


def test_bad_dtype_refused():
    with pytest.raises(UnsafeSourceError):
        _mon().feed(np.arange(100, dtype=np.int32))          # not float/int16


def test_non_finite_samples_refused():
    bad = np.array([0.1, np.nan, np.inf, 0.2], dtype=np.float32)
    with pytest.raises(UnsafeSourceError):
        _mon().feed(bad)


def test_unaligned_byte_chunk_refused():
    with pytest.raises(UnsafeSourceError):
        _mon().feed(b"\x01\x02\x03")                         # odd length -> not int16-aligned


def test_higher_dimensional_input_refused():
    with pytest.raises(UnsafeSourceError):
        _mon().feed(np.zeros((4, 4, 4), dtype=np.float32))


# ---- backpressure + bounded memory --------------------------------------------

def test_oversized_single_chunk_refused():
    mon = _mon(max_stream_chunk_s=0.5)
    too_big = np.zeros(int(SR * 0.6), dtype=np.float32)      # 0.6s > 0.5s cap
    with pytest.raises(UnsafeSourceError):
        mon.feed(too_big)


def test_window_buffer_is_bounded_regardless_of_input_length():
    # Feed far more than the window; internal buffer must stay clamped to the ring's maxlen.
    mon = _mon(stream_window_s=1.0, max_stream_chunk_s=2.0)
    cap = int(1.0 * SR)
    for _ in range(40):                                      # 40 * 0.5s = 20s of audio
        mon.feed(np.full(int(SR * 0.5), 0.2, dtype=np.float32))
    assert len(mon._window) == cap                           # O(window), not O(stream)


def test_dropout_span_list_is_capped():
    mon = _mon(max_stream_spans=2, stream_dropout_min_s=0.2)
    # 5 interior silent gaps separated by tone — only 2 should be recorded, then truncation noted.
    for _ in range(5):
        mon.feed(np.full(int(SR * 0.1), 0.3, dtype=np.float32))   # tone
        mon.feed(np.zeros(int(SR * 0.3), dtype=np.float32))       # gap >= 0.2s
    mon.feed(np.full(int(SR * 0.1), 0.3, dtype=np.float32))
    assert len(mon._spans) == 2 and mon._spans_truncated
    report = mon.finalize()
    assert any("capped" in i.message for i in report.issues)      # bound is surfaced, not silent


def test_out_of_range_floats_are_clamped_not_crashing():
    mon = _mon()
    update = mon.feed(np.array([5.0, -7.0, 0.5], dtype=np.float32))  # absurd amplitudes
    assert update.clipping and np.isfinite(update.peak_dbfs)         # clamped to full-scale, graded


def test_feed_after_finalize_refused():
    mon = _mon()
    mon.feed(np.full(SR, 0.2, dtype=np.float32))
    mon.finalize()
    with pytest.raises(UnsafeSourceError):
        mon.feed(np.zeros(10, dtype=np.float32))
