"""Phase 1 deterministic grading — fixtures grade to the right time-grounded verdicts."""

from __future__ import annotations

import asyncio

from audel import IssueKind, Verdict
from audel.core import check, render


def _check(p):
    return asyncio.run(check(str(p)))


def test_good_clip_passes(media):
    r = _check(media["good"])
    assert r.verdict == Verdict.PASS, [i.message for i in r.issues]
    assert r.duration_ms and r.channels == 1 and r.backend == "dsp"


def test_silent_clip_fails_with_silence(media):
    r = _check(media["silent"])
    assert r.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.SILENCE for i in r.issues)
    sil = next(i for i in r.issues if i.kind == IssueKind.SILENCE)
    assert sil.span is not None and sil.span.end_ms >= sil.span.start_ms


def test_clipping_clip_fails_with_clipping(media):
    r = _check(media["clipping"])
    assert r.verdict == Verdict.FAIL
    clip = next(i for i in r.issues if i.kind == IssueKind.CLIPPING)
    assert clip.span is not None and "dBTP" in clip.message


def test_truncated_clip_warns(media):
    r = _check(media["truncated"])
    assert any(i.kind == IssueKind.TRUNCATION for i in r.issues)


def test_missing_audio_is_critical(media):
    r = _check(media["no_audio"])
    assert r.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.MISSING_AUDIO for i in r.issues)


def test_render_returns_signals(media):
    rr = asyncio.run(render(str(media["good"])))
    assert rr.has_audio and rr.duration_ms
    assert rr.integrated_lufs is not None and rr.true_peak_dbtp is not None
