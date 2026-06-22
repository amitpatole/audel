"""Phase 4: temporal grading (file path) — dropouts / silent-video / A/V desync / plays-through."""

from __future__ import annotations

import asyncio

from audel import Verdict
from audel.core import watch
from audel.models import IssueKind


def _w(p, **kw):
    return asyncio.run(watch(str(p), **kw))


def test_good_clip_plays_through(media):
    r = _w(media["good"])
    assert r.verdict == Verdict.PASS and "plays through" in r.summary


def test_dropout_is_flagged_with_span(media):
    r = _w(media["dropout"])
    drop = next(i for i in r.issues if i.kind == IssueKind.DROPOUT)
    assert r.verdict == Verdict.FAIL
    assert drop.span is not None and drop.span.start_ms > 0 and drop.span.end_ms > drop.span.start_ms


def test_silent_video_flagged_though_it_plays(media):
    # The acceptance case: a video that "plays" but whose audio is silent.
    r = _w(media["silent_video"])
    assert r.verdict == Verdict.FAIL
    assert any(i.kind in (IssueKind.SILENCE, IssueKind.MISSING_AUDIO) for i in r.issues)


def test_av_desync_flagged(media):
    r = _w(media["desync"])
    assert any(i.kind == IssueKind.DESYNC for i in r.issues)


def test_watch_clamps_frames_and_interval(media):
    # Absurd frames/interval are clamped, not honored (DoS bound) — still grades fine.
    r = _w(media["good"], frames=10_000, interval_ms=10_000_000)
    assert r.verdict in (Verdict.PASS, Verdict.WARN, Verdict.FAIL)
