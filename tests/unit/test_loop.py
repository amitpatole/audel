"""Phase 5 — the audio feedback loop: offline grading, stuck-detection, diff, handoff persistence."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from audel import Verdict
from audel.core import compute_diff
from audel.core.diff import AudioDiff
from audel.core.loop import LoopSession
from audel.models import Issue, IssueKind, Report, Severity


def _report(verdict, issues):
    return Report(verdict=verdict, summary="s", issues=issues, backend="dsp")


def _issue(kind, msg, sev=Severity.ERROR):
    return Issue.make(kind, sev, msg)


# ---- compute_diff (pure, deterministic) ---------------------------------------

def test_diff_resolved_introduced_persisted():
    before = _report(Verdict.FAIL, [_issue(IssueKind.SILENCE, "silent"),
                                    _issue(IssueKind.CLIPPING, "clips")])
    after = _report(Verdict.WARN, [_issue(IssueKind.CLIPPING, "clips"),
                                   _issue(IssueKind.LOUDNESS, "too quiet")])
    d = compute_diff(before, after)
    assert isinstance(d, AudioDiff)
    assert any("silent" in r for r in d.resolved)
    assert any("too quiet" in i for i in d.introduced)
    assert any("clips" in p for p in d.persisted)
    assert d.improved and d.changed


def test_diff_regression_flagged():
    before = _report(Verdict.PASS, [])
    after = _report(Verdict.FAIL, [_issue(IssueKind.CLIPPING, "clips")])
    d = compute_diff(before, after)
    assert d.regressed and not d.improved


def test_diff_no_change_is_not_improved():
    issues = [_issue(IssueKind.SILENCE, "silent")]
    d = compute_diff(_report(Verdict.FAIL, issues), _report(Verdict.FAIL, list(issues)))
    assert not d.changed and not d.improved and not d.regressed


# ---- LoopSession over real fixtures (offline, zero network) --------------------

def test_loop_unchanged_failing_artifact_detects_stuck(media):
    session = LoopSession(str(media["silent"]), offline=True, stuck_threshold=2)
    history = asyncio.run(session.run(max_iter=5))
    assert len(history) == 2  # stops as soon as stuck is detected
    assert history[-1].stuck and session.stop_reason == "stuck"
    assert all(it.verdict == Verdict.FAIL for it in history)
    # second iteration diffs against the first and finds nothing changed
    assert history[1].diff is not None and not history[1].diff.changed


def test_loop_passing_artifact_stops_immediately(media):
    session = LoopSession(str(media["good"]), offline=True)
    history = asyncio.run(session.run(max_iter=5))
    assert len(history) == 1
    assert history[0].verdict == Verdict.PASS and session.stop_reason == "pass"
    assert history[0].handoff is not None and history[0].handoff.next_action.value == "done"


def test_loop_fix_between_iterations_progresses(media):
    session = LoopSession(str(media["silent"]), offline=True)
    first = asyncio.run(session.iterate())
    assert first.verdict == Verdict.FAIL and not first.progressed
    # agent "fixes" the audio by swapping in a good clip
    second = asyncio.run(session.iterate(source=str(media["good"])))
    assert second.verdict == Verdict.PASS and second.progressed
    assert second.diff is not None and second.diff.improved


def test_loop_persists_scrubbed_report_and_handoff(media):
    session = LoopSession(str(media["good"]), offline=True)
    result = asyncio.run(session.iterate())
    rp = Path(result.artifacts["report"])
    hp = Path(result.artifacts["handoff"])
    assert rp.exists() and hp.exists()
    json.loads(rp.read_text())  # valid JSON
    assert json.loads(hp.read_text())["perceived"] == "pass"
