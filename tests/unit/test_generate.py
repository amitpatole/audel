"""Phase 5 — the generative loop: generate -> hear -> refine, with stuck/match/refine-failure stops.

Network-free: ``analyze`` and the text backend are stubbed, so this exercises loop CONTROL FLOW
(the real grading path is covered by the analyze/check suites).
"""

from __future__ import annotations

import asyncio

import pytest

from audel.core import generate as gen_mod
from audel.core.generate import GenerativeLoopSession
from audel.models import Brief, IntentClaim, Issue, IssueKind, Report, Severity, Verdict


def _brief():
    return Brief(text="say hello", claims=[IntentClaim(text="says the word hello")])


def _report(verdict, msg="bad"):
    issues = [] if verdict == Verdict.PASS else [Issue.make(IssueKind.TRANSCRIPT_MISMATCH,
                                                            Severity.ERROR, msg)]
    return Report(verdict=verdict, summary="s", issues=issues, backend="ollama")


class _FakeBackend:
    def __init__(self, reply="improved prompt"):
        self.reply = reply
        self.calls = 0

    async def complete_text(self, system, user):
        self.calls += 1
        return self.reply


def _patch(monkeypatch, reports, backend=None):
    seq = iter(reports)

    async def fake_analyze(artifact, **kw):
        return next(seq)

    monkeypatch.setattr(gen_mod, "analyze", fake_analyze)
    if backend is not None:
        monkeypatch.setattr("audel.backends.registry.resolve_backend",
                            lambda name, settings: backend)


def test_empty_brief_rejected():
    with pytest.raises(ValueError):
        GenerativeLoopSession(Brief(), lambda p: "x.wav")


def test_matches_intent_stops_first_iteration(monkeypatch):
    _patch(monkeypatch, [_report(Verdict.PASS)])
    calls = []
    session = GenerativeLoopSession(_brief(), lambda p: calls.append(p) or "out0.wav")
    history = asyncio.run(session.run(max_iter=4))
    assert len(history) == 1 and session.stop_reason == "matched intent"
    assert history[0].artifact == "out0.wav"


def test_refine_runs_between_iterations_until_pass(monkeypatch):
    be = _FakeBackend(reply="say HELLO clearly")
    _patch(monkeypatch, [_report(Verdict.FAIL, "missing hello"), _report(Verdict.PASS)], backend=be)
    prompts = []
    session = GenerativeLoopSession(_brief(), lambda p: prompts.append(p) or "o.wav")
    history = asyncio.run(session.run(max_iter=4))
    assert len(history) == 2 and session.stop_reason == "matched intent"
    assert be.calls == 1                       # refined exactly once after the first failure
    assert prompts[1] == "say HELLO clearly"   # the refined prompt drove the 2nd generation


def test_stuck_when_same_issue_repeats(monkeypatch):
    be = _FakeBackend(reply="still the same")
    _patch(monkeypatch, [_report(Verdict.FAIL, "same"), _report(Verdict.FAIL, "same")], backend=be)
    session = GenerativeLoopSession(_brief(), lambda p: "o.wav", stuck_threshold=2)
    history = asyncio.run(session.run(max_iter=4))
    assert history[-1].stuck and session.stop_reason == "stuck"


def test_no_text_backend_stops_gracefully(monkeypatch):
    def boom(name, settings):
        raise RuntimeError("no key")

    _patch(monkeypatch, [_report(Verdict.FAIL)])
    monkeypatch.setattr("audel.backends.registry.resolve_backend", boom)
    session = GenerativeLoopSession(_brief(), lambda p: "o.wav")
    history = asyncio.run(session.run(max_iter=4))
    assert len(history) == 1
    assert session.stop_reason == "cannot refine (no text backend available)"
