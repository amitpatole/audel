"""Phase 3: analyze() orchestration with stub backends (deterministic, offline)."""

from __future__ import annotations

import asyncio
import importlib

import pytest

from audel import Brief, Verdict
from audel.acoustic import clap
from audel.backends.base import Segment, Transcript
from audel.core import analyze
from audel.errors import BackendAuthError
from audel.models import ClaimStatus, IssueKind

analyze_mod = importlib.import_module("audel.core.analyze")


class _StubLLM:
    name = "stub"

    def __init__(self, json_reply, available=True):
        self._reply, self._avail = json_reply, available

    def available(self):
        return self._avail

    async def transcribe(self, audio_path, *, language=None):
        return Transcript(text="the quick round fox", language="en",
                          segments=[Segment(start_ms=0, end_ms=1000, text="the quick round fox")])

    async def complete_text(self, system, user):
        # capture the prompt for the injection-isolation assertion
        _StubLLM.last_system, _StubLLM.last_user = system, user
        return self._reply

    async def critique_audio(self, audio_path, prompt):
        return ""


def _patch(monkeypatch, backend):
    monkeypatch.setattr(analyze_mod, "resolve_backend", lambda name, settings: backend)


def test_analyze_llm_grades_uncertain_should_claim(media, monkeypatch):
    _patch(monkeypatch, _StubLLM('[{"index":0,"status":"violated","evidence":"not a sentence"}]'))
    brief = Brief.from_inputs(expect=["should: the narration is a clear complete sentence"])
    r = asyncio.run(analyze(str(media["good"]), brief=brief, backend="stub"))
    c = r.conformance.claims[0]
    assert c.status == ClaimStatus.VIOLATED and c.source == "audio_llm"
    assert r.verdict == Verdict.WARN  # should-violation warns


def test_analyze_fail_closed_when_backend_unavailable(media, monkeypatch):
    _patch(monkeypatch, _StubLLM("[]", available=False))
    brief = Brief.from_inputs(expect=["must: the tone is warm and natural"])
    with pytest.raises(BackendAuthError):
        asyncio.run(analyze(str(media["good"]), brief=brief, backend="stub"))


def test_analyze_routes_contains_claim_to_clap(media, monkeypatch):
    _patch(monkeypatch, _StubLLM("[]"))
    # CLAP's real scorer is monkeypatched to a stub "hit" so no torch is needed.
    monkeypatch.setattr(clap, "real_scorer", lambda path, labels, settings: {labels[0]: 0.9, labels[1]: 0.1})
    brief = Brief.from_inputs(expect=["must: contains a chime at the end"])
    r = asyncio.run(analyze(str(media["good"]), brief=brief, backend="stub"))
    assert r.conformance.claims[0].status == ClaimStatus.SATISFIED
    assert r.conformance.claims[0].source == "acoustic"


def test_analyze_clap_violation_emits_issue(media, monkeypatch):
    _patch(monkeypatch, _StubLLM("[]"))
    monkeypatch.setattr(clap, "real_scorer", lambda path, labels, settings: {labels[0]: 0.05, labels[1]: 0.95})
    brief = Brief.from_inputs(expect=["must: contains a chime at the end"])
    r = asyncio.run(analyze(str(media["good"]), brief=brief, backend="stub"))
    assert r.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.INTENT_MISMATCH for i in r.issues)


def test_llm_grade_parse_tolerates_noise():
    from audel.core.analyze import _parse_grades
    g = _parse_grades('here you go: [{"index":0,"status":"satisfied","evidence":"ok"}] thanks')
    assert g[0][0] == ClaimStatus.SATISFIED
    assert _parse_grades("not json at all") == {}
