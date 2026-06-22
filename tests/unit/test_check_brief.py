"""Phase 2: check(brief=...) end-to-end with a stub backend (no whisper required)."""

from __future__ import annotations

import asyncio
import importlib

from audel import Brief, Verdict
from audel.backends.base import Segment, Transcript
from audel.core import check
from audel.models import IssueKind

# `audel.core.check` the attribute resolves to the *function* (re-exported in core/__init__);
# grab the actual module so we can patch its `resolve_backend` lookup.
check_mod = importlib.import_module("audel.core.check")


class _FakeBackend:
    name = "fake"

    def __init__(self, text, lang="en"):
        self._t = Transcript(text=text, language=lang,
                             segments=[Segment(start_ms=0, end_ms=2000, text=text)])

    def available(self):
        return True

    async def transcribe(self, audio_path, *, language=None):
        return self._t

    async def complete_text(self, system, user):
        return ""

    async def critique_audio(self, audio_path, prompt):
        return ""


def _patch(monkeypatch, text, lang="en"):
    monkeypatch.setattr(check_mod, "resolve_backend",
                        lambda name, settings: _FakeBackend(text, lang))


def test_check_brief_passes_when_narration_matches(media, monkeypatch):
    _patch(monkeypatch, "welcome to Audel")
    brief = Brief.from_inputs(expect=['must: narration says "welcome to Audel"',
                                      "must: language is en"])
    r = asyncio.run(check(str(media["good"]), brief=brief))
    assert r.conformance is not None and r.conformance.matches_intent()
    # verdict is PASS unless a DSP issue intervenes; the good clip is clean
    assert r.verdict == Verdict.PASS


def test_check_brief_fails_on_wrong_phrase_and_lists_intent(media, monkeypatch):
    _patch(monkeypatch, "welcome to oral")
    brief = Brief.from_inputs(expect=['must: narration says "welcome to Audel"'])
    r = asyncio.run(check(str(media["good"]), brief=brief))
    assert r.verdict == Verdict.FAIL
    assert not r.conformance.matches_intent()
    assert any(i.kind == IssueKind.TRANSCRIPT_MISMATCH for i in r.issues)
    h = r.to_handoff()
    assert h.matches_intent is False
    assert any("welcome to Audel" in t for t in h.todo)


def test_check_brief_fails_on_wrong_language(media, monkeypatch):
    _patch(monkeypatch, "bonjour le monde", lang="fr")
    brief = Brief.from_inputs(expect=["must: language is en"])
    r = asyncio.run(check(str(media["good"]), brief=brief))
    assert r.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.WRONG_LANGUAGE for i in r.issues)


def test_check_brief_over_duration_fails(media, monkeypatch):
    _patch(monkeypatch, "anything")
    brief = Brief.from_inputs(expect=["must: duration < 1s"])  # good clip is ~3s
    r = asyncio.run(check(str(media["good"]), brief=brief))
    assert r.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.DURATION for i in r.issues)
