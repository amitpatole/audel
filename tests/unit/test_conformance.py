"""Phase 2: transcript conformance grading (pure — no ASR, fast/deterministic)."""

from __future__ import annotations

from audel import Brief
from audel.backends.base import Segment, Transcript
from audel.models import ClaimStatus, IssueKind
from audel.speech.conformance import grade


def _t(text, lang="en"):
    return Transcript(text=text, language=lang,
                      segments=[Segment(start_ms=0, end_ms=len(text) * 50, text=text)])


def test_phrase_satisfied_with_span():
    brief = Brief.from_inputs(expect=['must: narration says "welcome to Audel"'])
    conf, issues = grade(brief, _t("Welcome to Audel, your audio companion."), 3000)
    assert conf.claims[0].status == ClaimStatus.SATISFIED
    assert conf.matches_intent() and issues == []


def test_phrase_violated_emits_transcript_mismatch_with_span():
    brief = Brief.from_inputs(expect=['must: narration says "welcome to Audel"'])
    conf, issues = grade(brief, _t("welcome to oral, your audio companion"), 3000)
    assert conf.claims[0].status == ClaimStatus.VIOLATED
    assert not conf.matches_intent()
    mm = next(i for i in issues if i.kind == IssueKind.TRANSCRIPT_MISMATCH)
    assert mm.span is not None and mm.detail["expected"] == "welcome to Audel"


def test_language_satisfied_and_violated():
    ok, _ = grade(Brief.from_inputs(expect=["must: language is en"]), _t("hello", "en"), 1000)
    assert ok.claims[0].status == ClaimStatus.SATISFIED
    bad, issues = grade(Brief.from_inputs(expect=["must: language is en"]), _t("bonjour", "fr"), 1000)
    assert bad.claims[0].status == ClaimStatus.VIOLATED
    assert any(i.kind == IssueKind.WRONG_LANGUAGE for i in issues)


def test_duration_claims_graded_without_transcript():
    # Duration needs no ASR — gradeable even when transcript is None.
    ok, _ = grade(Brief.from_inputs(expect=["must: duration < 32s"]), None, 30_000)
    assert ok.claims[0].status == ClaimStatus.SATISFIED
    bad, issues = grade(Brief.from_inputs(expect=["must: duration < 2s"]), None, 30_000)
    assert bad.claims[0].status == ClaimStatus.VIOLATED
    assert any(i.kind == IssueKind.DURATION for i in issues)


def test_language_and_phrase_uncertain_without_transcript():
    conf, issues = grade(Brief.from_inputs(
        expect=['must: language is en', 'must: says "hi"']), None, 1000)
    assert all(c.status == ClaimStatus.UNCERTAIN for c in conf.claims)
    assert issues == []  # never VIOLATED just because we couldn't hear


def test_unparseable_claim_is_uncertain():
    conf, issues = grade(Brief.from_inputs(expect=["should: the tone is warm and friendly"]),
                         _t("anything"), 1000)
    assert conf.claims[0].status == ClaimStatus.UNCERTAIN and issues == []
