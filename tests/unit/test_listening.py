"""Phase 10: deterministic listening on word-timed transcripts (no ASR needed)."""

from __future__ import annotations

from audel.backends.base import Segment, Transcript, Word
from audel.config import Settings
from audel.speech.listening import align_script, delivery_issues, script_issues, term_issues


def _t(words: list[tuple[str, int, int, float]]) -> Transcript:
    ws = [Word(text=w, start_ms=a, end_ms=b, probability=p) for w, a, b, p in words]
    return Transcript(text=" ".join(w for w, *_ in words), language="en",
                      segments=[Segment(start_ms=ws[0].start_ms, end_ms=ws[-1].end_ms,
                                        text=" ".join(w for w, *_ in words), words=ws)])


def _seq(text: str, start: int = 0, step: int = 300, p: float = 0.95):
    return [(w, start + i * step, start + i * step + 250, p) for i, w in enumerate(text.split())]


def test_dropped_line_is_a_time_grounded_error():
    heard = _t(_seq("good evening here is the news") + _seq("drivers take care", start=3000))
    res = align_script("Good evening, here is the news. Flooding is possible near the river. "
                       "Drivers take care.", heard, 5000)
    om = [d for d in res.deviations if d.op == "omission"]
    assert om and om[0].expected == "flooding is possible near the river"
    assert 1500 <= om[0].start_ms <= om[0].end_ms <= 3000   # between the words either side
    issues = script_issues(res)
    drop = [i for i in issues if i.detail["check"] == "script_omission"]
    assert drop and drop[0].severity.value == "error" and drop[0].confidence.value == "high"
    assert 0 < res.wer < 1


def test_perfect_read_has_no_deviations():
    heard = _t(_seq("the offer ends on friday"))
    res = align_script("The offer ends on Friday.", heard, 2000)
    assert res.wer == 0 and res.deviations == [] and script_issues(res) == []


def test_single_word_substitution_is_only_a_warning():
    heard = _t(_seq("the offer ends on monday"))
    issues = script_issues(align_script("The offer ends on Friday.", heard, 2000))
    assert [i.severity.value for i in issues] == ["warning"]


def test_required_and_forbidden_terms():
    heard = _t(_seq("buy now terms and conditions apply call our rival acme today"))
    issues, found = term_issues(heard, 5000, required=["Terms and conditions apply", "Offer ends Friday"],
                                forbidden=["acme"])
    assert found == {"Terms and conditions apply": True, "Offer ends Friday": False, "acme": True}
    req = [i for i in issues if i.detail["check"] == "required_term"]
    forb = [i for i in issues if i.detail["check"] == "forbidden_term"]
    assert len(req) == 1 and "Offer ends Friday" in req[0].message
    assert len(forb) == 1 and forb[0].span.start_ms == 9 * 300


def test_pace_pause_and_intelligibility():
    words = _seq("one two three four five six seven eight nine ten", step=150)  # 400 wpm
    words += [(w, 10_000 + i * 150, 10_000 + i * 150 + 100, 0.2)
              for i, w in enumerate("mumble mumble mumble mumble mumble mumble mumble mumble".split())]
    issues, d = delivery_issues(_t(words), Settings(), 12_000)
    checks = {i.detail["check"] for i in issues}
    assert {"speech_rate", "long_pause", "low_intelligibility"} <= checks
    assert d.longest_pause_s > 8 and d.low_confidence_ratio and d.low_confidence_ratio > 0.4
