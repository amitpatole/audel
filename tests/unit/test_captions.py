"""Phase 10: caption conformance — parsing is strict and bounded; grading finds real faults."""

from __future__ import annotations

import pytest

from audel.backends.base import Segment, Transcript, Word
from audel.config import Settings
from audel.errors import ConfigError
from audel.speech.captions import MAX_CAPTION_BYTES, caption_issues, parse_captions

SRT = """1
00:00:01,000 --> 00:00:03,000
<i>Good evening</i> and welcome.

2
00:00:04,000 --> 00:00:06,000
Rain is on the way.
"""

VTT = """WEBVTT

intro
00:01.000 --> 00:03.000 align:start position:10%
Good evening and welcome.

00:00:04.000 --> 00:00:06.000
Rain is on the way.
"""


def _heard(offset_ms: int = 0) -> Transcript:
    plan = [("good", 1000), ("evening", 1300), ("and", 1600), ("welcome", 1900),
            ("rain", 4000), ("is", 4300), ("on", 4500), ("the", 4700), ("way", 4900)]
    ws = [Word(text=w, start_ms=t + offset_ms, end_ms=t + offset_ms + 250, probability=0.9)
          for w, t in plan]
    return Transcript(text=" ".join(w for w, _ in plan),
                      segments=[Segment(start_ms=ws[0].start_ms, end_ms=ws[-1].end_ms, text="x",
                                        words=ws)])


def test_parse_srt_and_vtt_strip_markup():
    for text in (SRT, VTT):
        cues = parse_captions(text)
        assert [(c.start_ms, c.end_ms) for c in cues] == [(1000, 3000), (4000, 6000)]
        assert cues[0].text == "Good evening and welcome."


def test_parse_rejects_oversize_and_garbage():
    with pytest.raises(ConfigError):
        parse_captions("x" * (MAX_CAPTION_BYTES + 1))
    with pytest.raises(ConfigError):
        parse_captions("not a caption file")


def test_matching_captions_are_clean():
    issues, s = caption_issues(parse_captions(SRT), _heard(), Settings(), 7000)
    assert issues == [] and s.matched_ratio == 1.0


def test_consistent_offset_is_one_high_confidence_error():
    issues, s = caption_issues(parse_captions(SRT), _heard(offset_ms=2000), Settings(), 9000)
    off = [i for i in issues if i.detail["check"] == "caption_offset"]
    assert len(off) == 1 and off[0].severity.value == "error"
    assert s.median_drift_ms == 2000


def test_wrong_text_fast_cue_and_uncaptioned_speech():
    srt = SRT.replace("Rain is on the way.", "Sport is next after the break tonight here.")
    srt += "\n3\n00:00:06,500 --> 00:00:06,700\nThis cue is far too long to read in time.\n"
    t = _heard()
    extra = [Word(text=f"w{i}", start_ms=20_000 + i * 300, end_ms=20_000 + i * 300 + 250)
             for i in range(15)]
    t.segments.append(Segment(start_ms=20_000, end_ms=25_000, text="x", words=extra))
    issues, s = caption_issues(parse_captions(srt), t, Settings(), 26_000)
    checks = [i.detail["check"] for i in issues]
    assert "caption_text" in checks and "caption_reading_rate" in checks
    assert "caption_missing" in checks and s.uncaptioned_speech_s >= 3
