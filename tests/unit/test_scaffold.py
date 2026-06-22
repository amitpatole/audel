"""Phase 0b scaffold + security gates.

Pins: the base import is light (no torch/whisper), the audio models ground in time, the Handoff is
the *same* shared contract AgentVision emits (schema-compatible by construction), no default secret
exists, and the logging scrubber redacts registered secrets.
"""

from __future__ import annotations

import sys

import agentsensory

import audel
from audel import Issue, IssueKind, IssueSource, Report, Severity, Span, Verdict
from audel.config import LoudnessTarget, Settings, load_settings
from audel.logging import _SecretScrubber, register_secret


def test_base_import_is_light():
    assert "torch" not in sys.modules
    assert "faster_whisper" not in sys.modules
    assert "transformers" not in sys.modules


def test_audio_issue_is_time_grounded():
    i = Issue.make(IssueKind.TRUNCATION, Severity.ERROR, "cut off mid-word",
                   span=Span(start_ms=30120, end_ms=31040), source=IssueSource.DSP)
    assert i.span.duration_ms == 920 and i.bbox is None
    assert isinstance(i.kind, IssueKind) and i.kind.value == "truncation"
    assert i.source is IssueSource.DSP


def test_handoff_is_shared_contract_and_schema_compatible():
    # Audel and AgentVision both distill to the *same* agentsensory.Handoff class.
    assert audel.Handoff is agentsensory.Handoff
    r = Report(verdict=Verdict.FAIL, summary="bad",
               issues=[Issue.make(IssueKind.WRONG_LANGUAGE, Severity.ERROR, "heard fr, wanted en")],
               audio_path="intro.wav")
    h = r.to_handoff()
    assert h.todo == ["[wrong_language] heard fr, wanted en"]
    assert h.artifact == "intro.wav"
    props = set(audel.Handoff.model_json_schema()["properties"])
    assert {"perceived", "next_action", "todo", "open_questions", "artifact"} <= props


def test_loudness_target_default_and_lufs():
    s = Settings()
    assert s.loudness_target is LoudnessTarget.PODCAST
    assert s.loudness_target.lufs == -16.0
    assert LoudnessTarget.STREAMING.lufs == -14.0


def test_no_default_api_token():
    # A service token must never ship as a baked-in default (fail closed, not open).
    assert Settings().api_token is None
    assert load_settings().api_token is None


def test_secret_scrubber_redacts_registered_value():
    import logging as _logging

    register_secret("supersecretkey-abcdef123456")
    rec = _logging.LogRecord("audel", _logging.ERROR, __file__, 1,
                             "leaking supersecretkey-abcdef123456 now", None, None)
    _SecretScrubber().filter(rec)
    assert "supersecretkey-abcdef123456" not in rec.getMessage()
    assert "[REDACTED]" in rec.getMessage()


def test_lazy_core_not_wired_yet_errors_clearly():
    import pytest
    with pytest.raises(NotImplementedError):
        _ = audel.LoopSession
