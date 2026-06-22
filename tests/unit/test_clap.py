"""Phase 3: CLAP non-speech grading logic (stub scorer — no torch/model download)."""

from __future__ import annotations

import pytest

from audel.acoustic import clap
from audel.errors import ConfigError
from audel.models import ClaimStatus


def test_extract_sound_label():
    assert clap.extract_sound_label("contains a chime sound at the end") == "chime"
    assert clap.extract_sound_label("must: contains a doorbell") == "doorbell"
    assert clap.extract_sound_label('narration says "hello"') is None
    assert clap.extract_sound_label("contains the phrase welcome") is None  # speech, not acoustic


def test_grade_satisfied_and_violated_with_stub_scorer():
    hit = lambda path, labels, settings: {labels[0]: 0.8, labels[1]: 0.2}  # noqa: E731
    miss = lambda path, labels, settings: {labels[0]: 0.1, labels[1]: 0.9}  # noqa: E731
    s, p, _ = clap.grade("contains a chime", "x.wav", scorer=hit)
    assert s == ClaimStatus.SATISFIED and p == 0.8
    s, p, _ = clap.grade("contains a chime", "x.wav", scorer=miss)
    assert s == ClaimStatus.VIOLATED


def test_grade_uncertain_for_non_acoustic_claim():
    s, _, _ = clap.grade('says "hello"', "x.wav", scorer=lambda *a: {})
    assert s == ClaimStatus.UNCERTAIN


def test_model_allowlist():
    assert clap.validate_model("laion/clap-htsat-unfused")
    with pytest.raises(ConfigError):
        clap.validate_model("attacker/evil-clap")
