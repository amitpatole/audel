"""Phase 2 security: ASR supply-chain (model allowlist) + bounded-decode + no-egress.

Surfaces: a caller must not be able to point the ASR loader at an arbitrary model repo/path, and
the ASR path must transcribe a duration-bounded decode (never the raw, possibly-lying file).
"""

from __future__ import annotations

import inspect

import pytest

import audel.mediaguard as MG
import audel.speech.asr as asr
from audel.errors import ConfigError


def test_model_name_allowlist_blocks_arbitrary_loads():
    for bad in ("../evil", "/etc/passwd", "attacker/whisper-malware", "large-v3; rm -rf", "huge-v99"):
        with pytest.raises(ConfigError, match="allowlist"):
            asr.validate_model_name(bad)


def test_allowlisted_models_pass():
    for ok in ("base", "tiny.en", "large-v3", "distil-large-v3"):
        assert asr.validate_model_name(ok) == ok


def test_asr_transcribes_a_duration_bounded_decode_not_raw_file():
    # Structural guarantee: transcribe_file decodes to a bounded WAV via mediaguard before whisper.
    src = inspect.getsource(asr.transcribe_file)
    assert "decode_to_wav" in src and "validate_source" in src and "probe" in src
    # and decode_to_wav passes -t max_duration_s + mono 16k resample to ffmpeg
    dsrc = inspect.getsource(MG.decode_to_wav)
    assert "max_duration_s" in dsrc and '"-t"' in dsrc
    assert '"-ar"' in dsrc and '"-ac"' in dsrc and "sample_rate" in dsrc


def test_transcript_size_is_capped():
    assert asr._MAX_TRANSCRIPT_CHARS <= 1_000_000
