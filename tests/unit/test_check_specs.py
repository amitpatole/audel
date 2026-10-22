"""Phase 9: spec-driven grading on real media — tracks summarized, dialogue gating, back-compat."""

from __future__ import annotations

import asyncio
import shutil
import subprocess

import pytest

from audel.config import Settings
from audel.core import check
from audel.models import Severity

requires_ffmpeg = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")


@requires_ffmpeg
def test_report_carries_spec_and_track_summaries(media):
    r = asyncio.run(check(str(media["good"]), spec="ebu_r128"))
    assert r.spec == "ebu_r128" and len(r.tracks) == 1
    t = r.tracks[0]
    assert t.integrated_lufs is not None and t.true_peak_dbtp is not None
    r.model_dump_json()  # JSON-safe (no inf/nan)


@requires_ffmpeg
def test_default_grading_is_unchanged_without_a_spec(media):
    r = asyncio.run(check(str(media["good"])))
    assert r.spec == "preset.podcast"
    assert all(i.severity != Severity.ERROR for i in r.issues if i.kind.value == "loudness")


@requires_ffmpeg
def test_reject_strictness_makes_a_loudness_miss_an_error(media):
    r = asyncio.run(check(str(media["good"]), spec="ebu_r128"))
    loud = [i for i in r.issues if i.detail.get("check") == "integrated_loudness"]
    assert loud and all(i.severity == Severity.ERROR for i in loud)


@requires_ffmpeg
def test_unknown_spec_fails_closed(media):
    from audel.errors import ConfigError

    with pytest.raises(ConfigError):
        asyncio.run(check(str(media["good"]), spec="bogus"))


@pytest.mark.skipif(shutil.which("espeak-ng") is None or shutil.which("ffmpeg") is None,
                    reason="needs espeak-ng + ffmpeg")
def test_dialogue_gated_spec_measures_speech_only(tmp_path):
    pytest.importorskip("faster_whisper")
    speech = tmp_path / "speech.wav"
    subprocess.run(["espeak-ng", "-w", str(speech), "This is a short dialogue line for the "
                    "loudness meter. And here is a second sentence after a pause."], check=True)
    padded = tmp_path / "padded.wav"
    # 6 s of quiet room tone after the dialogue: programme loudness drops, speech-gated must not.
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(speech), "-af",
                    "apad=pad_dur=6", str(padded)], check=True)
    r = asyncio.run(check(str(padded), spec="netflix"))
    t = r.tracks[0]
    assert t.dialogue_lufs is not None and t.dialogue_coverage is not None
    assert 0.05 < t.dialogue_coverage < 0.9
    loud = [i for i in r.issues if i.detail.get("check") == "integrated_loudness"]
    for i in loud:
        assert i.detail["basis"] == "speech-gated"


@requires_ffmpeg
def test_multitrack_languages_are_reported(tmp_path):
    a = tmp_path / "a.wav"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "sine=f=440:d=2", str(a)],
                   check=True)
    mkv = tmp_path / "mt.mkv"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(a), "-i", str(a), "-map", "0:a",
                    "-map", "1:a", "-c:a", "pcm_s16le", "-metadata:s:a:0", "language=eng",
                    "-metadata:s:a:1", "language=fra", str(mkv)], check=True)
    r = asyncio.run(check(str(mkv), settings=Settings()))
    assert [t.language for t in r.tracks] == ["eng", "fra"]
