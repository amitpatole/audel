"""Synthesize demo/test media with ffmpeg — no binary fixtures committed to the repo.

Used by ``audel demo`` and the test-suite fixtures so both exercise the real decode path on
deterministically-generated clips (silent / clipping / truncated / clean).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _ffmpeg() -> str:
    path = shutil.which("ffmpeg")
    if not path:  # pragma: no cover
        raise RuntimeError("ffmpeg not found; install ffmpeg to generate demo assets")
    return path


def _synth(path: Path, lavfi: str, *, af: str | None = None) -> Path:
    argv = [_ffmpeg(), "-y", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", lavfi]
    if af:
        argv += ["-af", af]
    argv += [str(path)]
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
    return path


def make_silent(d: Path) -> Path:
    return _synth(d / "silent.wav", "anullsrc=r=16000:cl=mono:d=2")


def make_clipping(d: Path) -> Path:
    # A full-scale sine pushed +20 dB clips hard (true peak well above -1 dBTP).
    return _synth(d / "clipping.wav", "sine=frequency=440:duration=2:sample_rate=16000",
                  af="volume=20dB")


def make_truncated(d: Path) -> Path:
    # Moderate white noise that simply stops at high energy — no fade, no trailing silence
    # (truncation cue). Noise keeps RMS well above the truncation floor while true-peak stays
    # under the clip ceiling (a sine's crest factor can't satisfy both on every ffmpeg build).
    return _synth(d / "truncated.wav", "anoisesrc=d=1:c=white:a=0.3:r=16000")


def make_good(d: Path) -> Path:
    # Moderate tone normalized toward the podcast target (-16 LUFS) with a clean fade-out and a
    # real trailing silence (so it ends quietly — no clipping, no truncation cue).
    return _synth(d / "good.wav", "sine=frequency=440:duration=2.5:sample_rate=16000",
                  af="afade=t=out:st=2.0:d=0.5,apad=pad_dur=0.5,loudnorm=I=-16:TP=-2:LRA=11")


def make_video_no_audio(d: Path) -> Path:
    # A video-only file (no audio stream) — exercises the missing-audio check.
    return _synth(d / "noaudio.mp4", "testsrc=size=64x64:rate=5:duration=1")


def make_dropout(d: Path) -> Path:
    # An active tone with a 0.6s muted interior gap (a mid-playback dropout; >= silencedetect's
    # 0.5s floor so it registers, but < check()'s 1.5s plain-silence threshold).
    return _synth(d / "dropout.wav", "sine=frequency=440:duration=2:sample_rate=16000",
                  af="volume=0:enable='between(t,0.7,1.3)'")


def make_silent_video(d: Path) -> Path:
    # A video that "plays" but whose audio track is silent.
    p = d / "silentvideo.mp4"
    argv = [_ffmpeg(), "-y", "-hide_banner", "-loglevel", "error",
            "-f", "lavfi", "-i", "testsrc=size=64x64:rate=5:duration=1",
            "-f", "lavfi", "-i", "anullsrc=r=16000:cl=mono", "-shortest", str(p)]
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
    return p


def make_desync_video(d: Path) -> Path:
    # Video ~2s, audio ~1s (no -shortest) → audio/video duration mismatch (A/V desync).
    p = d / "desync.mp4"
    argv = [_ffmpeg(), "-y", "-hide_banner", "-loglevel", "error",
            "-f", "lavfi", "-i", "testsrc=size=64x64:rate=10:duration=2",
            "-f", "lavfi", "-i", "sine=frequency=440:duration=1:sample_rate=16000", str(p)]
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
    return p


def make_broken(d: Path) -> Path:
    """The deliberately-broken demo clip (clipping → deterministic FAIL)."""
    return make_clipping(d)
