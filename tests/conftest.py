"""Shared fixtures: synthesize media once per session via ffmpeg (no binaries committed)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from audel.adapters._demo_assets import (
    make_clipping,
    make_desync_video,
    make_dropout,
    make_good,
    make_silent,
    make_silent_video,
    make_truncated,
    make_video_no_audio,
)

_HAS_FFMPEG = shutil.which("ffmpeg") is not None
requires_ffmpeg = pytest.mark.skipif(not _HAS_FFMPEG, reason="ffmpeg not installed")


@pytest.fixture(scope="session")
def media(tmp_path_factory) -> dict[str, Path]:
    if not _HAS_FFMPEG:
        pytest.skip("ffmpeg not installed")
    d = tmp_path_factory.mktemp("media")
    return {
        "silent": make_silent(d),
        "clipping": make_clipping(d),
        "truncated": make_truncated(d),
        "good": make_good(d),
        "no_audio": make_video_no_audio(d),
        "dropout": make_dropout(d),
        "silent_video": make_silent_video(d),
        "desync": make_desync_video(d),
    }
