"""Phase 9 parsers: captured ffmpeg output (no subprocess) → frames, per-channel stats, series."""

from __future__ import annotations

import math

from audel.signals._parse import parse_astats_sections, parse_frames, parse_metadata_series
from audel.signals.vad import merge_regions

FRAMES = (
    "[Parsed_ebur128_0 @ 0x1] t: 0.399977   TARGET:-23 LUFS    M: -18.7 S:-120.7     "
    "I: -18.7 LUFS       LRA:   0.0 LU  FTPK: -18.1 -17.5 dBFS  TPK: -18.1 -17.5 dBFS\n"
    "[Parsed_ebur128_0 @ 0x1] t: 0.499977   TARGET:-23 LUFS    M: -inf S: -inf     "
    "I: -18.7 LUFS       LRA:   0.0 LU  FTPK: -inf -inf dBFS  TPK: -18.1 -17.5 dBFS\n"
    "unrelated line\n"
)

ASTATS = """[Parsed_astats_1 @ 0x2] Channel: 1
[Parsed_astats_1 @ 0x2] DC offset: 0.050000
[Parsed_astats_1 @ 0x2] Peak level dB: -3.0
[Parsed_astats_1 @ 0x2] RMS level dB: -21.0
[Parsed_astats_1 @ 0x2] Channel: 2
[Parsed_astats_1 @ 0x2] DC offset: 0.000000
[Parsed_astats_1 @ 0x2] Peak level dB: -inf
[Parsed_astats_1 @ 0x2] RMS level dB: -inf
[Parsed_astats_1 @ 0x2] Overall
[Parsed_astats_1 @ 0x2] Peak level dB: -3.0
[Parsed_astats_1 @ 0x2] RMS level dB: -24.0
"""

SERIES = """[Parsed_ametadata_4 @ 0x3] frame:0    pts:0       pts_time:0
[Parsed_ametadata_4 @ 0x3] lavfi.astats.Overall.RMS_level=-43.2
[Parsed_ametadata_9 @ 0x4] lavfi.astats.Overall.RMS_level=-inf
[Parsed_ametadata_4 @ 0x3] lavfi.astats.Overall.RMS_level=-42.8
"""


def test_parse_frames_reduces_per_channel_true_peak():
    f = parse_frames(FRAMES)
    assert len(f) == 2
    t, m, s, tp = f[0]
    assert abs(t - 0.4) < 1e-3 and m == -18.7 and s == -120.7 and tp == -17.5
    assert f[1][1] == -math.inf and f[1][3] == -math.inf


def test_parse_astats_sections_per_channel_and_overall():
    sec = parse_astats_sections(ASTATS)[1]
    assert [c["rms"] for c in sec["channels"]] == [-21.0, -math.inf]
    assert sec["channels"][0]["dc"] == 0.05
    assert sec["overall"]["rms"] == -24.0


def test_parse_metadata_series_keyed_by_instance():
    ser = parse_metadata_series(SERIES)
    assert ser[4] == [-43.2, -42.8] and ser[9] == [-150.0]


def test_merge_regions_bounds_the_select_expression():
    regions = [(i * 1.0, i * 1.0 + 0.5) for i in range(1000)]
    merged = merge_regions(regions, 200)
    assert len(merged) == 200
    assert merged[0][0] == 0.0 and merged[-1][1] == 999.5
    assert merge_regions([(2.0, 1.0), (0.0, 1.0), (0.5, 1.5)], 10) == [(0.0, 1.5)]


def test_parse_frames_keeps_silent_frames_with_negative_nan():
    text = ("[Parsed_ebur128_0 @ 0x1] t: 11.299955  TARGET:-23 LUFS    M:  -nan S:  -nan     "
            "I: -20.1 LUFS       LRA:   7.1 LU  FTPK:  -inf dBFS  TPK:  -1.7 dBFS\n")
    f = parse_frames(text)
    assert len(f) == 1 and abs(f[0][0] - 11.3) < 1e-3 and f[0][1] is None and f[0][2] is None
