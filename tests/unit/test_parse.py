"""Pure parser tests for ffmpeg filter output (no subprocess — fast, deterministic)."""

from __future__ import annotations

import math

from audel.signals._parse import parse_astats, parse_ebur128, parse_silences

_EBUR128 = """
[Parsed_ebur128_0 @ 0x1] t: 0.1  I: -70.0 LUFS  LRA: 0.0 LU
[Parsed_ebur128_0 @ 0x1] Summary:
  Integrated loudness:
    I:         -16.2 LUFS
  Loudness range:
    LRA:         5.0 LU
  True peak:
    Peak:       -1.0 dBFS
"""

_ASTATS = """
[Parsed_astats_1 @ 0x2] Overall
[Parsed_astats_1 @ 0x2] DC offset: -0.000006
[Parsed_astats_1 @ 0x2] Peak level dB: 0.000000
[Parsed_astats_1 @ 0x2] RMS level dB: -20.12
[Parsed_astats_1 @ 0x2] Flat factor: 1.5
"""

_SILENCES = """
[silencedetect @ 0x3] silence_start: 1.2
[silencedetect @ 0x3] silence_end: 3.4 | silence_duration: 2.2
[silencedetect @ 0x3] silence_start: 5.0
"""


def test_parse_ebur128_takes_summary_not_per_frame():
    e = parse_ebur128(_EBUR128)
    assert e["I"] == -16.2  # Summary value, not the -70 per-frame line
    assert e["LRA"] == 5.0 and e["true_peak"] == -1.0


def test_parse_astats():
    a = parse_astats(_ASTATS)
    assert a["peak"] == 0.0 and a["rms"] == -20.12 and a["flat"] == 1.5


def test_parse_silences_pairs_and_dangling():
    s = parse_silences(_SILENCES)
    assert s[0] == (1.2, 3.4)
    assert s[1] == (5.0, -1.0)  # dangling start (file ends silent) → -1 end sentinel


def test_parse_handles_inf():
    assert parse_astats("RMS level dB: -inf")["rms"] == -math.inf
