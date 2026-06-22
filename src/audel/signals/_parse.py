"""Parsers for ffmpeg ``ebur128`` / ``astats`` / ``silencedetect`` stderr output.

Kept pure and side-effect-free (no subprocess) so they are trivially unit-testable against
captured fixture strings.
"""

from __future__ import annotations

import math
import re

_RE_I = re.compile(r"\bI:\s*(-?[\d.]+|-?inf)\s*LUFS")
_RE_LRA = re.compile(r"\bLRA:\s*(-?[\d.]+|-?inf)\s*LU\b")
_RE_TRUE_PEAK = re.compile(r"Peak:\s*(-?[\d.]+|-?inf)\s*dBFS")
_RE_PEAK = re.compile(r"Peak level dB:\s*(-?[\d.]+|-?inf|nan)")
_RE_RMS = re.compile(r"RMS level dB:\s*(-?[\d.]+|-?inf|nan)")
_RE_DC = re.compile(r"DC offset:\s*(-?[\d.]+|-?inf|nan)")
_RE_FLAT = re.compile(r"Flat factor:\s*(-?[\d.]+|-?inf|nan)")
_RE_SIL_START = re.compile(r"silence_start:\s*(-?[\d.]+)")
_RE_SIL_END = re.compile(r"silence_end:\s*(-?[\d.]+)")


def _f(s: str | None) -> float | None:
    if s is None:
        return None
    low = s.strip().lower()
    if low in ("-inf", "inf", "nan"):
        return -math.inf if low == "-inf" else (math.inf if low == "inf" else None)
    try:
        return float(s)
    except ValueError:
        return None


def _first(rx: re.Pattern, text: str) -> float | None:
    m = rx.search(text)
    return _f(m.group(1)) if m else None


def _last(rx: re.Pattern, text: str) -> float | None:
    matches = list(rx.finditer(text))
    return _f(matches[-1].group(1)) if matches else None


def parse_ebur128(text: str) -> dict:
    # I/LRA appear per-frame too; the Summary line is last, so take the last match (robust
    # whether or not per-frame logging was suppressed). True peak appears only in the Summary.
    return {"I": _last(_RE_I, text), "LRA": _last(_RE_LRA, text),
            "true_peak": _last(_RE_TRUE_PEAK, text)}


def parse_astats(text: str) -> dict:
    return {"peak": _first(_RE_PEAK, text), "rms": _first(_RE_RMS, text),
            "dc": _first(_RE_DC, text), "flat": _first(_RE_FLAT, text)}


def parse_silences(text: str) -> list[tuple[float, float]]:
    """Pair silence_start/silence_end in order; a dangling start (file ends silent) ends at -1."""
    starts = [float(m.group(1)) for m in _RE_SIL_START.finditer(text)]
    ends = [float(m.group(1)) for m in _RE_SIL_END.finditer(text)]
    spans: list[tuple[float, float]] = []
    for i, s in enumerate(starts):
        e = ends[i] if i < len(ends) else -1.0
        spans.append((max(0.0, s), e))
    return spans
