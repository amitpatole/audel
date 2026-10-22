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
_RE_SIL_START = re.compile(r"silence_start:\s*(-?\d+(?:\.\d+)?)\b")
_RE_SIL_END = re.compile(r"silence_end:\s*(-?\d+(?:\.\d+)?)\b")


def _f(s: str | None) -> float | None:
    if s is None:
        return None
    low = s.strip().lower()
    if low in ("-nan", "+nan"):
        return None
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


def _floats(rx: re.Pattern, text: str) -> list[float]:
    out = []
    for m in rx.finditer(text):
        v = _f(m.group(1))
        if v is not None and math.isfinite(v):
            out.append(v)
    return out


def parse_silences(text: str) -> list[tuple[float, float]]:
    """Pair silence_start/silence_end in order; a dangling start (file ends silent) ends at -1."""
    starts = _floats(_RE_SIL_START, text)
    ends = _floats(_RE_SIL_END, text)
    spans: list[tuple[float, float]] = []
    for i, s in enumerate(starts):
        e = ends[i] if i < len(ends) else -1.0
        spans.append((max(0.0, s), e))
    return spans


# --- Phase 9: per-frame loudness, per-channel stats, windowed metadata series -----------------

_NUM = r"(-?[\d.]+|-?inf|-?nan)"
_RE_FRAME = re.compile(r"\bt:\s*([\d.]+)\s+TARGET:.*?\bM:\s*" + _NUM + r"\s+S:\s*" + _NUM)
_RE_FTPK = re.compile(r"\bFTPK:\s*((?:(?:-?[\d.]+|-?inf|-?nan)\s+)+)dBFS")
_RE_INSTANCE = re.compile(r"\[Parsed_(\w+?)_(\d+) @")
_RE_META_RMS = re.compile(r"lavfi\.astats\.Overall\.RMS_level=" + _NUM)
_MAX_FRAMES = 200_000  # 3h at 10 Hz is 108k; anything beyond is ignored (memory bound)


def parse_frames(text: str) -> list[tuple[float, float | None, float | None, float | None]]:
    """ebur128 ``framelog=verbose`` lines → ``(t_s, momentary, short_term, max frame true peak)``.

    Per-channel FTPK values are reduced to their max (the deliverable's frame peak).
    """
    out: list[tuple[float, float | None, float | None, float | None]] = []
    for line in text.split("\n"):
        if "TARGET:" not in line:
            continue
        m = _RE_FRAME.search(line)
        if not m:
            continue
        tp: float | None = None
        fm = _RE_FTPK.search(line)
        if fm:
            vals = [v for v in (_f(x) for x in fm.group(1).split()) if v is not None]
            tp = max(vals) if vals else None
        try:
            t = float(m.group(1))
        except ValueError:
            continue
        out.append((t, _f(m.group(2)), _f(m.group(3)), tp))
        if len(out) >= _MAX_FRAMES:
            break
    return out


def parse_astats_sections(text: str) -> dict[int, dict]:
    """astats summaries keyed by filter instance → ``{"channels": [ {...} ], "overall": {...}}``.

    Handles both per-channel and overall blocks (``Channel: N`` / ``Overall`` headers).
    """
    fields = {"Peak level dB": "peak", "RMS level dB": "rms", "DC offset": "dc",
              "Flat factor": "flat", "RMS trough dB": "rms_trough", "Noise floor dB": "noise_floor"}
    out: dict[int, dict] = {}
    current: dict[int, dict | None] = {}
    for line in text.split("\n"):
        im = _RE_INSTANCE.search(line)
        if not im or im.group(1) != "astats":
            continue
        inst = int(im.group(2))
        body = line[im.end():].split("]", 1)[-1].strip()
        rec = out.setdefault(inst, {"channels": [], "overall": {}})
        if body.startswith("Channel:"):
            ch: dict = {}
            rec["channels"].append(ch)
            current[inst] = ch
            continue
        if body.startswith("Overall"):
            current[inst] = rec["overall"]
            continue
        key, _, val = body.partition(":")
        name = fields.get(key.strip())
        target = current.get(inst)
        if name and target is not None:
            target[name] = _f(val.strip())
    return out


def parse_metadata_series(text: str) -> dict[int, list[float]]:
    """``ametadata=mode=print`` astats RMS series keyed by ametadata instance (−inf → −150 dB)."""
    out: dict[int, list[float]] = {}
    for line in text.split("\n"):
        im = _RE_INSTANCE.search(line)
        if not im or im.group(1) != "ametadata":
            continue
        m = _RE_META_RMS.search(line)
        if not m:
            continue
        v = _f(m.group(1))
        series = out.setdefault(int(im.group(2)), [])
        if len(series) < _MAX_FRAMES:
            series.append(-150.0 if v is None or v == -math.inf else max(-150.0, float(v)))
    return out
