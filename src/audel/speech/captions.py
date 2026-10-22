"""Caption / subtitle conformance (SRT and WebVTT) against what is actually heard.

For accessibility and localisation QC: does every cue say what the audio says, is it on time, can
it be read at a sensible pace, and is there speech with no caption at all? Parsing is strict and
bounded (file size, cue count, cue length); cue text is treated as untrusted data.
"""

from __future__ import annotations

import difflib
import re
import statistics
from dataclasses import dataclass

from ..backends.base import Transcript
from ..errors import ConfigError
from ..models import Confidence, Issue, IssueKind, IssueSource, Severity, Span
from .listening import _tokens, timed_words

MAX_CAPTION_BYTES = 2_000_000
MAX_CUES = 20_000
_MAX_CUE_CHARS = 1_000
_MAX_REPORTED = 30
_TS = r"(?:(\d{1,2}):)?(\d{1,2}):(\d{2})[.,](\d{3})"
_RE_TIMING = re.compile(_TS + r"\s*-->\s*" + _TS)
_RE_TAGS = re.compile(r"<[^>]{0,200}>|\{\\[^}]{0,200}\}")


@dataclass
class Cue:
    start_ms: int
    end_ms: int
    text: str


def _ms(h, m, s, ms) -> int:
    return ((int(h or 0) * 60 + int(m)) * 60 + int(s)) * 1000 + int(ms)


def parse_captions(text: str) -> list[Cue]:
    """Parse SRT or WebVTT. Raises ConfigError on oversize or no cues."""
    if len(text.encode("utf-8", "ignore")) > MAX_CAPTION_BYTES:
        raise ConfigError(f"caption file over {MAX_CAPTION_BYTES} bytes")
    cues: list[Cue] = []
    blocks = re.split(r"\r?\n\s*\r?\n", text.replace("﻿", ""))
    for block in blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        for k, ln in enumerate(lines):
            m = _RE_TIMING.search(ln)
            if not m:
                continue
            g = m.groups()
            start, end = _ms(*g[0:4]), _ms(*g[4:8])
            body = " ".join(lines[k + 1:])
            body = _RE_TAGS.sub("", body)[:_MAX_CUE_CHARS].strip()
            cues.append(Cue(start, end, body))
            break
        if len(cues) >= MAX_CUES:
            break
    if not cues:
        raise ConfigError("no caption cues found (expected SRT or WebVTT)")
    return cues


@dataclass
class CaptionSummary:
    cues: int = 0
    matched_ratio: float | None = None
    median_drift_ms: int | None = None
    max_cps: float | None = None
    uncaptioned_speech_s: float = 0.0


def caption_issues(cues: list[Cue], transcript: Transcript, settings,
                   duration_ms: int) -> tuple[list[Issue], CaptionSummary]:
    words = timed_words(transcript)
    out: list[Issue] = []
    summ = CaptionSummary(cues=len(cues))
    reported = {"text": 0, "timing": 0, "cps": 0, "format": 0}
    drifts: list[int] = []
    drift_cues: list[tuple[Cue, int]] = []
    matched = 0
    cps_max = 0.0

    def issue(kind, sev, msg, a, b, check, conf=Confidence.MEDIUM, **detail):
        out.append(Issue.make(kind, sev, msg, span=Span(start_ms=max(0, a), end_ms=max(a, b)),
                              source=IssueSource.ASR, confidence=conf,
                              detail={"check": check, **detail}))

    prev_end = -1
    for n, c in enumerate(cues):
        dur = c.end_ms - c.start_ms
        if dur <= 0 or c.start_ms < prev_end - 50:
            if reported["format"] < _MAX_REPORTED:
                issue(IssueKind.OTHER, Severity.WARNING,
                      f"cue {n + 1} has {'no duration' if dur <= 0 else 'an overlap with the previous cue'}",
                      c.start_ms, c.end_ms, "caption_format")
                reported["format"] += 1
        prev_end = max(prev_end, c.end_ms)
        if dur > 0:
            cps = len(c.text.replace(" ", "")) / (dur / 1000.0)
            cps_max = max(cps_max, cps)
            if cps > settings.caption_max_cps and reported["cps"] < _MAX_REPORTED:
                issue(IssueKind.OTHER, Severity.WARNING,
                      f"cue {n + 1} reads at {cps:.0f} characters/s (limit "
                      f"{settings.caption_max_cps:.0f}): too fast to read",
                      c.start_ms, c.end_ms, "caption_reading_rate", cps=round(cps, 1))
                reported["cps"] += 1
        ctoks = _tokens(c.text)
        if len(ctoks) < 2:
            continue
        # How much of the cue was actually heard while it was on screen (small tolerance either
        # side). Measured against the CUE's words, so neighbouring speech cannot dilute it.
        near = [w for w in words if c.start_ms - 400 <= (w.start_ms + w.end_ms) // 2 <= c.end_ms + 400]
        heard = [w.text for w in near]
        if heard:
            sm = difflib.SequenceMatcher(None, ctoks, heard, autojunk=False)
            ratio = sum(b.size for b in sm.get_matching_blocks()) / len(ctoks)
        else:
            ratio = 0.0
        if ratio < 0.6:
            # Allow for a consistent caption offset: look again in a wider window before judging.
            wide = [w.text for w in words
                    if c.start_ms - 5000 <= (w.start_ms + w.end_ms) // 2 <= c.end_ms + 5000]
            if wide:
                sm = difflib.SequenceMatcher(None, ctoks, wide, autojunk=False)
                wide_ratio = sum(b.size for b in sm.get_matching_blocks()) / len(ctoks)
                if wide_ratio >= 0.8:
                    near = [w for w in words if c.start_ms - 5000 <= (w.start_ms + w.end_ms) // 2
                            <= c.end_ms + 5000]
                    ratio = wide_ratio
        if ratio >= 0.6:
            matched += 1
            # Drift: where the cue's first words are actually spoken.
            for i in range(len(near)):
                if near[i].text == ctoks[0] and (len(ctoks) < 2 or i + 1 >= len(near)
                                                 or near[i + 1].text == ctoks[1]):
                    drifts.append(near[i].start_ms - c.start_ms)
                    drift_cues.append((c, near[i].start_ms - c.start_ms))
                    break
        elif reported["text"] < _MAX_REPORTED:
            issue(IssueKind.TRANSCRIPT_MISMATCH, Severity.ERROR if ratio < 0.3 else Severity.WARNING,
                  f"cue {n + 1} says \"{c.text[:100]}\" but the audio there says "
                  f"\"{' '.join(heard)[:100]}\"", c.start_ms, c.end_ms, "caption_text",
                  similarity=round(ratio, 2))
            reported["text"] += 1
    summ.matched_ratio = matched / len(cues) if cues else None
    summ.max_cps = round(cps_max, 1) if cps_max else None
    if drifts:
        med = int(statistics.median(drifts))
        summ.median_drift_ms = med
        if abs(med) > settings.caption_max_drift_ms:
            issue(IssueKind.DESYNC, Severity.ERROR,
                  f"captions are {'late' if med < 0 else 'early'} by {abs(med) / 1000:.1f}s "
                  "throughout (median offset between cue and speech)", 0, duration_ms,
                  "caption_offset", conf=Confidence.HIGH, median_drift_ms=med)
        else:
            for c, dft in drift_cues:
                if abs(dft - med) > settings.caption_max_drift_ms and reported["timing"] < _MAX_REPORTED:
                    issue(IssueKind.DESYNC, Severity.WARNING,
                          f"cue at {c.start_ms / 1000:.1f}s is {abs(dft - med) / 1000:.1f}s off "
                          "the speech", c.start_ms, c.end_ms, "caption_timing", drift_ms=dft)
                    reported["timing"] += 1
    # Speech with no caption on screen.
    covered = sorted((c.start_ms - 500, c.end_ms + 500) for c in cues)
    run_start = None
    last_end = 0
    uncaptioned = 0.0
    k = 0
    for w in words:
        while k < len(covered) and covered[k][1] < w.start_ms:
            k += 1
        inside = k < len(covered) and covered[k][0] <= w.start_ms <= covered[k][1]
        if not inside:
            run_start = w.start_ms if run_start is None else run_start
            last_end = w.end_ms
        elif run_start is not None:
            if last_end - run_start >= 3000:
                uncaptioned += (last_end - run_start) / 1000.0
                issue(IssueKind.TRANSCRIPT_MISMATCH, Severity.WARNING,
                      f"{(last_end - run_start) / 1000:.1f}s of speech has no caption",
                      run_start, last_end, "caption_missing")
            run_start = None
    if run_start is not None and last_end - run_start >= 3000:
        uncaptioned += (last_end - run_start) / 1000.0
        issue(IssueKind.TRANSCRIPT_MISMATCH, Severity.WARNING,
              f"{(last_end - run_start) / 1000:.1f}s of speech has no caption", run_start,
              last_end, "caption_missing")
    summ.uncaptioned_speech_s = round(uncaptioned, 1)
    return out, summ
