"""Grade a :class:`Brief` against the ASR transcript — deterministic where possible.

Three claim shapes are graded without an LLM: **language** ("language is en"), **phrase**
("narration says \"welcome to Audel\"" / quoted text), and **duration** ("duration < 32s"). Each
produces a :class:`ClaimResult` (the intent side) and, when violated, a time-grounded
:class:`Issue` (the defect side that drives the verdict). Anything else is left UNCERTAIN for the
LLM critique path (Phase 3).
"""

from __future__ import annotations

import re

from ..backends.base import Transcript, _normalize
from ..models import (
    ClaimResult,
    ClaimStatus,
    Confidence,
    Conformance,
    Importance,
    Issue,
    IssueKind,
    IssueSource,
    Severity,
    Span,
)

_SEV = {Importance.MUST: Severity.ERROR, Importance.SHOULD: Severity.WARNING,
        Importance.NICE: Severity.INFO}

_LANG_NAMES = {
    "english": "en", "spanish": "es", "french": "fr", "german": "de", "italian": "it",
    "portuguese": "pt", "dutch": "nl", "russian": "ru", "chinese": "zh", "japanese": "ja",
    "korean": "ko", "hindi": "hi", "arabic": "ar",
}

_RE_LANG = re.compile(r"\blanguage\b\s*(?:is|=|:|in)?\s*([a-z]{2}|[a-z]{4,})\b", re.IGNORECASE)
_RE_DUR = re.compile(r"\bduration\b\s*([<>]=?|==?)\s*(\d+(?:\.\d+)?)\s*(ms|s|sec|seconds)?",
                     re.IGNORECASE)
_RE_QUOTED = re.compile(r"[\"“]([^\"”]+)[\"”]")
# Speech-CONTENT verbs only — "<says> X" asserts the narration content is X. The bare noun
# "narration"/"audio" must NOT trigger this (e.g. "the narration is clear" is a quality claim for
# the LLM, not a transcript match). Bare "contains a chime" is a non-speech acoustic claim (CLAP);
# only "contains the phrase/text/words ..." is a speech claim.
_RE_PHRASE_KW = re.compile(r"\b(?:says?|said|states?|reads?|speaks?|utters?|"
                           r"contains?\s+the\s+(?:phrase|text|words?))\b\s*[:\-]?\s*(.+)$",
                           re.IGNORECASE)


def _expected_language(text: str) -> str | None:
    m = _RE_LANG.search(text)
    if not m:
        return None
    tok = m.group(1).lower()
    return _LANG_NAMES.get(tok, tok if len(tok) == 2 else None)


def _duration_constraint(text: str):
    m = _RE_DUR.search(text)
    if not m:
        return None
    op, val, unit = m.group(1), float(m.group(2)), (m.group(3) or "s").lower()
    ms = val if unit == "ms" else val * 1000.0
    return op, ms


def _expected_phrase(text: str) -> str | None:
    q = _RE_QUOTED.search(text)
    if q:
        return q.group(1).strip()
    kw = _RE_PHRASE_KW.search(text)
    if kw:
        return kw.group(1).strip().strip("\"'“”")
    return None


def _find_span(phrase_norm: str, t: Transcript) -> Span | None:
    first = phrase_norm.split()[0] if phrase_norm.split() else ""
    for seg in t.segments:
        if phrase_norm in _normalize(seg.text) or (first and first in _normalize(seg.text)):
            return Span(start_ms=seg.start_ms, end_ms=seg.end_ms)
    return None


def _full_span(duration_ms: int | None) -> Span:
    return Span(start_ms=0, end_ms=int(duration_ms or 0))


def grade(brief, transcript: Transcript | None,
          duration_ms: int | None) -> tuple[Conformance, list[Issue]]:
    """Grade ``brief`` against the transcript (or ``None`` when ASR was unavailable).

    Duration claims are always checkable; language/phrase claims need a transcript and are left
    UNCERTAIN without one (we never mark a claim VIOLATED just because we couldn't hear it).
    """
    claims: list[ClaimResult] = []
    issues: list[Issue] = []
    tnorm = transcript.normalized() if transcript else ""

    for claim in getattr(brief, "claims", []):
        text = claim.text
        imp: Importance = claim.importance
        sev = _SEV[imp]
        status = ClaimStatus.UNCERTAIN
        conf = Confidence.HIGH
        evidence = ""

        lang = _expected_language(text)
        dur = _duration_constraint(text)
        phrase = None if (lang or dur) else _expected_phrase(text)

        if lang is not None and transcript is None:
            status, conf, evidence = ClaimStatus.UNCERTAIN, Confidence.LOW, "no transcript (ASR unavailable)"
        elif phrase and transcript is None:
            status, conf, evidence = ClaimStatus.UNCERTAIN, Confidence.LOW, "no transcript (ASR unavailable)"
        elif lang is not None:
            assert transcript is not None  # narrowed: the None case is handled above
            heard = (transcript.language or "").lower()
            if heard == lang:
                status, evidence = ClaimStatus.SATISFIED, f"detected language {heard!r}"
            else:
                status, evidence = ClaimStatus.VIOLATED, f"expected {lang!r}, detected {heard or '?'!r}"
                issues.append(Issue.make(IssueKind.WRONG_LANGUAGE, sev,
                                         f"expected language {lang!r}, heard {heard or 'unknown'!r}",
                                         span=_full_span(duration_ms), source=IssueSource.ASR,
                                         detail={"expected": lang, "heard": heard}))
        elif dur is not None:
            op, limit_ms = dur
            actual = float(duration_ms or 0)
            ok = {"<": actual < limit_ms, "<=": actual <= limit_ms, ">": actual > limit_ms,
                  ">=": actual >= limit_ms, "=": abs(actual - limit_ms) < 1,
                  "==": abs(actual - limit_ms) < 1}.get(op, False)
            status = ClaimStatus.SATISFIED if ok else ClaimStatus.VIOLATED
            evidence = f"actual {actual:.0f}ms {op} {limit_ms:.0f}ms"
            if not ok:
                issues.append(Issue.make(IssueKind.DURATION, sev,
                                         f"duration {actual:.0f}ms violates '{op} {limit_ms:.0f}ms'",
                                         span=_full_span(duration_ms), source=IssueSource.ASR,
                                         detail={"actual_ms": actual, "op": op, "limit_ms": limit_ms}))
        elif phrase:
            assert transcript is not None  # narrowed: the None case is handled above
            pnorm = _normalize(phrase)
            if pnorm and pnorm in tnorm:
                span = _find_span(pnorm, transcript)
                status, evidence = ClaimStatus.SATISFIED, f"found {phrase!r}"
                conf = Confidence.HIGH if span else Confidence.MEDIUM
            else:
                status = ClaimStatus.VIOLATED
                heard = transcript.text[:120]
                evidence = f"expected {phrase!r}, heard {heard!r}"
                issues.append(Issue.make(IssueKind.TRANSCRIPT_MISMATCH, sev,
                                         f"expected '{phrase}', not found in narration",
                                         span=_find_span(pnorm, transcript) or _full_span(duration_ms),
                                         source=IssueSource.ASR,
                                         detail={"expected": phrase, "heard": heard}))
        else:
            status, conf = ClaimStatus.UNCERTAIN, Confidence.LOW
            evidence = "not deterministically checkable (needs LLM critique)"

        claims.append(ClaimResult(text=text, importance=imp, status=status, confidence=conf,
                                  evidence=evidence, source="asr"))

    return Conformance(claims=claims), issues
