"""``listen`` — hear the signal, then attend to what is said.

``check`` HEARS: is the audio present, healthy and on spec? ``listen`` does that and then LISTENS:
transcribes with word timing and grades what was said and whether a person could follow it.

Deterministic and offline (local faster-whisper, no network):

* script adherence (omissions / substitutions / ad-libs, word error rate)
* required and forbidden wording
* speech rate, rushed passages, dead-air pauses, hard-to-make-out stretches
* caption conformance (SRT/WebVTT text, offset, per-cue timing, reading rate, uncaptioned speech)
* expected language per audio track

Opt-in understanding (``understand=True``), on the backend you name. ``ollama-local`` keeps it on
your own network:

* did each key message land, and what is the one-sentence takeaway
* how was it delivered (an audio-capable model hears excerpts), versus the tone the brief asks for
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ..backends.local import LocalBackend
from ..backends.registry import resolve_backend
from ..config import Settings, load_settings
from ..errors import ConfigError, MissingDependencyError
from ..logging import get_logger
from ..mediaguard import excerpt_wav, validate_source
from ..models import (
    Confidence,
    Conformance,
    DeliveryReading,
    Issue,
    IssueKind,
    IssueSource,
    ListeningSummary,
    Report,
    Severity,
    Span,
    verdict_from_issues,
)
from ..speech import captions as cap
from ..speech import listening as lis
from ..speech import understanding as und
from ..speech.conformance import grade
from .check import check

_log = get_logger("listen")
_TRANSCRIPT_CAP = 20_000
_LANG_RE_OK = frozenset("abcdefghijklmnopqrstuvwxyz")


def _lang(code: str) -> str:
    c = (code or "").strip().lower()
    if not (2 <= len(c) <= 3) or not set(c) <= _LANG_RE_OK:
        raise ConfigError(f"language code {code!r} must be a 2-3 letter ISO 639 code")
    return c


async def listen(source, *, settings: Settings | None = None, spec=None, brief=None,
                 script: str | None = None, required: list[str] | None = None,
                 forbidden: list[str] | None = None, captions: str | None = None,
                 languages: dict[int, str] | None = None, key_messages: list[str] | None = None,
                 tone: str | None = None, understand: bool = False,
                 backend: str | None = None) -> Report:
    """Hear and listen to ``source``. Returns one Report: the hearing findings, the listening
    findings, and ``report.listening`` with the measurements behind them.

    Without ``understand`` this never touches the network. With it, egress goes ONLY to
    ``backend`` (default: ``ollama-local`` when ``AUDEL_LOCAL_LLM_URL`` is set, else the
    configured ``audio_backend``).
    """
    settings = settings or load_settings()
    if captions is not None and len(captions.encode("utf-8", "ignore")) > cap.MAX_CAPTION_BYTES:
        raise ConfigError("caption text over the size cap")
    if script is not None and len(script) > lis.MAX_SCRIPT_CHARS:
        raise ConfigError("script over the size cap")
    if tone and tone.strip().lower() not in und.DELIVERY_LABELS:
        raise ConfigError(f"tone must be one of {', '.join(und.DELIVERY_LABELS)}")
    langs = {int(k): _lang(v) for k, v in (languages or {}).items()}
    cues = cap.parse_captions(captions) if captions else None

    heard = await check(source, settings=settings, spec=spec)  # hearing first
    if not heard.tracks or any(i.kind in (IssueKind.DECODE_ERROR, IssueKind.MISSING_AUDIO)
                               for i in heard.issues):
        return heard  # nothing to listen to

    missing = [i for i in langs if not any(t.index == i for t in heard.tracks)]
    if missing:
        raise ConfigError(f"no audio track {missing[0]} in this file")
    asr = LocalBackend(settings)
    if not asr.available():
        raise MissingDependencyError("listen needs local ASR: pip install 'audel[asr]'")
    path = str(validate_source(source, settings))
    duration_ms = heard.duration_ms or 0
    transcript = await asr.transcribe(path)

    issues: list[Issue] = list(heard.issues)
    summ = ListeningSummary(language=transcript.language,
                            language_confidence=transcript.language_confidence,
                            transcript=transcript.text[:_TRANSCRIPT_CAP])

    def _deterministic() -> None:
        """All post-ASR text analysis. CPU-bound (alignment, caption matching), so it runs in a
        worker thread: one large caption file must not stall the event loop for every tenant."""
        found, delivery = lis.delivery_issues(transcript, settings, duration_ms)
        silent_spans = [i.span for i in heard.issues if i.kind == IssueKind.SILENCE and i.span]
        for i in found:  # a long pause already reported as a silence gap is one finding, not two
            if i.detail.get("check") == "long_pause" and i.span and any(
                    s.start_ms <= i.span.end_ms and i.span.start_ms <= s.end_ms for s in silent_spans):
                continue
            issues.append(i)
        summ.words, summ.speech_s, summ.wpm = delivery.words, round(delivery.speech_s, 2), (
            round(delivery.wpm, 1) if delivery.wpm is not None else None)
        summ.longest_pause_s = round(delivery.longest_pause_s, 2)
        summ.mean_word_confidence = (round(delivery.mean_word_confidence, 3)
                                     if delivery.mean_word_confidence is not None else None)
        summ.low_confidence_ratio = (round(delivery.low_confidence_ratio, 3)
                                     if delivery.low_confidence_ratio is not None else None)

        if script:
            res = lis.align_script(script, transcript, duration_ms)
            issues.extend(lis.script_issues(res))
            summ.script_words, summ.script_wer = res.script_words, round(res.wer, 3)
            summ.script_adherence = round(res.adherence, 3)
            if res.truncated:
                issues.append(Issue.make(IssueKind.OTHER, Severity.WARNING,
                                         "script check stopped early: the script and the read are "
                                         "too long or repetitive to align in full",
                                         span=Span(start_ms=0, end_ms=duration_ms),
                                         source=IssueSource.ASR, confidence=Confidence.LOW,
                                         detail={"check": "script_truncated"}))
            if res.wer > 0.25:
                issues.append(Issue.make(IssueKind.TRANSCRIPT_MISMATCH, Severity.ERROR,
                                         f"read departs from the script: {res.adherence:.0%} adherence "
                                         f"(word error rate {res.wer:.0%})",
                                         span=Span(start_ms=0, end_ms=duration_ms),
                                         source=IssueSource.ASR,
                                         detail={"check": "script_adherence", "wer": round(res.wer, 3)}))
        if required or forbidden:
            t_issues, summ.terms = lis.term_issues(transcript, duration_ms, required=required,
                                                   forbidden=forbidden)
            issues.extend(t_issues)
        if cues is not None:
            c_issues, cs = cap.caption_issues(cues, transcript, settings, duration_ms)
            issues.extend(c_issues)
            summ.caption_cues, summ.caption_matched_ratio = cs.cues, cs.matched_ratio
            summ.caption_median_drift_ms, summ.caption_max_cps = cs.median_drift_ms, cs.max_cps
            summ.uncaptioned_speech_s = cs.uncaptioned_speech_s

    await asyncio.to_thread(_deterministic)
    for idx, want in langs.items():
        got = transcript if idx == 0 else await asr.transcribe(path, stream=idx)
        detected = (got.language or "").lower()
        summ.track_languages[str(idx)] = detected
        if detected and detected != want:
            issues.append(Issue.make(IssueKind.WRONG_LANGUAGE, Severity.ERROR,
                                     f"track {idx} should be {want!r}, heard {detected!r}",
                                     span=Span(start_ms=0, end_ms=duration_ms),
                                     source=IssueSource.ASR,
                                     detail={"check": "track_language", "stream": idx,
                                             "expected": want, "heard": detected}))

    conformance: Conformance | None = None
    if brief is not None and getattr(brief, "claims", None):
        conformance, b_issues = grade(brief, transcript, duration_ms)
        issues.extend(b_issues)

    backend_used = heard.backend + "+listen"
    if understand:
        name = backend or ("ollama-local" if settings.local_llm_url else settings.audio_backend)
        be = resolve_backend(name, settings)
        if not be.available():
            raise ConfigError(f"understand=True needs a configured backend; {be.name!r} is not")
        summ.understood_by = be.name
        backend_used += f"+understand:{be.name}"
        claims = und.key_message_claims(key_messages or [])
        if claims or transcript.text:
            results, m_issues, summ.takeaway = await und.grade_messages(
                be, transcript.text, claims, duration_ms)
            issues.extend(m_issues)
            if results:
                conformance = Conformance(claims=[*(conformance.claims if conformance else []),
                                                  *results])
        readings = await _hear_delivery(be, path, transcript, settings)
        summ.delivery = [DeliveryReading(start_ms=a, end_ms=b, **r) for a, b, r in readings]
        issues.extend(und.delivery_issues(readings, tone))

    return heard.model_copy(update={
        "verdict": verdict_from_issues(issues),  # type: ignore[arg-type]
        "issues": issues,
        "summary": _summary(issues, summ),
        "conformance": conformance,
        "backend": backend_used,
        "listening": summ,
    })


async def _hear_delivery(be, path: str, transcript, settings) -> list[tuple[int, int, dict]]:
    """Excerpts at the start, middle and end of the speech, heard by an audio-capable model."""
    if not getattr(be, "hears_audio", False) or not transcript.segments:
        return []
    first, last = transcript.segments[0].start_ms, transcript.segments[-1].end_ms
    length_ms = int(settings.listen_excerpt_s * 1000)
    n = max(1, min(settings.listen_max_excerpts, 3))
    span = max(0, last - first - length_ms)
    starts = sorted({first + int(span * k / max(1, n - 1)) for k in range(n)}) if n > 1 else [first]
    out: list[tuple[int, int, dict]] = []
    for st in starts:
        wav = excerpt_wav(Path(path), settings, start_s=st / 1000.0, dur_s=settings.listen_excerpt_s)
        try:
            content = await be.critique_audio(str(wav), und.AUDIO_PROMPT)
        except Exception as e:  # noqa: BLE001 - delivery is advisory; never sink the grade
            _log.warning("delivery listening failed: %s", type(e).__name__)
            content = ""
        finally:
            wav.unlink(missing_ok=True)
        if content:
            out.append((st, min(last, st + length_ms), und.parse_delivery(content)))
    return out


def _summary(issues: list[Issue], s: ListeningSummary) -> str:
    bits = []
    if s.wpm:
        bits.append(f"{s.words} words at {s.wpm:.0f} wpm")
    if s.script_adherence is not None:
        bits.append(f"script adherence {s.script_adherence:.0%}")
    if s.caption_cues:
        bits.append(f"{s.caption_cues} caption cues")
    head = f"{len(issues)} issue(s)" if issues else "heard and listened: ok"
    return head + (" — " + ", ".join(bits) if bits else "")
