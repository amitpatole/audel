"""Listening — attending to what is SAID, not only whether there is sound.

Hearing (``check``) answers "is the signal healthy?". Listening answers "did the right words get
said, could a listener follow them, and is anything missing or out of place?" Everything here is
deterministic and offline: it works on the word-timed faster-whisper transcript.

* **Script adherence** — align the transcript to the approved script and report every omission,
  substitution and ad-lib, time-grounded, plus the word error rate.
* **Required / forbidden terms** — legal disclaimers, sponsor reads and brand names that must be
  said; competitor names or banned words that must not.
* **Pace** — words per minute overall, and rushed passages.
* **Pauses** — dead air inside the read that a listener would notice.
* **Intelligibility** — stretches where the recogniser itself could barely make the words out.

ASR is not ground truth. Findings that rest on a single word carry MEDIUM or LOW confidence; a run
of several missing script words (a dropped line) is the high-confidence signal.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from ..backends.base import Transcript, Word, _normalize
from ..models import Confidence, Issue, IssueKind, IssueSource, Severity, Span

MAX_SCRIPT_CHARS = 200_000
_MAX_TOKENS = 30_000
_MAX_DEVIATIONS = 40
_RUN_IS_A_LINE = 3        # this many consecutive script words missing = a dropped line
_SUB_IS_A_MISREAD = 5     # substitutions are often recogniser errors: need a longer run


@dataclass
class ScriptDeviation:
    op: str               # omission | substitution | insertion
    expected: str
    heard: str
    start_ms: int
    end_ms: int
    words: int
    low_confidence: bool = False


@dataclass
class ScriptResult:
    script_words: int
    heard_words: int
    wer: float
    deviations: list[ScriptDeviation] = field(default_factory=list)
    truncated: bool = False

    @property
    def adherence(self) -> float:
        return max(0.0, 1.0 - self.wer)


def _tokens(text: str) -> list[str]:
    return _normalize(text).split()[:_MAX_TOKENS]


def timed_words(t: Transcript) -> list[Word]:
    """Word-timed tokens; if the ASR ran without word timestamps, spread each segment's words
    evenly across the segment (coarser, but keeps every finding time-grounded)."""
    words = t.words()
    if words:
        out = []
        for w in words:
            for tok in _tokens(w.text):  # one ASR "word" can normalize to several tokens
                out.append(Word(start_ms=w.start_ms, end_ms=w.end_ms, text=tok,
                                probability=w.probability))
        return out[:_MAX_TOKENS]
    out = []
    for s in t.segments:
        toks = _tokens(s.text)
        if not toks:
            continue
        step = max(1, (s.end_ms - s.start_ms) // len(toks))
        for i, tok in enumerate(toks):
            a = s.start_ms + i * step
            out.append(Word(start_ms=a, end_ms=a + step, text=tok))
    return out[:_MAX_TOKENS]


def _gap_span(words: list[Word], j: int, duration_ms: int) -> tuple[int, int]:
    start = words[j - 1].end_ms if j > 0 else 0
    end = words[j].start_ms if j < len(words) else duration_ms
    return start, max(start, end)


_EXACT_LIMIT = 250_000     # script x heard tokens below this: one exact alignment
_CHUNK = 150               # otherwise align ~150-token script windows against nearby speech
_ALIGN_BUDGET_S = 20.0     # wall-clock budget; past it the alignment is reported as truncated


def _opcodes(s_toks: list[str], h_toks: list[str], state: dict | None = None):
    """difflib opcodes, exact for small pairs; windowed (O(n x window)) otherwise, under a
    wall-clock budget (``state["truncated"]`` is set when it runs out) so alignment time stays
    bounded whatever the input, including adversarially repetitive text."""
    import time

    state = state if state is not None else {}
    if len(s_toks) * max(1, len(h_toks)) <= _EXACT_LIMIT:
        yield from difflib.SequenceMatcher(None, s_toks, h_toks, autojunk=False).get_opcodes()
        return
    deadline = time.monotonic() + _ALIGN_BUDGET_S
    j = 0
    ratio = len(h_toks) / max(1, len(s_toks))
    for i in range(0, len(s_toks), _CHUNK):
        if time.monotonic() > deadline:
            state["truncated"] = True
            state["aligned_upto"] = i
            return
        a = s_toks[i:i + _CHUNK]
        last = i + _CHUNK >= len(s_toks)
        # heard window: proportional extent plus slack, starting where the last chunk ended
        jend = len(h_toks) if last else min(len(h_toks), j + int(len(a) * ratio * 1.5) + 50)
        b = h_toks[j:jend]
        ops = difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
        if not last:
            # keep heard tokens after the chunk's last match for the next window
            keep = [op for op in ops if not (op[0] == "insert" and op[3] >= max(
                (o[4] for o in ops if o[0] == "equal"), default=0))]
            consumed = max((o[4] for o in keep), default=0)
            ops = keep
        else:
            consumed = len(b)
        for tag, i1, i2, j1, j2 in ops:
            yield tag, i + i1, i + i2, j + j1, j + j2
        j += consumed


def align_script(script: str, transcript: Transcript, duration_ms: int) -> ScriptResult:
    script = (script or "")[:MAX_SCRIPT_CHARS]
    s_toks = _tokens(script)
    words = timed_words(transcript)
    h_toks = [w.text for w in words]
    edits = 0
    devs: list[ScriptDeviation] = []
    state: dict = {}
    for tag, i1, i2, j1, j2 in _opcodes(s_toks, h_toks, state):
        if tag == "equal":
            continue
        a, b = i2 - i1, j2 - j1
        edits += max(a, b)
        heard = words[j1:j2]
        low = bool(heard) and all((w.probability or 1.0) < 0.6 for w in heard)
        if tag == "delete":
            st, en = _gap_span(words, j1, duration_ms)
            devs.append(ScriptDeviation("omission", " ".join(s_toks[i1:i2]), "", st, en, a))
        elif tag == "replace":
            devs.append(ScriptDeviation("substitution", " ".join(s_toks[i1:i2]),
                                        " ".join(h_toks[j1:j2]), heard[0].start_ms,
                                        heard[-1].end_ms, max(a, b), low))
        elif tag == "insert":
            devs.append(ScriptDeviation("insertion", "", " ".join(h_toks[j1:j2]),
                                        heard[0].start_ms, heard[-1].end_ms, b, low))
    denom = state.get("aligned_upto", len(s_toks)) or 1
    wer = edits / denom if s_toks else 0.0
    return ScriptResult(script_words=len(s_toks), heard_words=len(h_toks), wer=wer,
                        deviations=devs, truncated=bool(state.get("truncated")))


def script_issues(res: ScriptResult) -> list[Issue]:
    out: list[Issue] = []
    for d in res.deviations[:_MAX_DEVIATIONS]:
        line = d.words >= _RUN_IS_A_LINE
        if d.op == "insertion" and not line:
            continue  # a stray extra word is usually ASR noise or a harmless filler
        if d.op == "omission":
            sev = Severity.ERROR if line else Severity.WARNING
            msg = f"script line not heard: \"{d.expected[:160]}\""
        elif d.op == "substitution":
            sev = Severity.ERROR if d.words >= _SUB_IS_A_MISREAD else Severity.WARNING
            msg = f"script says \"{d.expected[:120]}\", heard \"{d.heard[:120]}\""
        else:
            sev = Severity.WARNING
            msg = f"unscripted words: \"{d.heard[:160]}\""
        # Only a dropped LINE is high-confidence: substitutions and ad-libs are often recognition
        # errors, so they stay medium (or low when the recogniser itself was unsure).
        if d.low_confidence:
            conf = Confidence.LOW
        elif d.op == "omission" and line:
            conf = Confidence.HIGH
        else:
            conf = Confidence.MEDIUM
        out.append(Issue.make(IssueKind.TRANSCRIPT_MISMATCH, sev, msg,
                              span=Span(start_ms=d.start_ms, end_ms=d.end_ms),
                              source=IssueSource.ASR, confidence=conf,
                              detail={"check": f"script_{d.op}", "expected": d.expected[:500],
                                      "heard": d.heard[:500], "words": d.words}))
    return out


def _find(seq: list[str], needle: list[str], index: dict[str, list[int]] | None = None) -> list[int]:
    """Start positions of ``needle`` in ``seq``. With a token->positions index only candidate
    positions are checked (linear in matches, not in sequence length x terms)."""
    if not needle:
        return []
    n = len(needle)
    starts = index.get(needle[0], []) if index is not None else range(len(seq) - n + 1)
    return [i for i in starts if seq[i:i + n] == needle]


def _index(seq: list[str]) -> dict[str, list[int]]:
    idx: dict[str, list[int]] = {}
    for i, t in enumerate(seq):
        idx.setdefault(t, []).append(i)
    return idx


def term_issues(transcript: Transcript, duration_ms: int, *, required: list[str] | None = None,
                forbidden: list[str] | None = None) -> tuple[list[Issue], dict[str, bool]]:
    words = timed_words(transcript)
    toks = [w.text for w in words]
    index = _index(toks)
    found: dict[str, bool] = {}
    out: list[Issue] = []
    for term in (required or [])[:200]:
        needle = _tokens(term)[:50]
        hits = _find(toks, needle, index)[:1000]
        found[term] = bool(hits)
        if not hits:
            out.append(Issue.make(IssueKind.TRANSCRIPT_MISMATCH, Severity.ERROR,
                                  f"required wording not heard: \"{term[:160]}\"",
                                  span=Span(start_ms=0, end_ms=duration_ms), source=IssueSource.ASR,
                                  confidence=Confidence.MEDIUM,
                                  detail={"check": "required_term", "term": term[:200]}))
    for term in (forbidden or [])[:200]:
        needle = _tokens(term)[:50]
        hits = _find(toks, needle, index)[:1000]
        found[term] = bool(hits)
        for i in hits[:20]:
            out.append(Issue.make(IssueKind.INTENT_MISMATCH, Severity.ERROR,
                                  f"forbidden wording heard: \"{term[:160]}\"",
                                  span=Span(start_ms=words[i].start_ms,
                                            end_ms=words[i + len(needle) - 1].end_ms),
                                  source=IssueSource.ASR, confidence=Confidence.MEDIUM,
                                  detail={"check": "forbidden_term", "term": term[:200]}))
    return out, found


@dataclass
class Delivery:
    words: int = 0
    speech_s: float = 0.0
    wpm: float | None = None
    longest_pause_s: float = 0.0
    low_confidence_ratio: float | None = None
    mean_word_confidence: float | None = None


def delivery_issues(transcript: Transcript, settings, duration_ms: int) -> tuple[list[Issue], Delivery]:
    words = transcript.words()  # raw ASR words (probabilities live here)
    d = Delivery(words=len(words))
    out: list[Issue] = []
    if len(words) < 8:
        return out, d
    d.speech_s = sum(max(0, s.end_ms - s.start_ms) for s in transcript.segments) / 1000.0
    d.wpm = (len(words) / d.speech_s * 60.0) if d.speech_s > 0 else None
    if d.wpm is not None and (d.wpm < settings.listen_min_wpm or d.wpm > settings.listen_max_wpm):
        fast = d.wpm > settings.listen_max_wpm
        out.append(Issue.make(IssueKind.OTHER, Severity.WARNING,
                              f"speech rate {d.wpm:.0f} words/min is {'rushed' if fast else 'slow'} "
                              f"(comfortable range {settings.listen_min_wpm:.0f}-"
                              f"{settings.listen_max_wpm:.0f})",
                              span=Span(start_ms=words[0].start_ms, end_ms=words[-1].end_ms),
                              source=IssueSource.ASR, confidence=Confidence.MEDIUM,
                              detail={"check": "speech_rate", "wpm": round(d.wpm, 1)}))
    # Rushed passages: consecutive 10 s windows well above the ceiling.
    rushed = 0
    t0 = words[0].start_ms
    window: list[Word] = []
    for w in words + [Word(start_ms=10**12, end_ms=10**12, text="")]:
        if w.start_ms - t0 >= 10_000 or w.start_ms == 10**12:
            if len(window) >= 2:
                span_s = (window[-1].end_ms - window[0].start_ms) / 1000.0
                rate = len(window) / span_s * 60 if span_s > 0 else 0.0
                if span_s >= 8.0 and rate > settings.listen_max_wpm * 1.25 and rushed < 10:
                    out.append(Issue.make(IssueKind.OTHER, Severity.WARNING,
                                          f"rushed passage: {rate:.0f} words/min",
                                          span=Span(start_ms=window[0].start_ms,
                                                    end_ms=window[-1].end_ms),
                                          source=IssueSource.ASR, confidence=Confidence.MEDIUM,
                                          detail={"check": "rushed_passage", "wpm": round(rate, 1)}))
                    rushed += 1
            window, t0 = [], w.start_ms
        window.append(w)
    # Long pauses inside the read.
    for a, b in zip(words, words[1:], strict=False):
        gap = (b.start_ms - a.end_ms) / 1000.0
        d.longest_pause_s = max(d.longest_pause_s, gap)
        if gap >= settings.listen_max_pause_s:
            out.append(Issue.make(IssueKind.OTHER, Severity.WARNING,
                                  f"{gap:.1f}s pause inside the read (dead air for a listener)",
                                  span=Span(start_ms=a.end_ms, end_ms=b.start_ms),
                                  source=IssueSource.ASR, confidence=Confidence.MEDIUM,
                                  detail={"check": "long_pause", "pause_s": round(gap, 2)}))
    # Intelligibility: stretches the recogniser could barely make out.
    probs = [w.probability for w in words if w.probability is not None]
    if probs:
        d.mean_word_confidence = sum(probs) / len(probs)
        low = [w for w in words if w.probability is not None and w.probability < settings.listen_low_conf]
        d.low_confidence_ratio = len(low) / len(probs)
        run: list[Word] = []
        reported = 0
        for w in words + [Word(start_ms=10**12, end_ms=10**12, text="", probability=1.0)]:
            if w.probability is not None and w.probability < settings.listen_low_conf:
                run.append(w)
                continue
            if run and (run[-1].end_ms - run[0].start_ms) >= 1000 and reported < 10:
                out.append(Issue.make(IssueKind.OTHER, Severity.WARNING,
                                      f"hard to make out: \"{' '.join(x.text for x in run)[:120]}\"",
                                      span=Span(start_ms=run[0].start_ms, end_ms=run[-1].end_ms),
                                      source=IssueSource.ASR, confidence=Confidence.LOW,
                                      detail={"check": "low_intelligibility",
                                              "mean_probability": round(sum(
                                                  x.probability or 0 for x in run) / len(run), 3)}))
                reported += 1
            run = []
    return out, d
