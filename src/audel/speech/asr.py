"""Local ASR via faster-whisper (lazy, optional ``[asr]`` extra).

Security: the model name is validated against a closed allowlist of known whisper sizes BEFORE it
reaches faster-whisper, so a caller can never point the loader at an arbitrary Hugging Face repo or
local path (supply-chain / verify-before-load). Input length is already bounded upstream by
``mediaguard`` (duration cap), and the transcript is size-capped here (memory).
"""

from __future__ import annotations

from functools import lru_cache

from ..backends.base import Segment, Transcript
from ..config import Settings
from ..errors import ConfigError, MissingDependencyError

# Closed allowlist — only these names may be loaded (each maps to a vetted CTranslate2 model).
ALLOWED_MODELS = frozenset({
    "tiny", "tiny.en", "base", "base.en", "small", "small.en",
    "medium", "medium.en", "large-v1", "large-v2", "large-v3",
    "distil-small.en", "distil-medium.en", "distil-large-v3",
})

_MAX_TRANSCRIPT_CHARS = 200_000  # cap transcript size (memory bound on adversarial audio)


def validate_model_name(name: str) -> str:
    if name not in ALLOWED_MODELS:
        raise ConfigError(
            f"ASR model {name!r} is not in the allowlist (verify-before-load); "
            f"choose one of: {', '.join(sorted(ALLOWED_MODELS))}"
        )
    return name


@lru_cache(maxsize=2)
def _load(model_name: str):
    validate_model_name(model_name)
    try:
        from faster_whisper import WhisperModel
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise MissingDependencyError("faster-whisper not installed; pip install audel[asr]") from e
    return WhisperModel(model_name, device="cpu", compute_type="int8")


def transcribe_file(path: str, *, model_name: str = "base", language: str | None = None,
                    settings: Settings | None = None) -> Transcript:
    """Transcribe a local audio file to a Transcript — self-guarding.

    Validates the source, enforces the decode caps, and transcribes a DURATION-BOUNDED 16 kHz mono
    WAV (never the raw file) so the ASR path can't be made to process unbounded audio.
    """
    from ..mediaguard import decode_to_wav, probe, validate_source

    settings = settings or Settings()
    vp = validate_source(path, settings)
    probe(vp, settings)  # enforces byte/duration/sample-rate/channel caps
    wav = decode_to_wav(vp, settings)
    try:
        model = _load(model_name)
        segments, info = model.transcribe(str(wav), language=language, vad_filter=True)
        segs, parts, total = _collect(segments)
    finally:
        wav.unlink(missing_ok=True)
    return Transcript(
        text=" ".join(parts).strip(),
        language=getattr(info, "language", None),
        language_confidence=getattr(info, "language_probability", None),
        segments=segs,
    )


def _collect(segments):
    """Stream whisper segments into (segments, text-parts, total-chars), capping transcript size."""
    segs: list[Segment] = []
    parts: list[str] = []
    total = 0
    for s in segments:
        txt = (s.text or "").strip()
        total += len(txt)
        if total > _MAX_TRANSCRIPT_CHARS:
            break
        segs.append(Segment(start_ms=int(s.start * 1000), end_ms=int(s.end * 1000), text=txt))
        parts.append(txt)
    return segs, parts, total
