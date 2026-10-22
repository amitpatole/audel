"""Local ASR via faster-whisper (lazy, optional ``[asr]`` extra).

Security: the model name is validated against a closed allowlist of known whisper sizes BEFORE it
reaches faster-whisper, so a caller can never point the loader at an arbitrary Hugging Face repo or
local path (supply-chain / verify-before-load). Input length is already bounded upstream by
``mediaguard`` (duration cap), and the transcript is size-capped here (memory).
"""

from __future__ import annotations

from functools import lru_cache

from ..backends.base import Segment, Transcript, Word
from ..config import Settings
from ..errors import ConfigError, MissingDependencyError

# Closed allowlist — only these names may be loaded (each maps to a vetted CTranslate2 model).
ALLOWED_MODELS = frozenset({
    "tiny", "tiny.en", "base", "base.en", "small", "small.en",
    "medium", "medium.en", "large-v1", "large-v2", "large-v3",
    "distil-small.en", "distil-medium.en", "distil-large-v3",
})

_MAX_TRANSCRIPT_CHARS = 200_000  # cap transcript size (memory bound on adversarial audio)
_MAX_WORDS_PER_SEGMENT = 500


def validate_model_name(name: str) -> str:
    if name not in ALLOWED_MODELS:
        raise ConfigError(
            f"ASR model {name!r} is not in the allowlist (verify-before-load); "
            f"choose one of: {', '.join(sorted(ALLOWED_MODELS))}"
        )
    return name


_DEVICES = frozenset({"auto", "cpu", "cuda"})
_COMPUTE = frozenset({"auto", "int8", "int8_float16", "float16", "float32"})


def _device_and_compute(device: str, compute: str) -> tuple[str, str]:
    if device not in _DEVICES or compute not in _COMPUTE:
        raise ConfigError(f"asr_device must be one of {sorted(_DEVICES)} and asr_compute_type one "
                          f"of {sorted(_COMPUTE)}")
    if device == "auto":
        try:
            import ctranslate2

            device = "cuda" if ctranslate2.get_cuda_device_count() > 0 else "cpu"
        except Exception:  # noqa: BLE001 - no CUDA runtime: CPU
            device = "cpu"
    if compute == "auto":
        compute = "float16" if device == "cuda" else "int8"
    return device, compute


@lru_cache(maxsize=2)
def _load(model_name: str, device: str = "cpu", compute: str = "int8",
          download_root: str | None = None):
    validate_model_name(model_name)
    try:
        from faster_whisper import WhisperModel
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise MissingDependencyError("faster-whisper not installed; pip install audel[asr]") from e
    return WhisperModel(model_name, device=device, compute_type=compute, download_root=download_root)


def transcribe_file(path: str, *, model_name: str = "base", language: str | None = None,
                    settings: Settings | None = None, stream: int = 0,
                    word_timestamps: bool = True) -> Transcript:
    """Transcribe a local audio file to a Transcript — self-guarding.

    Validates the source, enforces the decode caps, and transcribes a DURATION-BOUNDED 16 kHz mono
    WAV (never the raw file) so the ASR path can't be made to process unbounded audio.
    """
    from ..mediaguard import decode_to_wav, probe, validate_source

    settings = settings or Settings()
    vp = validate_source(path, settings)
    probe(vp, settings)  # enforces byte/duration/sample-rate/channel caps
    wav = decode_to_wav(vp, settings, stream=stream)
    try:
        device, compute = _device_and_compute(settings.asr_device, settings.asr_compute_type)
        root = str(settings.asr_model_dir) if settings.asr_model_dir else None
        model = _load(model_name, device, compute, root)
        # Hand whisper the decoded samples, not a path: we already decoded a bounded 16 kHz mono
        # WAV with ffmpeg, and faster-whisper's own loader (PyAV) breaks across PyAV releases.
        audio = _read_wav_f32(wav)
        segments, info = model.transcribe(audio, language=language, vad_filter=True,
                                          word_timestamps=word_timestamps)
        segs, parts, total = _collect(segments)
    finally:
        wav.unlink(missing_ok=True)
    return Transcript(
        text=" ".join(parts).strip(),
        language=getattr(info, "language", None),
        language_confidence=getattr(info, "language_probability", None),
        segments=segs,
    )


def _read_wav_f32(path):
    import wave

    import numpy as np

    with wave.open(str(path), "rb") as w:
        if w.getsampwidth() != 2 or w.getnchannels() != 1:
            raise ConfigError("ASR expects 16-bit mono PCM")
        raw = w.readframes(w.getnframes())
    return np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0


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
        words = [Word(start_ms=int(w.start * 1000), end_ms=int(w.end * 1000),
                      text=(w.word or "").strip()[:64], probability=getattr(w, "probability", None))
                 for w in (getattr(s, "words", None) or [])][:_MAX_WORDS_PER_SEGMENT]
        segs.append(Segment(start_ms=int(s.start * 1000), end_ms=int(s.end * 1000), text=txt,
                            words=words, avg_logprob=getattr(s, "avg_logprob", None),
                            no_speech_prob=getattr(s, "no_speech_prob", None)))
        parts.append(txt)
    return segs, parts, total
