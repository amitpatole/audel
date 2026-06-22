"""CLAP zero-shot non-speech conformance — "contains a chime / doorbell / alarm".

Heavy (torch + transformers) and optional (``[clap]`` extra), lazy-imported. The model id is
validated against a closed allowlist before load (verify-before-load / supply-chain). The grading
logic (label extraction + threshold) is separated from the scorer so it is unit-testable with a
stub; the real scorer downloads a pinned CLAP checkpoint only when actually used.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..config import Settings
from ..errors import ConfigError, MissingDependencyError
from ..models import ClaimStatus

ALLOWED_CLAP_MODELS = frozenset({
    "laion/clap-htsat-unfused", "laion/clap-htsat-fused", "laion/larger_clap_general",
})
DEFAULT_CLAP_MODEL = "laion/clap-htsat-unfused"
_PRESENCE_THRESHOLD = 0.55  # P(label) above this = present

_RE_CONTAINS = re.compile(r"\bcontains?\b\s+(.+)", re.IGNORECASE)
_STRIP = re.compile(r"\b(a|an|the|sound|sounds|noise|audio|at\s+the\s+(?:start|end|beginning))\b",
                    re.IGNORECASE)


def extract_sound_label(claim_text: str) -> str | None:
    """Pull the non-speech sound label from a claim ("contains a chime at the end" -> "chime").

    Returns None when the claim is not a "contains <sound>" acoustic claim (e.g. a speech phrase,
    which is graded against the transcript instead).
    """
    m = _RE_CONTAINS.search(claim_text)
    if not m:
        return None
    raw = m.group(1)
    if re.match(r"\s*the\s+(phrase|text|words?)\b", raw, re.IGNORECASE):
        return None  # "contains the phrase ..." is a speech claim, not acoustic
    label = _STRIP.sub(" ", raw)
    label = re.sub(r"[^\w\s]", " ", label)
    label = re.sub(r"\s+", " ", label).strip()
    return label or None


def validate_model(model_id: str) -> str:
    if model_id not in ALLOWED_CLAP_MODELS:
        raise ConfigError(f"CLAP model {model_id!r} not in the allowlist (verify-before-load)")
    return model_id


@lru_cache(maxsize=1)
def _load(model_id: str):
    validate_model(model_id)
    try:
        from transformers import ClapModel, ClapProcessor
    except ImportError as e:  # pragma: no cover - only without the extra
        raise MissingDependencyError("CLAP needs transformers+torch; pip install audel[clap]") from e
    return ClapModel.from_pretrained(model_id), ClapProcessor.from_pretrained(model_id)


def real_scorer(audio_path: str, labels: list[str], settings: Settings) -> dict:  # pragma: no cover
    """Score P(label) for each candidate label against the audio via a pinned CLAP model."""
    import librosa
    import torch

    model, processor = _load(DEFAULT_CLAP_MODEL)
    audio, _ = librosa.load(audio_path, sr=48000, mono=True)
    inputs = processor(text=labels, audios=audio, sampling_rate=48000, return_tensors="pt",
                       padding=True)
    with torch.no_grad():
        logits = model(**inputs).logits_per_audio[0]
        probs = torch.softmax(logits, dim=-1).tolist()
    return dict(zip(labels, probs, strict=False))


def grade(claim_text: str, audio_path: str, *, settings: Settings | None = None, scorer=None):
    """Grade a non-speech "contains <sound>" claim. ``scorer`` is injectable for tests.

    Returns (ClaimStatus, score, evidence). UNCERTAIN when not an acoustic claim.
    """
    settings = settings or Settings()
    label = extract_sound_label(claim_text)
    if not label:
        return ClaimStatus.UNCERTAIN, None, "not a non-speech acoustic claim"
    fn = scorer or real_scorer
    scores = fn(audio_path, [label, "other ambient audio"], settings)
    p = float(scores.get(label, 0.0))
    if p >= _PRESENCE_THRESHOLD:
        return ClaimStatus.SATISFIED, p, f"detected {label!r} (p={p:.2f})"
    return ClaimStatus.VIOLATED, p, f"{label!r} not detected (p={p:.2f})"
