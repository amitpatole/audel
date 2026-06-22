"""Audio backend protocol + transcript model (mirrors AgentVision's ``VisionBackend``).

A backend turns audio into a transcript (deterministic, local) and — optionally — into LLM
critique (claim extraction, naturalness/tone). The offline ``local`` backend implements only
``transcribe`` and returns ``""`` from the LLM methods, exactly as AgentVision's local backend does.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class Segment(BaseModel):
    start_ms: int
    end_ms: int
    text: str


class Transcript(BaseModel):
    text: str = ""
    language: str | None = None
    language_confidence: float | None = None
    segments: list[Segment] = Field(default_factory=list)

    def normalized(self) -> str:
        return _normalize(self.text)


def _normalize(s: str) -> str:
    """Lowercase, drop punctuation, collapse whitespace — for robust phrase matching."""
    import re

    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", s.lower())).strip()


@runtime_checkable
class AudioBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    async def transcribe(self, audio_path: str, *, language: str | None = None) -> Transcript: ...

    async def complete_text(self, system: str, user: str) -> str:
        """Text-only completion (transcript critique / claim extraction). ``""`` if unsupported."""
        ...

    async def critique_audio(self, audio_path: str, prompt: str) -> str:
        """Audio-native critique (tone/naturalness). ``""`` unless the backend hears raw audio."""
        ...
