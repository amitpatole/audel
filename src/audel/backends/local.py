"""The offline ``local`` backend — faster-whisper transcription, no LLM, no egress.

Mirrors AgentVision's local backend: implements the deterministic capability (``transcribe``) and
returns ``""`` from the LLM methods so the no-key path is fully functional.
"""

from __future__ import annotations

import asyncio

from ..config import Settings
from .base import Transcript


class LocalBackend:
    name = "local"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def available(self) -> bool:
        import importlib.util

        return importlib.util.find_spec("faster_whisper") is not None

    async def transcribe(self, audio_path: str, *, language: str | None = None) -> Transcript:
        from ..speech.asr import transcribe_file

        model = self._settings.asr_model
        lang = language if language is not None else self._settings.asr_language
        return await asyncio.to_thread(transcribe_file, audio_path, model_name=model,
                                       language=lang, settings=self._settings)

    async def complete_text(self, system: str, user: str) -> str:
        return ""

    async def critique_audio(self, audio_path: str, prompt: str) -> str:
        return ""
