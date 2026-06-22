"""Anthropic (Claude Haiku) text-critique backend — the fallback for ``complete_text``.

Key-gated and lazy: the SDK is imported only when used; ``available()`` is False without a key, so
``analyze`` fails closed rather than downgrading. Transcription delegates to the offline local ASR;
Claude is text-only here, so ``critique_audio`` returns ``""``.
"""

from __future__ import annotations

import asyncio

from ..config import Settings
from ..errors import BackendAuthError, BackendError
from .base import Transcript
from .local import LocalBackend

_MAX_RESPONSE_CHARS = 20_000


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def available(self) -> bool:
        return bool(self._settings.key_for("anthropic"))

    async def transcribe(self, audio_path: str, *, language: str | None = None) -> Transcript:
        return await LocalBackend(self._settings).transcribe(audio_path, language=language)

    async def complete_text(self, system: str, user: str) -> str:
        key = self._settings.key_for("anthropic")
        if not key:
            raise BackendAuthError("no Anthropic key (set ANTHROPIC_API_KEY or ~/.config/Anthropic/key)")
        return await asyncio.to_thread(self._complete, key, system, user)

    async def critique_audio(self, audio_path: str, prompt: str) -> str:
        return ""

    def _complete(self, key: str, system: str, user: str) -> str:
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise BackendError("anthropic SDK not installed; pip install audel[cloud]") from e
        try:
            client = anthropic.Anthropic(api_key=key)
            msg = client.messages.create(
                model=self._settings.anthropic_model, max_tokens=700, temperature=0,
                system=system, messages=[{"role": "user", "content": user}])
            parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
        except Exception as e:  # noqa: BLE001
            raise BackendError(f"Anthropic request failed: {type(e).__name__}") from e
        return ("".join(parts))[:_MAX_RESPONSE_CHARS]
