"""Gemini audio-native backend — the opt-in path for prosody/tone the transcript can't capture.

Key-gated and lazy. Unlike the text backends, ``critique_audio`` sends the actual (bounded) audio
to Gemini, so it can grade naturalness/tone. ``complete_text`` does text grading; ``transcribe``
delegates to the offline local ASR.
"""

from __future__ import annotations

import asyncio

from ..config import Settings
from ..errors import BackendAuthError, BackendError
from ..mediaguard import decode_to_wav, probe, validate_source
from .base import Transcript
from .local import LocalBackend

_MAX_RESPONSE_CHARS = 20_000


class GeminiAudioBackend:
    name = "gemini-audio"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def available(self) -> bool:
        return bool(self._settings.key_for("gemini-audio"))

    async def transcribe(self, audio_path: str, *, language: str | None = None) -> Transcript:
        return await LocalBackend(self._settings).transcribe(audio_path, language=language)

    async def complete_text(self, system: str, user: str) -> str:
        return await asyncio.to_thread(self._text, system, user)

    async def critique_audio(self, audio_path: str, prompt: str) -> str:
        return await asyncio.to_thread(self._audio, audio_path, prompt)

    def _client(self):
        key = self._settings.key_for("gemini-audio")
        if not key:
            raise BackendAuthError("no Google key (set GOOGLE_API_KEY or ~/.config/Google/key)")
        try:
            from google import genai
        except ImportError as e:  # pragma: no cover
            raise BackendError("google-genai not installed; pip install audel[cloud]") from e
        return genai.Client(api_key=key)

    def _text(self, system: str, user: str) -> str:
        client = self._client()
        try:
            r = client.models.generate_content(model=self._settings.gemini_audio_model,
                                                contents=f"{system}\n\n{user}")
            return (getattr(r, "text", "") or "")[:_MAX_RESPONSE_CHARS]
        except Exception as e:  # noqa: BLE001
            raise BackendError(f"Gemini request failed: {type(e).__name__}") from e

    def _audio(self, audio_path: str, prompt: str) -> str:
        client = self._client()
        # Send a duration-bounded decode, never the raw file.
        vp = validate_source(audio_path, self._settings)
        probe(vp, self._settings)
        wav = decode_to_wav(vp, self._settings)
        try:
            uploaded = client.files.upload(file=str(wav))
            r = client.models.generate_content(model=self._settings.gemini_audio_model,
                                                contents=[prompt, uploaded])
            return (getattr(r, "text", "") or "")[:_MAX_RESPONSE_CHARS]
        except Exception as e:  # noqa: BLE001
            raise BackendError(f"Gemini audio request failed: {type(e).__name__}") from e
        finally:
            wav.unlink(missing_ok=True)
