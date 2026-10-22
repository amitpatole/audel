"""On-prem / LAN inference backend — an Ollama server the operator runs (``ollama-local``).

For media that must not leave the building (unreleased programmes, embargoed news, client
masters), point Audel at your own Ollama: ``AUDEL_LOCAL_LLM_URL=http://10.0.0.100:11434`` plus
``AUDEL_TRUSTED_BACKEND_HOSTS=["10.0.0.100"]``. Nothing is sent to any third party.

* ``complete_text`` — transcript-level understanding (key messages, takeaway) via ``/api/chat``.
* ``critique_audio`` — **audio-native listening** when the model can hear (verified with
  ``gemma4:12b-it-qat`` on Ollama 0.34: the clip is passed in the message's ``images`` list, which
  is how that Ollama build routes audio to the model). The caller passes a bounded excerpt.
* ``transcribe`` — the offline faster-whisper path (Ollama serves no verbatim ASR).

Security: the URL is vetted by :func:`audel.netguard.assert_backend_url` (a private address is
reachable only for a host the operator listed as trusted; metadata/link-local never), requests
refuse redirects, responses are size-capped, and the excerpt sent is capped in bytes.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

from ..config import Settings
from ..errors import BackendAuthError, BackendError, UnsafeSourceError
from ..netguard import assert_backend_url, post_json
from .base import Transcript
from .local import LocalBackend

_MAX_RESPONSE_BYTES = 1_000_000
_MAX_RESPONSE_CHARS = 20_000
_MAX_AUDIO_BYTES = 4_000_000  # ~2 min of 16 kHz mono PCM; excerpts are far smaller


class LocalLLMBackend:
    name = "ollama-local"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def available(self) -> bool:
        return bool(self._settings.local_llm_url)

    @property
    def hears_audio(self) -> bool:
        return self.available() and self._settings.local_llm_audio

    def _url(self) -> str:
        base = self._settings.local_llm_url
        if not base:
            raise BackendAuthError("no local LLM configured (set AUDEL_LOCAL_LLM_URL)")
        url = base.rstrip("/") + "/api/chat"
        assert_backend_url(url, self._settings.trusted_backend_hosts, self._settings)
        return url

    async def transcribe(self, audio_path: str, *, language: str | None = None,
                         stream: int = 0) -> Transcript:
        return await LocalBackend(self._settings).transcribe(audio_path, language=language,
                                                             stream=stream)

    async def complete_text(self, system: str, user: str) -> str:
        url = self._url()
        body = {"model": self._settings.local_llm_model, "stream": False,
                "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        return await asyncio.to_thread(self._chat, url, body)

    async def critique_audio(self, audio_path: str, prompt: str) -> str:
        if not self.hears_audio:
            return ""
        url = self._url()
        p = Path(audio_path)
        size = p.stat().st_size
        if size > _MAX_AUDIO_BYTES:
            raise UnsafeSourceError(f"audio excerpt is {size} bytes, over the {_MAX_AUDIO_BYTES} cap")
        b64 = base64.b64encode(p.read_bytes()).decode("ascii")
        body = {"model": self._settings.local_llm_model, "stream": False, "format": "json",
                "options": {"temperature": 0},
                "messages": [{"role": "user", "content": prompt, "images": [b64]}]}
        return await asyncio.to_thread(self._chat, url, body)

    def _chat(self, url: str, body: dict) -> str:
        try:
            data = post_json(url, body, timeout_s=self._settings.local_llm_timeout_s,
                             max_bytes=_MAX_RESPONSE_BYTES)
        except Exception as e:  # noqa: BLE001 - normalize transport/parse errors
            raise BackendError(f"local LLM request failed: {type(e).__name__}") from e
        if data.get("error"):
            raise BackendError("local LLM returned an error")
        msg = data.get("message")
        content = msg.get("content") if isinstance(msg, dict) else ""
        return str(content or "")[:_MAX_RESPONSE_CHARS]
