"""Ollama Cloud text-critique backend — the default ``analyze`` LLM (flat-rate, OpenAI-compatible).

Implements ``complete_text`` (transcript critique / non-deterministic claim grading) against
``https://ollama.com/v1``. It cannot hear raw audio (verified: the API rejects audio input), so
``critique_audio`` returns ``""``; transcription delegates to the offline local ASR. The endpoint
URL is SSRF-vetted and responses are size-capped. Egress happens ONLY here (the ``check`` path
never constructs this backend).
"""

from __future__ import annotations

import asyncio

from ..config import Settings
from ..errors import BackendAuthError, BackendError
from ..logging import get_logger
from ..netguard import assert_backend_url, post_json
from .base import Transcript
from .local import LocalBackend

_log = get_logger("ollama")
_MAX_RESPONSE_CHARS = 20_000
_TIMEOUT_S = 60.0
_MAX_RESPONSE_BYTES = 1_000_000


class OllamaBackend:
    name = "ollama"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def available(self) -> bool:
        return bool(self._settings.key_for("ollama"))

    async def transcribe(self, audio_path: str, *, language: str | None = None) -> Transcript:
        # Ollama does no ASR; use the offline local transcriber for grounding.
        return await LocalBackend(self._settings).transcribe(audio_path, language=language)

    async def complete_text(self, system: str, user: str) -> str:
        key = self._settings.key_for("ollama")
        if not key:
            raise BackendAuthError("no Ollama key (set OLLAMA_API_KEY or ~/.config/ollama/key)")
        url = self._settings.ollama_base_url.rstrip("/") + "/chat/completions"
        from urllib.parse import urlsplit

        from ..errors import UnsafeSourceError

        u = urlsplit(url)
        if u.scheme != "https":
            raise UnsafeSourceError("the Ollama cloud key is only ever sent over https")
        from ..netguard import canonical_host

        if canonical_host(u.hostname) in {canonical_host(h)
                                          for h in self._settings.trusted_backend_hosts}:
            raise UnsafeSourceError("the Ollama cloud key is never sent to an on-prem host; "
                                    "use the keyless ollama-local backend for LAN servers")
        assert_backend_url(url, self._settings.trusted_backend_hosts, self._settings)  # SSRF: vet the endpoint
        return await asyncio.to_thread(self._post, url, key, system, user)

    async def critique_audio(self, audio_path: str, prompt: str) -> str:
        return ""  # Ollama's API cannot ingest audio

    def _post(self, url: str, key: str, system: str, user: str) -> str:
        body = {
            "model": self._settings.ollama_model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": 700,
            "temperature": 0,
        }
        try:
            # No redirects, bounded read: a misbehaving endpoint can neither bounce the request to
            # an internal address nor make us buffer an unbounded body.
            data = post_json(url, body, headers={"Authorization": f"Bearer {key}"},
                             timeout_s=_TIMEOUT_S, max_bytes=_MAX_RESPONSE_BYTES)
        except Exception as e:  # noqa: BLE001 - normalize transport/parse errors
            raise BackendError(f"Ollama request failed: {type(e).__name__}") from e
        try:
            content = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            content = ""
        return str(content)[:_MAX_RESPONSE_CHARS]
