"""Backend resolution: built-in ``local`` + third-party plugins via the ``audel.backends`` entry
-point group (so ``audel-backend-foo`` ships an ``AudioBackend`` that ``backend="foo"`` resolves)."""

from __future__ import annotations

from ..config import Settings
from ..errors import ConfigError
from .base import AudioBackend
from .local import LocalBackend


def resolve_backend(name: str | None, settings: Settings | None = None) -> AudioBackend:
    settings = settings or Settings()
    name = name or settings.audio_backend or "local"
    if name == "local":
        return LocalBackend(settings)
    if name == "ollama":
        from .ollama import OllamaBackend

        return OllamaBackend(settings)
    if name == "anthropic":
        from .anthropic_backend import AnthropicBackend

        return AnthropicBackend(settings)
    if name in ("gemini-audio", "gemini_audio"):
        from .gemini_audio import GeminiAudioBackend

        return GeminiAudioBackend(settings)

    # Third-party backends registered under the `audel.backends` entry-point group (py>=3.11
    # supports the `group=` selection form directly).
    from importlib.metadata import entry_points

    for ep in entry_points(group="audel.backends"):
        if ep.name == name:
            factory = ep.load()
            return factory(settings) if callable(factory) else factory
    raise ConfigError(f"unknown audio backend {name!r} (no built-in or plugin provides it)")
