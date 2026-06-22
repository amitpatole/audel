"""Audel audio backends (ASR / LLM critique)."""

from __future__ import annotations

from .base import AudioBackend, Segment, Transcript
from .local import LocalBackend
from .registry import resolve_backend

__all__ = ["AudioBackend", "Transcript", "Segment", "LocalBackend", "resolve_backend"]
