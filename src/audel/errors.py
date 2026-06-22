"""Audel exception hierarchy.

Mirrors AgentVision's hierarchy so the trio raises structurally-similar errors; ``UnsafeSourceError``
is the guard-failure signal (oversized/malformed media, path traversal, SSRF) and ``DecodeError``
covers ffmpeg/codec failures on untrusted input.
"""

from __future__ import annotations


class AudelError(Exception):
    """Base class for all Audel errors."""


class UnsafeSourceError(AudelError):
    """A source was refused by a guard (size/duration cap, path traversal, disallowed scheme/host)."""


class DecodeError(AudelError):
    """Decoding the media failed (corrupt container, unsupported/mismatched codec, empty stream)."""


class MissingDependencyError(AudelError):
    """A required optional dependency (ffmpeg, faster-whisper, torch/CLAP, Playwright) is absent."""


class BackendError(AudelError):
    """A grading backend (ASR/audio-LLM/text-LLM) failed."""


class BackendAuthError(BackendError):
    """A backend was selected but its credential is missing or rejected (fail closed, don't downgrade)."""


class ConfigError(AudelError):
    """Invalid or inconsistent configuration."""
