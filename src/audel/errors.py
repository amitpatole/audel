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


class EgressDeniedError(UnsafeSourceError):
    """The egress policy (``AUDEL_EGRESS``) forbids this network call."""


_PATHLIKE = None
_SENSITIVE: set[str] = set()


def register_sensitive_path(path) -> None:
    """Register a server path (workspace, temp dir) that must never reach a remote caller. It is
    replaced EXACTLY before the pattern pass, so a path containing spaces or commas cannot leak
    partially."""
    v = str(path or "").rstrip("/\\")
    if len(v) >= 2:
        _SENSITIVE.add(v)


def sanitize_message(msg: str, *, limit: int = 300) -> str:
    """Strip anything that looks like a filesystem path, server temp-file name, address or
    pointer from a message that may reach a remote caller (tool stderr echoes input paths).
    Keeps the human-readable reason."""
    import re
    import tempfile

    global _PATHLIKE
    if _PATHLIKE is None:
        _PATHLIKE = re.compile(
            r"[A-Za-z]:\\[^\s'\"]+"                                   # Windows paths
            r"|(?:%2[fF][^\s'\"%]*)+"                                   # percent-encoded paths
            r"|(?:[A-Za-z]:)?(?:/[^\s'\"():,]+){2,}"                     # POSIX paths (2+ parts)
            r"|/[^\s'\"():,]+\.[A-Za-z0-9]{1,8}"                         # /file.ext
            r"|\b(?:upload|ingest)_[0-9a-f]{8,}[\w.]*"                     # server temp names
            r"|\baudel-[a-z]+-[\w.]+"
            r"|\[[0-9A-Fa-f:.]{2,}\](?::\d+)?"                           # [IPv6]:port
            r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")                    # IPv4[:port]
    text = str(msg)
    roots = set(_SENSITIVE)
    roots.add(tempfile.gettempdir().rstrip("/\\"))
    for root in sorted(roots, key=len, reverse=True):
        if root:
            text = text.replace(root, "<path>")
    text = re.sub(r"\s*@\s*0x[0-9a-fA-F]+", "", text)                  # ffmpeg context pointers
    return _PATHLIKE.sub("<path>", text)[:limit]
