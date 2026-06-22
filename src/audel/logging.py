"""Lightweight logging setup.

Audel NEVER logs resolved credentials. Every key the config resolves is registered here and
scrubbed by value from any log line; a shape-based regex is a heuristic backstop. Mirrors
AgentVision's scrubber so the trio shares one secret-handling discipline.
"""

from __future__ import annotations

import logging
import os
import re

_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_\-]{8,}|AIza[A-Za-z0-9_\-]{8,}"
    r"|[Bb]earer\s+[A-Za-z0-9._\-]{8,}"
    r"|(?:api[_-]?key|token|secret|password)[\"'`:=\s]+[A-Za-z0-9._\-]{6,})",
    re.IGNORECASE,
)

_LOGGER_NAME = "audel"

# Exact secret VALUES resolved at runtime (provider keys, the API token). Value-based scrubbing
# is sound where the regex is only a backstop; config registers every key it resolves.
_KNOWN_SECRETS: set[str] = set()


def register_secret(value: str | None) -> None:
    """Register a resolved secret value so it is redacted from any log line. No-op for short or
    empty values (avoids redacting innocuous substrings)."""
    if value and len(value) >= 6:
        _KNOWN_SECRETS.add(value)


def scrub_text(text: str) -> str:
    """Redact known secret values (and shape-matched ones) from arbitrary text.

    Value-based redaction is sound (config registers every key it resolves); the regex is a
    backstop. Used by the workspace so a credential can never reach disk via persisted session
    state, and by the log filter below."""
    for secret in _KNOWN_SECRETS:
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    if _SECRET_RE.search(text):
        text = _SECRET_RE.sub("[REDACTED]", text)
    return text


class _SecretScrubber(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            msg = record.getMessage()
        except Exception:
            return True
        scrubbed = scrub_text(msg)
        if scrubbed != msg:
            record.msg = scrubbed
            record.args = ()
        return True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a namespaced logger under ``audel`` with the secret scrubber attached."""
    base = logging.getLogger(_LOGGER_NAME)
    if not base.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s audel: %(message)s"))
        handler.addFilter(_SecretScrubber())
        base.addHandler(handler)
        level = os.environ.get("AUDEL_LOG_LEVEL", "WARNING").upper()
        base.setLevel(getattr(logging, level, logging.WARNING))
        base.propagate = False
    if name:
        return base.getChild(name)
    return base
