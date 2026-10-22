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
    r"(audel_[A-Za-z0-9_\-]{43}_[a-z2-7]{8}"                       # minted Audel tokens, anywhere
    r"|sk-[A-Za-z0-9_\-]{8,}|AIza[A-Za-z0-9_\-]{8,}"
    r"|[Bb]earer\s+[A-Za-z0-9._~+/=\-]{8,}"
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
    # Longest first: a secret containing a shorter registered secret must be redacted whole.
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    if _SECRET_RE.search(text):
        text = _SECRET_RE.sub("[REDACTED]", text)
    return text


class _SecretScrubber(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # Scrub the template and each argument IN PLACE, keeping the args' shape: formatters such
        # as uvicorn's access formatter unpack a fixed number of args.
        try:
            if isinstance(record.msg, str):
                record.msg = scrub_text(record.msg)
            if isinstance(record.args, tuple):
                record.args = tuple(scrub_text(a) if isinstance(a, str) else a for a in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: scrub_text(v) if isinstance(v, str) else v
                               for k, v in record.args.items()}
            full = record.getMessage()
        except Exception:
            return True
        if scrub_text(full) != full:  # a secret spanning template + argument: flatten
            record.msg, record.args = scrub_text(full), ()
        if record.exc_info:
            # Tracebacks can carry secrets too (exception text, locals in messages).
            import traceback

            record.exc_text = scrub_text("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
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


def scrub_logger(name: str) -> None:
    """Attach the secret scrubber to another library's logger (e.g. uvicorn's), whose handlers
    would otherwise print exception text unfiltered."""
    lg = logging.getLogger(name)
    if not any(isinstance(f, _SecretScrubber) for f in lg.filters):
        lg.addFilter(_SecretScrubber())
    for h in lg.handlers:
        if not any(isinstance(f, _SecretScrubber) for f in h.filters):
            h.addFilter(_SecretScrubber())


def uvicorn_log_config() -> dict:
    """uvicorn's own logging config with the scrubber attached to EVERY handler (uvicorn rebuilds
    its handlers at startup, so filters added beforehand would be lost)."""
    import copy

    from uvicorn.config import LOGGING_CONFIG

    cfg = copy.deepcopy(LOGGING_CONFIG)
    cfg.setdefault("filters", {})["audel_scrub"] = {"()": "audel.logging._SecretScrubber"}
    for h in cfg.get("handlers", {}).values():
        h.setdefault("filters", []).append("audel_scrub")
    return cfg
