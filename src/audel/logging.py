"""Lightweight logging setup.

Audel NEVER logs resolved credentials. Every key the config resolves is registered here and
scrubbed by value from any log line; a shape-based regex is a heuristic backstop. Mirrors
AgentVision's scrubber so the trio shares one secret-handling discipline.
"""

from __future__ import annotations

import logging
import os
import re

# Redaction must stay LINEAR on hostile input: logged text includes unauthenticated request lines,
# written on the event loop. So there is no general "find a secret anywhere" regex. Instead:
#   1. split the text ONCE into runs of URL/token characters (one class, no alternation);
#   2. test each run with substring checks and FIXED-length patterns only, on the raw run and on
#      its percent-decoded forms; a run that holds a credential is redacted IN ITS ORIGINAL form,
#      so decoding never rewrites (or forges) the rest of the line;
#   3. three context patterns (key=value, Authorization:, Bearer) that start only at a keyword
#      and use possessive quantifiers, so a failed attempt never rescans.
_RUN = re.compile(r"[A-Za-z0-9_.~+/=%\-]++")
_TOKCH = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_MINTED = re.compile(r"audel_[A-Za-z0-9_\-]{43}_[a-z2-7]{8}", re.IGNORECASE)        # fixed length
_PROVIDER = re.compile(r"(?<![A-Za-z0-9])(?:sk-|AIza)[A-Za-z0-9_\-]{8}", re.IGNORECASE)
_KV = re.compile(
    r"((?:api[_-]?key|token|secret|password|passwd)[\"'`]?+[ \t]*+[:=][ \t]*+[\"'`]?+)"
    r"[A-Za-z0-9._~+/=%\-]{6,}+", re.IGNORECASE)
_AUTHZ = re.compile(r"(authorization[\"'`]?+[ \t]*+[:=][ \t]*+[\"'`]?+)[^\s\"'`,;]++"
                    r"(?:[ \t]++[^\s\"'`,;]++)?+", re.IGNORECASE)
_BEARER = re.compile(r"(bearer\s++)[A-Za-z0-9._~+/=\-]{8,}+", re.IGNORECASE)
_MAX_UNQUOTE = 5


def _jwt_in(run: str) -> bool:
    """A JWT (base64url ``{"``/``{ "`` header) inside a run, found in linear time."""
    low = run.lower()
    if "eyj" not in low and "eya" not in low:
        return False
    segs = run.split(".")
    for i in range(len(segs) - 2):
        seg = segs[i]
        j = len(seg)
        while j > 0 and seg[j - 1] in _TOKCH:   # the maximal token-character tail
            j -= 1
        tail = seg[j:].lower()
        k = min((x for x in (tail.find("eyj"), tail.find("eya")) if x >= 0), default=-1)
        if k < 0 or len(tail) - k < 11:
            continue
        mid, last = segs[i + 1], segs[i + 2]
        if len(mid) >= 2 and all(c in _TOKCH for c in mid) and len(last) >= 2 \
                and last[0] in _TOKCH and last[1] in _TOKCH:
            return True
    return False


def _credential(run: str) -> bool:
    if any(sec in run for sec in _KNOWN_SECRETS):
        return True
    low = run.lower()
    return bool(("audel" in low and _MINTED.search(run))
                or (("sk-" in low or "aiza" in low) and _PROVIDER.search(run))
                or _jwt_in(run))


def _run_holds_secret(run: str) -> bool:
    if _credential(run):
        return True
    if "%" in run:  # a credential misplaced in a URL may be percent-encoded, even repeatedly
        from urllib.parse import unquote

        cur = run
        for _ in range(_MAX_UNQUOTE):
            nxt = unquote(cur)
            if nxt == cur:
                break
            cur = nxt
            if _credential(cur):
                return True
    return False


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
    """Redact known secret values (and shape-matched ones) from arbitrary text, in linear time.

    Value-based redaction is sound (config registers every key it resolves); the shapes are a
    backstop for credentials stored only as hashes (tenant tokens) or never seen (JWTs). A run
    holding a credential is replaced whole, in its original encoding, so the rest of the line
    is left exactly as it was. Used by the workspace so a credential can never reach disk via
    persisted session state, and by the log filter below."""
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):  # longest first
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    text = _AUTHZ.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = _BEARER.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = _KV.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return _RUN.sub(lambda m: "[REDACTED]" if _run_holds_secret(m.group()) else m.group(), text)


_MAX_LOG_TEXT = 8192  # log text scrubbed per field; a request line can be arbitrarily long


def _clip(text: str) -> str:
    """Bound what one log field can cost to scrub. Cut back to a run boundary so a credential
    straddling the cut is dropped whole, never left half-visible."""
    if len(text) <= _MAX_LOG_TEXT:
        return text
    cut = _MAX_LOG_TEXT
    while cut > 0 and _RUN.fullmatch(text[cut - 1]):
        cut -= 1
    return text[:cut] + f"...[{len(text) - cut} chars truncated]"


class _SecretScrubber(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # Scrub the template and each argument IN PLACE, keeping the args' shape: formatters such
        # as uvicorn's access formatter unpack a fixed number of args.
        try:
            if isinstance(record.msg, str):
                record.msg = scrub_text(_clip(record.msg))
            if isinstance(record.args, tuple):
                record.args = tuple(scrub_text(_clip(a)) if isinstance(a, str) else a
                                    for a in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: scrub_text(_clip(v)) if isinstance(v, str) else v
                               for k, v in record.args.items()}
            full = record.getMessage()
        except Exception:
            return True
        clean = scrub_text(_clip(full))
        if clean != full:  # a secret spanning template + argument: flatten
            record.msg, record.args = clean, ()
        if record.stack_info:
            record.stack_info = scrub_text(record.stack_info)
        if record.exc_info:
            # Tracebacks can carry secrets too (exception text, locals in messages).
            import traceback

            record.exc_text = scrub_text("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        return True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a namespaced logger under ``audel`` with the secret scrubber attached."""
    base = logging.getLogger(_LOGGER_NAME)
    for h in base.handlers:  # a host app configured it first: still scrub what it prints
        if not any(isinstance(f, _SecretScrubber) for f in h.filters):
            h.addFilter(_SecretScrubber())
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
    # Records from asyncio and other libraries reach the root logger: give it a scrubbed handler
    # too (otherwise they fall through to logging.lastResort, unfiltered).
    cfg["root"] = {"handlers": ["default"], "level": "WARNING"}
    return cfg
