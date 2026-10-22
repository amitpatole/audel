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
#   1. split the text ONCE into runs of URL/token characters of credential length (11+;
#      registered secret values are matched by value before this, encoded or not);
#   2. test each run with substring checks and FIXED-length patterns only, on the raw run and on
#      its percent-decoded forms (within a per-call decode budget); a run that holds a credential
#      is redacted IN ITS ORIGINAL form, so decoding never rewrites the rest of the line;
#   3. context patterns (key=value, Authorization:, Bearer) that start only at a keyword and use
#      possessive quantifiers, so a failed attempt never rescans.
_RUN = re.compile(r"[A-Za-z0-9_.~+/=%\-]{11,}+")  # the shortest credential shape is 11
_RUN_CH = re.compile(r"[A-Za-z0-9_.~+/=%\-]")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_TOKCH = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_MINTED = re.compile(r"audel_[A-Za-z0-9_\-]{43}_[a-z2-7]{8}", re.IGNORECASE)        # fixed length
_PROVIDER = re.compile(r"(?<![A-Za-z0-9])(?:sk-|AIza)[A-Za-z0-9_\-]{8}", re.IGNORECASE)
# Keys whose value is a credential whatever it looks like (when assigned), and the weaker
# ``token`` / ``key`` family, whose ``key: value`` prose is redacted only for credential-like values.
_STRONG_KEYS = (r"password|passwd|passphrase|secret|client[_-]?secret|api[_-]?key|apikey"
                r"|access[_-]?key|private[_-]?key|credentials?|signature"
                # short keys only as whole words (not "compass:", "bypass=", "design:")
                r"|(?-i:(?<![a-z]))(?:pwd|pass|sig)")
_KV = re.compile(
    r"((?:" + _STRONG_KEYS + r"|token)([\"'`]?+)[ \t]*+([:=])[ \t]*+[\"'`]?+)"
    r"([^\s&\"'`,;<>\\]{6,}+)", re.IGNORECASE)
_AUTHZ = re.compile(r"(authorization[\"'`]?+[ \t]*+[:=][ \t]*+[\"'`]?+)"
                    r"((?:[A-Za-z][A-Za-z0-9_-]{1,31}\s++)?+[^\s\"'`,;\\]++)", re.IGNORECASE)
_BEARER = re.compile(r"(bearer\s++)([A-Za-z0-9._~+/=\-]{8,}+)", re.IGNORECASE)
_SECRETISH = frozenset("0123456789._~+/=-%")
_STRONG_RE = re.compile(_STRONG_KEYS, re.IGNORECASE)


def _looks_secret(value: str) -> bool:
    """A word ("authentication", "expired") is not a credential; a token has a digit or a
    token separator, mixes case inside it, or is long."""
    if len(value) >= 24 or any(c in _SECRETISH for c in value):
        return True
    return len(value) >= 12 and any(c.isupper() for c in value[1:]) and \
        any(c.islower() for c in value)


_MAX_UNQUOTE = 5
_DECODE_BUDGET = 256  # percent-decodings per scrub call; past it, encoded runs fail closed
_JWT_HDR = re.compile(r'\{\s*"[^"\\]{1,32}"\s*:')
_JWT_PREFIX = ("eyj", "eya", "ewo", "ew0", "ewk")  # base64url of '{"', '{ "', '{\n', '{\r', '{\t'
_JWT_TRIES = 16
_JWT_ANY = re.compile(r"e(?:y[ja]|w[o0k])", re.IGNORECASE)


def _jwt_header(chunk: str) -> bool:
    """The candidate header really is base64url JSON (``{"alg":`` ...), not a word that happens to
    contain "eyJ" (``honeyJar``, ``keyArchive``). Fixed cost: at most 24 characters decoded."""
    import base64
    import binascii

    chunk = chunk[: len(chunk) // 4 * 4]
    try:
        dec = base64.urlsafe_b64decode(chunk).decode("latin-1")
    except (binascii.Error, ValueError):
        return False
    return _JWT_HDR.match(dec) is not None


def _jwt_in(run: str) -> bool:
    """A JWT inside a run, in linear time: every header candidate in a segment's token-character
    tail is tried (bounded), so text glued in front of a JWT can't hide it."""
    if run.count(".") < 2 or _JWT_ANY.search(run) is None:
        return False
    segs = run.split(".")
    for i in range(len(segs) - 2):
        mid, last = segs[i + 1], segs[i + 2]
        if not (len(mid) >= 2 and all(c in _TOKCH for c in mid) and len(last) >= 2
                and last[0] in _TOKCH and last[1] in _TOKCH):
            continue
        seg = segs[i]
        j = len(seg)
        while j > 0 and seg[j - 1] in _TOKCH:   # the maximal token-character tail
            j -= 1
        tail = seg[j:]
        low_t = tail.lower()
        tries = 0
        for k in range(len(tail) - 1):
            if low_t[k:k + 2] in ("ey", "ew") and low_t[k:k + 3] in _JWT_PREFIX:
                tries += 1
                if len(tail) - k >= 8 and _jwt_header(tail[k:k + 24]):
                    return True
                if tries >= _JWT_TRIES:
                    break
    return False


def _credential(run: str) -> bool:
    if _KNOWN_RE is not None and _KNOWN_RE.search(run):
        return True
    low = run.lower()
    return bool(("audel" in low and _MINTED.search(run))
                or (("sk-" in low or "aiza" in low) and _PROVIDER.search(run))
                or _jwt_in(run))


def _run_holds_secret(run: str, budget: list[int]) -> bool:
    if _credential(run):
        return True
    if "%" in run and _PCT.search(run):  # a credential may be percent-encoded, even repeatedly
        cur = run
        for _ in range(_MAX_UNQUOTE):
            if budget[0] <= 0:
                return True  # decode budget spent: an encoded run fails closed (redacted)
            budget[0] -= 1
            nxt = unquote(cur)
            if nxt == cur:
                break
            cur = nxt
            if _credential(cur):
                return True
    return False


from urllib.parse import unquote  # noqa: E402 - kept beside its only use

_LOGGER_NAME = "audel"

# Exact secret VALUES resolved at runtime (provider keys, the API token). Value-based scrubbing
# is sound where the regex is only a backstop; config registers every key it resolves.
_KNOWN_SECRETS: set[str] = set()
_KNOWN_RE: re.Pattern | None = None  # one compiled alternation: a C-speed check per run


def register_secret(value: str | None) -> None:
    """Register a resolved secret value so it is redacted from any log line. No-op for short or
    empty values (avoids redacting innocuous substrings)."""
    global _KNOWN_RE
    if value and len(value) >= 6 and value not in _KNOWN_SECRETS:
        _KNOWN_SECRETS.add(value)
        _KNOWN_RE = re.compile("|".join(re.escape(v) for v in
                                        sorted(_KNOWN_SECRETS, key=len, reverse=True)))


def _kv(m: re.Match) -> str:
    key, quote, sep, value = m.group(1), m.group(2), m.group(3), m.group(4)
    # An assignment (``=``), a quoted JSON/YAML key, or a strong key is a credential whatever
    # the value looks like; ``token: expired`` prose is redacted only for credential-like values.
    explicit = sep == "=" or bool(quote) or _STRONG_RE.search(key) is not None
    return key + "[REDACTED]" if explicit or _looks_secret(value) else m.group()


def scrub_text(text: str) -> str:
    """Redact known secret values (and shape-matched ones) from arbitrary text, in linear time.

    Value-based redaction is sound (config registers every key it resolves); the shapes are a
    backstop for credentials stored only as hashes (tenant tokens) or never seen (JWTs). A run
    holding a credential is replaced whole, in its original encoding, so the rest of the line
    is left exactly as it was. Used by the workspace so a credential can never reach disk via
    persisted session state, and by the log filter below."""
    text = _AUTHZ.sub(lambda m: m.group(1) + "[REDACTED]", _scrub_shapes(text))
    text = _BEARER.sub(lambda m: m.group(1) + "[REDACTED]" if _looks_secret(m.group(2))
                       else m.group(), text)
    return _KV.sub(_kv, text)


def _scrub_shapes(text: str) -> str:
    """Registered values and credential-shaped runs only (no keyword context)."""
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):  # longest first
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    budget = [_DECODE_BUDGET]
    return _RUN.sub(lambda m: "[REDACTED]" if _run_holds_secret(m.group(), budget)
                    else m.group(), text)


_MAX_LOG_TEXT = 8192  # log text scrubbed per field; a request line can be arbitrarily long


def _clip(text: str) -> str:
    """Bound what one log field can cost to scrub. Cut back to a run boundary so a credential
    straddling the cut is dropped whole, never left half-visible."""
    if len(text) <= _MAX_LOG_TEXT:
        return text
    cut = _MAX_LOG_TEXT
    while cut > 0 and _RUN_CH.fullmatch(text[cut - 1]):
        cut -= 1
    if cut < 64:
        # One run fills the whole window: keep its scrubbed opening so the field isn't blanked
        # (a credential inside the window is redacted whole).
        head = _scrub_shapes(text[:_MAX_LOG_TEXT])
        return head[:64] + f"...[{len(text) - 64} chars truncated]"
    return text[:cut] + f"...[{len(text) - cut} chars truncated]"


# Records whose formatter unpacks a fixed argument tuple. Their templates are fixed (uvicorn's),
# so each argument is a separate field: scrubbed once, in place.
_TUPLE_FORMATTED = ("uvicorn.access",)


class _SecretScrubber(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if record.name in _TUPLE_FORMATTED and isinstance(record.args, tuple) \
                and isinstance(record.msg, str):
            record.args = tuple(scrub_text(_clip(a)) if isinstance(a, str) else a
                                for a in record.args)
        else:
            # Everything else: render first (``str()`` of any message or argument object, so an
            # exception or a dict is covered), then scrub the whole line once and flatten. A
            # keyword in the template and its credential in an argument are scrubbed together.
            try:
                full = record.getMessage()
            except Exception:  # noqa: BLE001 - a broken template must not print raw arguments
                full = f"{record.msg!s} [log arguments withheld: the message failed to format]"
            record.msg, record.args = scrub_text(_clip(full)), ()
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
