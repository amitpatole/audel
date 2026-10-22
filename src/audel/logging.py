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
# Real provider-key shapes, case-sensitive (so "aizawa-studios" or "sk-broadband.co.kr" are names).
_PROVIDER = re.compile(r"(?<![A-Za-z0-9])(?:AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9_\-]{20,}+"
                       r"|gh[pousr]_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_\-]{20}"
                       r"|xox[abprs]-[A-Za-z0-9-]{10,}+|AKIA[0-9A-Z]{16})")
# Keys whose value is a credential whatever it looks like when assigned or quoted. Short keys
# (pwd/pass/sig) only as whole words or a camelCase suffix (not "compass:", "bypass=", "COMPASS:").
_STRONG_KEYS = (r"password|passwd|passphrase|secret|client[_-]?secret|api[_-]?key|apikey"
                r"|access[_-]?key|private[_-]?key|auth[_-]?token|x-api-key"
                r"|(?<![A-Za-z])(?:pwd|pass|sig)(?![A-Za-z])|(?-i:(?<=[a-z])(?:Pwd|Pass|Sig))")
# Weaker keys: ``key: value`` prose after them is redacted only for credential-like values.
_WEAK_KEYS = r"token|signature|credentials?"
_KEYS = "(?:" + _STRONG_KEYS + "|" + _WEAK_KEYS + ")"
# Unquoted value: up to whitespace / separators.
_KEY_START = r"(?=[pPsScCaAxXtT])"  # every key starts with one of these: skip other positions fast
_KV = re.compile(
    _KEY_START + r"(" + _KEYS + r"([\"'`]?+)[ \t]*+([:=])[ \t]*+[\"'`]?+)"
    r"([^\s&\"'`]{1,4096}+)", re.IGNORECASE)
# Quoted value (JSON / Python repr / header tuples), redacted up to its closing quote, spaces and
# all: ``"password": "correct horse"``, ``{'password': b'x'}``, ``('x-api-key', 'abc')``.
_KVQ = re.compile(
    _KEY_START + r"((?:" + _KEYS + r"|authorization|cookie|set-cookie)[\"'`]?+[ \t]*+[:=][ \t]*+b?([\"'`]))"
    r"((?:[^\"'`\n\\]|\\.|(?!\2)[\"'`]){4,4096}+)(?=\2)",
    re.IGNORECASE)
_HEADER_KEYS = (r"(?:proxy-)?authorization|set-cookie|cookie|x-api-key|api-key|apikey|x-auth-token"
                r"|x-amz-security-token|x-goog-api-key|private-token")
# Header tuples: ``(b'authorization', b'Basic ...')``, ``('x-api-key', 'abc')``. Only in a tuple
# or list opening, so a bare "pass" in ``['pass', 'warn']`` doesn't redact its neighbour.
_KVT = re.compile(
    r"([\(\[][ \t]*+b?[\"'](?:" + _HEADER_KEYS + r")[\"'][ \t]*+,"
    r"[ \t]*+b?([\"']))((?:[^\"'\n\\]|\\.|(?!\2)[\"']){1,4096}+)(?=\2)", re.IGNORECASE)
_MAX_KEYWORDS = 128   # keyword positions matched with the patterns; beyond, a linear fallback
_KEY_BACK = 8         # a key starts at most this far before its hint ("client_" + "secret")
_KV_HINT = ("pass", "pwd", "secret", "key", "credential", "signature", "sig", "token",
            "authorization", "cookie")
_AUTHZ = re.compile(r"(authorization([\"'`]?+)[ \t]*+([:=])[ \t]*+([\"'`]?+))"
                    r"((?:[A-Za-z][A-Za-z0-9_-]{1,31}\s++)?+[^\s\"'`,;\\]++)", re.IGNORECASE)
_BEARER = re.compile(r"(bearer\s++)([A-Za-z0-9._~+/=\-]{8,}+)", re.IGNORECASE)
_SECRETISH = frozenset("0123456789.~+/=%")  # not "_" or "-": snake_case / kebab-case are words
# Keys explicit even in ``key: value`` prose. The short keys, "signature" and "credential" are
# not: "VERDICT PASS: loudness_ok", "credential: missing" are prose unless the value looks secret.
_EXPLICIT_RE = re.compile(r"password|passwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key"
                          r"|private[_-]?key|auth[_-]?token|x-api-key", re.IGNORECASE)


def _looks_secret(value: str) -> bool:
    """A word ("authentication", "expired") is not a credential; a token has a digit or a
    token separator, mixes case inside it, or is long."""
    if len(value) >= 24 or any(c in _SECRETISH for c in value):
        return True
    return len(value) >= 12 and any(c.isupper() for c in value[1:]) and \
        any(c.islower() for c in value)


_MAX_UNQUOTE = 5
_DECODE_CHARS = 2 * 8192   # characters percent-decoded per scrub call; past it, fail closed
_HEADER_TRIES = 64         # JWT header decodes per scrub call; past it, candidates fail closed
_JWT_HDR = re.compile(r'\{\s*"[ !#-\[\]-~]{1,32}"\s*:')  # printable key, up to 32 chars
_JWT_PREFIX = ("eyj", "eya", "ewo", "ew0", "ewk")  # base64url of '{"', '{ "', '{\n', '{\r', '{\t'
_JWT_ANY = re.compile(r"e(?:y[ja]|w[o0k])", re.IGNORECASE)


class _Budget:
    """Per-call work budgets: hostile text can't cost more than a bounded amount of decoding."""

    __slots__ = ("chars", "headers")

    def __init__(self) -> None:
        self.chars, self.headers = _DECODE_CHARS, _HEADER_TRIES


def _jwt_header(chunk: str) -> bool:
    """The candidate header really is base64url JSON (``{"alg":`` ...), not a word that happens to
    contain "eyJ" (``honeyJar``, ``keyArchive``). Fixed cost: at most 56 characters decoded,
    enough for a first key of up to 32 characters."""
    chunk = chunk[: len(chunk) // 4 * 4]
    try:
        dec = base64.urlsafe_b64decode(chunk).decode("latin-1")
    except (binascii.Error, ValueError):
        return False
    return _JWT_HDR.match(dec) is not None


def _jwt_in(run: str, budget: _Budget) -> bool:
    """A JWT inside a run, in linear time: every header candidate in a segment's token-character
    tail is tried, within the call's header budget (spent: fail closed), so text glued in front of
    a JWT can't hide it and floods of candidates can't make scrubbing costly."""
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
        for m in _JWT_ANY.finditer(low_t):
            k = m.start()
            if len(tail) - k < 8:
                break
            if budget.headers <= 0:
                return True  # header budget spent: a remaining candidate fails closed
            budget.headers -= 1
            if _jwt_header(tail[k:k + 56]):
                return True
    return False


def _credential(run: str, budget: _Budget, *, decoded: bool = False) -> bool:
    # Registered values in the RAW text were already replaced by value; only decoded forms
    # need the check here.
    if decoded and any(sec in run for sec in _KNOWN_SECRETS):
        return True
    low = run.lower()
    return bool(("audel" in low and _MINTED.search(run))
                or (any(p in low for p in ("sk-", "aiza", "gh", "glpat-", "xox", "akia"))
                    and _PROVIDER.search(run))
                or _jwt_in(run, budget))


def _run_holds_secret(run: str, budget: _Budget) -> bool:
    if _credential(run, budget):
        return True
    cur = run
    for _ in range(_MAX_UNQUOTE):  # a credential may be percent-encoded, even repeatedly
        if "%" not in cur or not _PCT.search(cur):
            break  # nothing left to decode: no charge
        if budget.chars < len(cur):
            return True  # decode budget spent: an encoded run fails closed (redacted)
        budget.chars -= len(cur)
        cur = unquote(cur)
        if _credential(cur, budget, decoded=True):
            return True
    return False


import base64  # noqa: E402
import binascii  # noqa: E402
from urllib.parse import unquote  # noqa: E402

_LOGGER_NAME = "audel"

# Exact secret VALUES resolved at runtime (provider keys, the API token). Value-based scrubbing
# is sound where the regex is only a backstop; config registers every key it resolves.
_KNOWN_SECRETS: set[str] = set()


def register_secret(value: str | None) -> None:
    """Register a resolved secret value so it is redacted from any log line. No-op for short or
    empty values (avoids redacting innocuous substrings)."""
    if value and len(value) >= 6:
        _KNOWN_SECRETS.add(value)


def _kv(m: re.Match) -> str:
    key, quote, sep, value = m.group(1), m.group(2), m.group(3), m.group(4)
    # An assignment (``=``), a quoted JSON/YAML key, or a strong key is a credential whatever
    # the value looks like, short or with punctuation; prose after a weak key (``token:
    # expired``, ``signature: verified``) is redacted only for credential-like values.
    explicit = sep == "=" or bool(quote) or _EXPLICIT_RE.search(key) is not None
    if explicit or (len(value) >= 6 and _looks_secret(value.rstrip(",;.)"))):
        return key + "[REDACTED]"
    return m.group()


_HINT_RE = re.compile("|".join(_KV_HINT))
_VALUE_END = frozenset(" \t\r\n\"'`&")
_KEY_FIRST = frozenset("pscaxt([")  # first characters of every key, and of a tuple opening


def _scrub_keywords(text: str) -> str:
    """Key/value credentials, in linear time: the patterns run only at keyword positions (found
    with plain substring search), anchored, for the first ``_MAX_KEYWORDS``; any beyond get a
    cheap value-only redaction. Nothing is blanked wholesale, so a flood of keywords can't hide
    the rest of a line (the route of a probing request), nor make matching costly."""
    low = text.lower()
    hits: list[int] = []
    for hm in _HINT_RE.finditer(low):  # in order, C-speed; stop just past the pattern budget
        hits.append(hm.start())
        if len(hits) > _MAX_KEYWORDS:
            break
    if not hits:
        return text
    out: list[str] = []
    last = 0
    tried = 0
    for p in hits:
        if p < last:
            continue
        if tried >= _MAX_KEYWORDS:
            # Pattern budget spent: one C-speed pass redacts the value after any remaining
            # keyword (fail closed), without per-keyword Python work.
            out.append(text[last:p])
            out.append(_FALLBACK.sub(lambda m: m.group(1) + "[REDACTED]", text[p:]))
            return "".join(out)
        tried += 1
        span = None
        for i in range(max(last, p - _KEY_BACK), p + 1):
            if low[i] not in _KEY_FIRST:
                continue  # no key (or tuple opening) starts here: skip the patterns
            m = _KVT.match(text, i) or _KVQ.match(text, i)
            if m:
                span = (m.start(), m.end(), m.group(1) + "[REDACTED]")
                break
            m = _KV.match(text, i)
            if m:
                span = (m.start(), m.end(), _kv(m))
                break
        if span is not None:
            out.append(text[last:span[0]])
            out.append(span[2])
            last = span[1]
    out.append(text[last:])
    return "".join(out)


_FALLBACK = re.compile(
    r"((?:pass|pwd|secret|key|credential|signature|sig|token|authorization|cookie)"
    r"[A-Za-z_\-]{0,24}+[\"'`]?+[ \t]*+[:=][ \t]*+[\"'`]?+)([^\s\"'`&]{1,4096}+)",
    re.IGNORECASE)


def _authz(m: re.Match) -> str:
    # ``Authorization: <scheme> <credential>`` and ``authorization="..."`` are credentials; prose
    # (``authorization: required for this endpoint``) is kept.
    value = m.group(5)
    # "<Scheme> <credential>" (Basic, Token, SSWS, bearer ...): a second word of 8+ token
    # characters is a credential whatever its case; "required for this" is prose.
    parts = value.split()
    scheme = (len(parts) == 2 and len(parts[1]) >= 8
              and all(c.isalnum() or c in "-_.~+/=" for c in parts[1])) or \
        (" " in value and value[:1].isupper())
    explicit = m.group(3) == "=" or bool(m.group(2)) or bool(m.group(4)) or scheme
    return m.group(1) + "[REDACTED]" if explicit or _looks_secret(value) else m.group()


def scrub_text(text: str) -> str:
    """Redact known secret values (and shape-matched ones) from arbitrary text, in linear time.

    Value-based redaction is sound (config registers every key it resolves); the shapes are a
    backstop for credentials stored only as hashes (tenant tokens) or never seen (JWTs). A run
    holding a credential is replaced whole, in its original encoding, so the rest of the line
    is left exactly as it was. Used by the workspace so a credential can never reach disk via
    persisted session state, and by the log filter below."""
    text = _scrub_shapes(text)
    low = text.lower()
    if "authorization" in low:
        text = _AUTHZ.sub(_authz, text)
    if "bearer" in low:
        text = _BEARER.sub(lambda m: m.group(1) + "[REDACTED]"
                       if _looks_secret(m.group(2)) or any(c in "_-" for c in m.group(2))
                       else m.group(), text)
    return _scrub_keywords(text)


def _scrub_shapes(text: str) -> str:
    """Registered values and credential-shaped runs only (no keyword context)."""
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):  # longest first
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    budget = _Budget()
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
_TUPLE_FORMATTED = ("uvicorn.access", "uvicorn.error")


class _SecretScrubber(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if record.name in _TUPLE_FORMATTED and isinstance(record.args, tuple) \
                and isinstance(record.msg, str):
            record.msg = scrub_text(_clip(record.msg))  # the template is text too (f-strings)
            record.args = tuple(
                a if isinstance(a, (int, float))   # numbers (and bools) stay as they are (%d)
                else scrub_text(_clip(a if isinstance(a, str) else str(a)))
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
