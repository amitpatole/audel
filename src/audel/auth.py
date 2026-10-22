"""Who is calling the service — resolve a request's credentials to a tenant, and rate-limit it.

Every REST request except ``/healthz`` is authenticated before its body is read. The result is a
:class:`Principal` whose ``tenant`` scopes everything the caller can see (async jobs, rate
limits, audit records).

Credential sources, tried in this order:

1. **Per-tenant tokens** — ``AUDEL_API_TOKENS_FILE`` points at a JSON file holding only SHA-256
   hashes of each tenant's token (``audel token new`` mints one)::

       {"tenants": {"newsroom": {"sha256": "<hex>", "rate_per_min": 300},
                    "promos":   {"sha256": "<hex>"}}}

   The server never stores a plaintext token. Every tenant hash is compared, in constant time,
   on every request (no early exit, no timing signal about which tenant matched).
2. **A single shared token** — ``AUDEL_API_TOKEN`` (tenant ``default``).
3. **OIDC / JWT** — ``AUDEL_JWT_JWKS_FILE`` (a local JWKS: no network fetch at request time),
   ``AUDEL_JWT_ISSUER``, ``AUDEL_JWT_AUDIENCE``. Asymmetric algorithms only; ``exp`` and ``iat``
   are required; lifetime is capped; the tenant comes from a claim (``AUDEL_JWT_TENANT_CLAIM``,
   default ``tenant``) and must be a plain identifier.

Rate limits are token buckets per tenant (``AUDEL_RATE_LIMIT_PER_MIN``, per-tenant override in
the tokens file) and, for failed authentication, per client address
(``AUDEL_AUTH_FAIL_PER_MIN``). Every credential is a generated secret of 256 bits (tokens) or a
signature (JWT), so online guessing is infeasible; the failure throttle exists to cap noise and
cost from invalid attempts, and a VALID credential always passes it (so one unauthenticated client
cannot lock out users who share its address).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .errors import ConfigError
from .logging import get_logger

log = get_logger("auth")
_TENANT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MAX_FILE_BYTES = 1_000_000
_MAX_TENANTS = 10_000
_ASYMMETRIC = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                         "ES256", "ES384", "ES512", "EdDSA"})
_MAX_BEARER = 8192
_MIN_SHARED_TOKEN = 32
_RESERVED = frozenset({"default", "anonymous", "admin"})
# JWT algorithm family -> JWK key type it must be verified with (no cross-type key use).
_ALG_KTY = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}


@dataclass(frozen=True)
class Principal:
    tenant: str
    method: str  # none | token | tenant-token | jwt
    rate_per_min: int | None = None


ANONYMOUS = Principal(tenant="anonymous", method="none")


def valid_tenant(name: str) -> bool:
    return bool(_TENANT_RE.match(name or ""))


_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "0123456789abcdef")


def _walks(t: str, n: int = 5) -> bool:
    """True if ``t`` contains an ASCII-sequential or keyboard-row run of ``n`` characters."""
    low = t.lower()
    for i in range(len(low) - n + 1):
        chunk = low[i:i + n]
        steps = {ord(chunk[k + 1]) - ord(chunk[k]) for k in range(n - 1)}
        if steps in ({1}, {-1}):
            return True
        if any(chunk in row or chunk in row[::-1] for row in _ROWS):
            return True
    return False


def strong_token(token: str) -> bool:
    """A shared token must look like GENERATOR output, not something a person typed:
    64+ hex characters (``openssl rand -hex 32``) or 43+ URL-safe characters
    (``audel token new`` / ``secrets.token_urlsafe(32)``), not compressible like a repeat, and
    with no 5-character sequential or keyboard-row walk. Online guessing is then infeasible,
    which is what lets valid credentials always pass the failure throttle."""
    import re
    import zlib

    if not (re.fullmatch(r"[0-9a-fA-F]{64,512}", token)
            or re.fullmatch(r"[A-Za-z0-9_-]{43,512}", token)):
        return False
    if len(zlib.compress(token.encode(), 9)) / len(token) < 0.8:
        return False
    return not _walks(token)


def new_token() -> str:
    """A fresh 256-bit URL-safe token that passes :func:`strong_token`."""
    import secrets

    while True:
        t = secrets.token_urlsafe(32)
        if strong_token(t):
            return t


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_tenants(path: Path) -> dict[str, tuple[bytes, int | None]]:
    """tenant -> (sha256 digest bytes, rate override). Strict: bad entries fail the whole load."""
    p = Path(path).expanduser()
    try:
        if p.stat().st_size > _MAX_FILE_BYTES:
            raise ConfigError("tokens file is too large")
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ConfigError(f"could not read tokens file {p.name}: {type(e).__name__}") from None
    tenants = data.get("tenants") if isinstance(data, dict) else None
    if not isinstance(tenants, dict) or not tenants or len(tenants) > _MAX_TENANTS:
        raise ConfigError("tokens file needs a non-empty 'tenants' object")
    out: dict[str, tuple[bytes, int | None]] = {}
    seen: set[bytes] = set()
    for name, entry in tenants.items():
        if not valid_tenant(str(name)) or not isinstance(entry, dict):
            raise ConfigError(f"invalid tenant entry {str(name)[:64]!r}")
        if str(name).lower() in _RESERVED:
            raise ConfigError(f"tenant name {name!r} is reserved")
        h = str(entry.get("sha256", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            raise ConfigError(f"tenant {name!r}: sha256 must be 64 hex characters")
        rate = entry.get("rate_per_min")
        if rate is not None and (not isinstance(rate, int) or isinstance(rate, bool)
                                 or rate < 1 or rate > 1_000_000):
            raise ConfigError(f"tenant {name!r}: rate_per_min must be an integer from 1")
        digest = bytes.fromhex(h)
        if digest in seen:
            raise ConfigError(f"tenant {name!r}: the same token hash is assigned to two tenants")
        seen.add(digest)
        out[str(name)] = (digest, rate)
    return out


def _jwk_fits(k, kty: str | None, alg: str) -> bool:
    """A JWKS key may verify this token only if its type matches the alg family and its own
    declared alg/use (when present) agree. Prevents cross-type key use and type-confusion crashes."""
    data = getattr(k, "_jwk_data", None) or {}
    ops = data.get("key_ops")
    return (data.get("kty") == kty and data.get("alg") in (None, alg)
            and data.get("use") in (None, "sig")
            and (ops is None or (isinstance(ops, list) and "verify" in ops)))


class _JWTVerifier:
    def __init__(self, s: Settings) -> None:
        try:
            import jwt  # PyJWT
        except ImportError as e:  # pragma: no cover - only without the extra
            raise ConfigError("JWT auth needs PyJWT: pip install 'audel[oidc]'") from e
        if not (s.jwt_issuer and s.jwt_audience):
            raise ConfigError("JWT auth needs AUDEL_JWT_ISSUER and AUDEL_JWT_AUDIENCE")
        algs = [a for a in s.jwt_algorithms if a in _ASYMMETRIC]
        if not algs or len(algs) != len(s.jwt_algorithms):
            raise ConfigError(f"jwt_algorithms must be asymmetric: {sorted(_ASYMMETRIC)}")
        p = Path(str(s.jwt_jwks_file)).expanduser()
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                raise ConfigError("JWKS file is too large")
            self._jwks = jwt.PyJWKSet.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except ConfigError:
            raise
        except Exception as e:  # noqa: BLE001 - any parse/shape problem is a config error
            raise ConfigError(f"could not load JWKS file {p.name}: {type(e).__name__}") from None
        self._jwt, self._s, self._algs = jwt, s, algs

    def verify(self, token: str) -> Principal | None:
        jwt = self._jwt
        try:
            header = jwt.get_unverified_header(token)
            alg, kid = header.get("alg"), header.get("kid")
            if not isinstance(alg, str) or alg not in self._algs:
                return None
            kty = _ALG_KTY.get(alg[:2])
            keys = [k for k in self._jwks.keys
                    if (kid is None or k.key_id == kid) and _jwk_fits(k, kty, alg)]
            if not keys:
                return None
            for k in keys:
                try:
                    claims = jwt.decode(
                        token, k.key, algorithms=self._algs, audience=self._s.jwt_audience,
                        issuer=self._s.jwt_issuer, leeway=self._s.jwt_leeway_s,
                        options={"require": ["exp", "iat", "iss", "aud"]})
                    break
                except (jwt.InvalidSignatureError, jwt.InvalidKeyError, TypeError, ValueError):
                    continue
            else:
                return None
        except (jwt.PyJWTError, TypeError, ValueError, KeyError):
            return None
        if float(claims["exp"]) - float(claims["iat"]) > self._s.jwt_max_lifetime_s:
            return None
        tenant = claims.get(self._s.jwt_tenant_claim)
        if not isinstance(tenant, str) or not valid_tenant(tenant):
            return None
        # Namespaced: a JWT tenant can never equal a token tenant (names can't contain ':').
        return Principal(tenant=f"jwt:{tenant}", method="jwt")


class Authenticator:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        if settings.api_token is not None and not strong_token(settings.api_token):
            raise ConfigError("AUDEL_API_TOKEN must be generated, not chosen: use "
                              "`openssl rand -hex 32` or `audel token new`")
        self._tenants = load_tenants(settings.api_tokens_file) if settings.api_tokens_file else {}
        self._jwt = _JWTVerifier(settings) if settings.jwt_jwks_file else None

    @property
    def required(self) -> bool:
        return bool(self._s.api_token or self._tenants or self._jwt)

    def authenticate(self, authorization: str | None) -> Principal | None:
        """Principal for a valid credential, ``ANONYMOUS`` when none is required, else ``None``."""
        if not self.required:
            return ANONYMOUS
        header = authorization or ""
        if len(header) > _MAX_BEARER or not header.startswith("Bearer "):
            return None
        presented = header[7:].strip()
        if not presented:
            return None
        if self._tenants:
            digest = hashlib.sha256(presented.encode("utf-8", "ignore")).digest()
            match: tuple[str, int | None] | None = None
            for name, (h, rate) in self._tenants.items():  # compare ALL: no early exit
                if hmac.compare_digest(digest, h) and match is None:
                    match = (name, rate)
            if match is not None:
                return Principal(tenant=match[0], method="tenant-token", rate_per_min=match[1])
        token = self._s.api_token or ""
        # Compare as BYTES: Starlette decodes headers as latin-1, and compare_digest on a str with
        # a non-ASCII char raises TypeError (a crafted header would 500 instead of 401).
        if token and hmac.compare_digest(presented.encode("utf-8", "ignore"), token.encode()):
            return Principal(tenant="default", method="token")
        if self._jwt is not None and presented.count(".") == 2:
            return self._jwt.verify(presented)
        return None


class RateLimiter:
    """Token buckets keyed by tenant (or client address). Bounded: least-recently-used keys are
    evicted past ``max_keys``, so an attacker rotating addresses cannot grow memory."""

    def __init__(self, per_min: int, burst: int | None = None, max_keys: int = 10_000) -> None:
        self._per_min = per_min
        self._burst = burst
        self._max = max_keys
        self._b: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        """True if ``key`` has no tokens left (does not consume)."""
        if self._per_min <= 0:
            return False
        cap = float(self._burst if self._burst is not None else max(1, self._per_min // 4))
        with self._lock:
            if key not in self._b:
                return False
            tokens, last = self._b[key]
        return min(max(cap, 1.0), tokens + (time.monotonic() - last) * self._per_min / 60.0) < 1.0

    def allow(self, key: str, per_min: int | None = None) -> tuple[bool, int]:
        """(allowed, retry_after_s). ``per_min`` overrides the default for this key; 0 = no limit."""
        rate = self._per_min if per_min is None else per_min
        if rate <= 0:
            return True, 0
        cap = float(self._burst if self._burst is not None else max(1, rate // 4))
        cap = max(cap, 1.0)
        refill = rate / 60.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._b.pop(key, (cap, now))
            tokens = min(cap, tokens + (now - last) * refill)
            ok = tokens >= 1.0
            if ok:
                tokens -= 1.0
            self._b[key] = (tokens, now)
            while len(self._b) > self._max:
                self._b.popitem(last=False)
        return ok, (0 if ok else max(1, int((1.0 - tokens) / refill) + 1))


def client_key(host: str | None) -> str:
    """Rate-limit key for a client address: IPv6 is bucketed by /64 (one subscriber's prefix),
    so rotating addresses inside a prefix does not buy fresh attempts."""
    import ipaddress

    if not host:
        return "unknown"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host[:64]
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is None:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip.ipv4_mapped or ip) if isinstance(ip, ipaddress.IPv6Address) else str(ip)
