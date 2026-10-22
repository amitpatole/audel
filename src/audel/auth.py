"""Who is calling the service — resolve a request's credentials to a tenant.

Every REST request is authenticated before its body is read. The result is a :class:`Principal`
whose ``tenant`` scopes everything the caller can see (async jobs, rate limits, audit records).

Credential sources (Phase 11: a single shared token; Phase 12 adds per-tenant tokens and JWT):

* ``AUDEL_API_TOKEN`` — one bearer token, tenant ``default``.

All secret comparisons are constant time. When no credential is configured the service is
zero-config on loopback only (``serve`` refuses a routable bind without auth).
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .config import Settings


@dataclass(frozen=True)
class Principal:
    tenant: str
    method: str  # none | token


ANONYMOUS = Principal(tenant="anonymous", method="none")


class Authenticator:
    def __init__(self, settings: Settings) -> None:
        self._s = settings

    @property
    def required(self) -> bool:
        return bool(self._s.api_token)

    def authenticate(self, authorization: str | None) -> Principal | None:
        """Principal for a valid credential, ``ANONYMOUS`` when none is required, else ``None``."""
        if not self.required:
            return ANONYMOUS
        header = authorization or ""
        token = self._s.api_token or ""
        # Compare as BYTES: Starlette decodes headers as latin-1, and compare_digest on a str with
        # a non-ASCII char raises TypeError (a crafted header would 500 instead of 401).
        if token and hmac.compare_digest(header.encode("utf-8", "ignore"),
                                         f"Bearer {token}".encode()):
            return Principal(tenant="default", method="token")
        return None
