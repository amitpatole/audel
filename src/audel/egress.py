"""One egress policy for every network call Audel can make (``AUDEL_EGRESS``).

* ``allow`` (default): network-backed features work as documented (each still opt-in).
* ``local-only``: only hosts the operator listed in ``trusted_backend_hosts`` (an on-prem LLM).
  No public internet: no cloud model providers, no URL ingestion, no web capture, no model
  downloads.
* ``deny``: no network at all. Only the deterministic, offline paths run; anything that would
  reach the network raises :class:`~audel.errors.EgressDeniedError`.

Every egress point calls :func:`require` (cloud backends, the on-prem backend, URL ingestion, web
capture) and model loaders call :func:`models_offline` so a restricted deployment never
downloads weights. The check fails closed: an unknown mode is a configuration error.
"""

from __future__ import annotations

from enum import Enum

from .config import Settings
from .errors import ConfigError, EgressDeniedError


class EgressMode(str, Enum):
    ALLOW = "allow"
    LOCAL_ONLY = "local-only"
    DENY = "deny"


def mode(settings: Settings) -> EgressMode:
    try:
        return EgressMode(str(settings.egress).strip().lower())
    except ValueError as e:
        raise ConfigError("AUDEL_EGRESS must be allow, local-only or deny") from e


def require(settings: Settings, what: str, *, trusted: bool = False) -> None:
    """Raise unless the policy allows ``what``. ``trusted`` = an operator-trusted on-prem host."""
    m = mode(settings)
    if m is EgressMode.ALLOW:
        return
    if m is EgressMode.LOCAL_ONLY and trusted:
        return
    raise EgressDeniedError(f"{what} is blocked by the egress policy (AUDEL_EGRESS={m.value})")


def models_offline(settings: Settings) -> bool:
    """True when model loaders must use local files only (no Hugging Face download)."""
    return mode(settings) is not EgressMode.ALLOW
