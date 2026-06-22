"""Network safety policy — SSRF defense (mirrors AgentVision's netguard).

Phase 3 uses it to vet **backend endpoint URLs** (an operator could misconfigure
``ollama_base_url`` to an internal host); Phase 4 extends it with a DNS-rebinding-proof egress
proxy for headless web capture. A blocked address is any private / loopback / link-local /
reserved / multicast / unspecified range, the cloud-metadata endpoints, or an unparseable host
(fail closed). IPv4-mapped IPv6 is normalized so it can't smuggle an internal address past the
range checks.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .errors import UnsafeSourceError

ALLOWED_SCHEMES = ("http", "https")

_METADATA = {
    "169.254.169.254",      # AWS / GCP / Azure / OpenStack IMDS
    "fd00:ec2::254",        # AWS IMDS over IPv6
    "100.100.100.200",      # Alibaba Cloud
}
_EXTRA_BLOCKED = [ipaddress.ip_network("100.64.0.0/10")]  # carrier-grade NAT (RFC 6598)


def _normalize(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def ip_is_blocked(addr: str) -> bool:
    """True if a literal address is internal / metadata / unparseable (fail closed)."""
    try:
        ip = _normalize(ipaddress.ip_address(addr))
    except ValueError:
        return True
    if str(ip) in _METADATA or addr in _METADATA:
        return True
    if any(ip in net for net in _EXTRA_BLOCKED):
        return True
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _is_literal_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def assert_host_safe(host: str | None, port: int | None = None) -> None:
    """Resolve-time SSRF check (sync). Raise :class:`UnsafeSourceError` if internal.

    Names the caller-supplied host but never the resolved IP (no SSRF/port oracle).
    """
    if not host:
        raise UnsafeSourceError("URL has no host.")
    blocked = f"refusing to reach {host!r}: resolves to a non-public address (SSRF protection)"
    if _is_literal_ip(host):
        if ip_is_blocked(host):
            raise UnsafeSourceError(blocked)
        return
    try:
        infos = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeSourceError(f"could not resolve host {host!r} (SSRF protection)") from e
    if any(ip_is_blocked(str(info[4][0])) for info in infos):
        raise UnsafeSourceError(blocked)


def assert_safe_url(url: str) -> None:
    """Vet a backend endpoint URL: allowed scheme + a public host. Raises ``UnsafeSourceError``."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeSourceError(f"backend URL scheme {parsed.scheme!r} not allowed (http/https only)")
    assert_host_safe(parsed.hostname, parsed.port)
