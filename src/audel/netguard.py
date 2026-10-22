"""Network safety policy — SSRF defense (mirrors AgentVision's netguard).

Phase 3 uses it to vet **backend endpoint URLs** (an operator could misconfigure
``ollama_base_url`` to an internal host); Phase 4 extends it with a DNS-rebinding-proof egress
proxy for headless web capture. A blocked address is any private / loopback / link-local /
reserved / multicast / unspecified range, the cloud-metadata endpoints, or an unparseable host
(fail closed). IPv4-mapped IPv6 is normalized so it can't smuggle an internal address past the
range checks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.request
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


_NAT64 = [ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48")]


def _embedded_ipv4(ip) -> list:
    """IPv4 addresses carried inside IPv6 transition formats (NAT64, 6to4, Teredo). A routable
    IPv6 address must not smuggle an internal IPv4 destination past the checks."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    out = []
    if any(ip in n for n in _NAT64):
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.extend(ip.teredo)
    return out


def ip_is_blocked(addr: str) -> bool:
    """True if a literal address is internal / metadata / unparseable (fail closed)."""
    try:
        ip = _normalize(ipaddress.ip_address(addr))
    except ValueError:
        return True
    if any(ip_is_blocked(str(v4)) for v4 in _embedded_ipv4(ip)):
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


async def host_is_safe(host: str | None, port: int | None) -> bool:
    """Fetch-time SSRF check (async). Re-resolves so a DNS flip / redirect to internal is blocked.
    Fail closed (False) on any resolution error."""
    if not host:
        return False
    if _is_literal_ip(host):
        return not ip_is_blocked(host)
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return False
    return all(not ip_is_blocked(str(info[4][0])) for info in infos)


async def resolve_safe_ip(host: str | None, port: int | None) -> str | None:
    """Resolve+vet ONCE and return a safe IP to PIN the connection to (defeats DNS rebinding: the
    proxy connects to this exact vetted IP rather than re-resolving). None if internal/unresolvable."""
    if not host:
        return None
    if _is_literal_ip(host):
        return None if ip_is_blocked(host) else host
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return None
    ips = [str(info[4][0]) for info in infos]
    if not ips or any(ip_is_blocked(ip) for ip in ips):
        return None
    return ips[0]


# --- Operator-trusted backend hosts (Phase 10: on-prem / LAN inference) ------------------------

def _always_blocked(addr: str) -> bool:
    """Addresses no configuration can make reachable: cloud metadata, link-local, multicast,
    unspecified, reserved. (Private and loopback stay reachable only for TRUSTED hosts.)"""
    try:
        ip = _normalize(ipaddress.ip_address(addr))
    except ValueError:
        return True
    if str(ip) in _METADATA or addr in _METADATA:
        return True
    return bool(ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def canonical_host(host: str | None) -> str:
    """One spelling per host: lower-case, no trailing dot, IPs normalized (IPv4-mapped IPv6,
    decimal / octal / hex IPv4 forms) so allow/deny lists can't be dodged by re-spelling."""
    h = (host or "").strip().lower().rstrip(".").strip("[]")
    try:
        ip = _normalize(ipaddress.ip_address(h))
        return str(ip)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(h)  # accepts 134744072, 0x08080808, 010.010.010.010 ...
        if h and not any(c.isalpha() for c in h.replace("0x", "")):
            return str(ipaddress.IPv4Address(packed))
    except OSError:
        pass
    return h


def assert_backend_url(url: str, trusted_hosts: list[str] | tuple[str, ...] = (),
                       settings=None) -> None:
    """Vet a backend endpoint. Public hosts pass the normal SSRF check. A host the OPERATOR listed
    in ``trusted_backend_hosts`` (exact, case-insensitive match) may be private or loopback — that
    is how a LAN inference server is reached — but never metadata / link-local / multicast."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeSourceError(f"backend URL scheme {parsed.scheme!r} not allowed (http/https only)")
    host = canonical_host(parsed.hostname)
    if parsed.username or parsed.password:
        raise UnsafeSourceError("backend URL may not embed credentials")
    trusted = {canonical_host(h) for h in trusted_hosts if h and h.strip()}
    if settings is not None:
        from .egress import require

        require(settings, f"backend call to {host!r}", trusted=bool(host and host in trusted))
    if host and host in trusted:
        if _is_literal_ip(host):
            if _always_blocked(host):
                raise UnsafeSourceError(f"refusing to reach {host!r} even though it is trusted")
            return
        try:
            infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise UnsafeSourceError(f"could not resolve trusted host {host!r}") from e
        if any(_always_blocked(str(i[4][0])) for i in infos):
            raise UnsafeSourceError(f"refusing to reach {host!r}: resolves to a forbidden address")
        return
    assert_host_safe(parsed.hostname, parsed.port)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib handler that refuses every redirect (a backend must answer, not bounce us)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UnsafeSourceError(f"backend redirected ({code}); redirects are refused")


def post_json(url: str, body: dict, *, headers: dict[str, str] | None = None,
              timeout_s: float = 60.0, max_bytes: int = 4_000_000) -> dict:
    """POST JSON to an already-vetted backend URL: no redirects, bounded response read."""
    import json

    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=timeout_s) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise UnsafeSourceError(f"backend response over {max_bytes} bytes (refused)")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("backend returned non-object JSON")
    return data
