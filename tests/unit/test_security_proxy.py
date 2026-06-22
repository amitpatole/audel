"""Phase 4 security: the vetting egress proxy pins to vetted IPs and refuses internal targets."""

from __future__ import annotations

import asyncio

from audel.netguard import resolve_safe_ip
from audel.proxy import VettingProxy


async def _request(port: int, raw: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    try:
        data = await asyncio.wait_for(r.read(200), timeout=5)
    finally:
        w.close()
    return data


def test_resolve_safe_ip_blocks_internal_allows_public_literal():
    async def go():
        assert await resolve_safe_ip("127.0.0.1", 80) is None
        assert await resolve_safe_ip("10.0.0.5", 80) is None
        assert await resolve_safe_ip("169.254.169.254", 80) is None  # cloud metadata
        assert await resolve_safe_ip("8.8.8.8", 443) == "8.8.8.8"   # public literal, vetted
    asyncio.run(go())


def test_proxy_connect_to_internal_is_forbidden():
    async def go():
        proxy = VettingProxy("127.0.0.1")
        await proxy.start()
        try:
            for host in (b"127.0.0.1:80", b"169.254.169.254:80", b"10.0.0.1:443"):
                resp = await _request(proxy.port, b"CONNECT " + host + b" HTTP/1.1\r\n\r\n")
                assert b"403" in resp, (host, resp)
        finally:
            await proxy.stop()
    asyncio.run(go())


def test_proxy_connection_cap_returns_503():
    async def go():
        proxy = VettingProxy("127.0.0.1", max_connections=0)  # any connection is over the cap
        await proxy.start()
        try:
            resp = await _request(proxy.port, b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            assert b"503" in resp
        finally:
            await proxy.stop()
    asyncio.run(go())


def test_proxy_rejects_malformed_request():
    async def go():
        proxy = VettingProxy("127.0.0.1")
        await proxy.start()
        try:
            resp = await _request(proxy.port, b"GARBAGE\r\n\r\n")
            assert b"400" in resp
        finally:
            await proxy.stop()
    asyncio.run(go())


def test_proxy_idle_timeout_configured():
    assert VettingProxy("127.0.0.1", idle_timeout_s=12.5)._idle == 12.5
