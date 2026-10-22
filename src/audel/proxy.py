"""Vetting egress proxy — the definitive close for the DNS-rebinding race (ported from AgentVision).

Chromium (the headless web-capture path, Phase 4) is launched with ``--proxy-server`` pointing
here, so EVERY outbound request flows through this proxy. It resolves each host ONCE, vets the
resolved IP against :mod:`audel.netguard`, and connects to THAT exact IP — Chromium never resolves
the host itself, so there is no second lookup to rebind. The original Host/SNI is preserved (the
client still speaks the original hostname over the tunnel); only the TCP connection is pinned to
the vetted address. Pure asyncio, loopback-bound, one short-lived instance per capture; internal
targets get 403, and concurrent connections + idle time are bounded.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from .logging import get_logger
from .netguard import resolve_safe_ip

log = get_logger("proxy")
_ALLOWED_PORTS = frozenset({80, 443})  # web ports only: no tunnelling to arbitrary services


_HOST_ERRNOS = frozenset(getattr(__import__("errno"), n) for n in
                         ("EMFILE", "ENFILE", "ENOSPC", "ENOMEM", "ENOBUFS")
                         if hasattr(__import__("errno"), n))
BUSY_STATUS = b"503 Audel Host Busy"  # our own reply: the host, not the source, is at its limits


def _upstream_failure(e: OSError) -> bytes:
    return BUSY_STATUS if e.errno in _HOST_ERRNOS else b"502 Bad Gateway"


class VettingProxy:
    def __init__(self, host: str = "127.0.0.1", *, max_connections: int = 64,
                 idle_timeout_s: float = 30.0, max_lifetime_s: float = 600.0):
        self._host = host
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self._max_conn = max_connections
        self._idle = idle_timeout_s
        self._lifetime = max_lifetime_s  # absolute cap per connection, however active it is
        self._active = 0  # in-flight connections (single-threaded asyncio → no lock needed)
        self._tasks: set[asyncio.Task] = set()
        # Set when THIS proxy refused an upstream connection for lack of host resources. The
        # ingest path trusts only this flag, never response text an origin could forge.
        self.host_busy = False

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            # Live connections are cancelled, not waited on: a trickling upstream must not be
            # able to hold the proxy (and its caller) open past the caller's own deadline.
            for t in list(self._tasks):
                t.cancel()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2)
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._active += 1
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            await asyncio.wait_for(self._dispatch(reader, writer), timeout=self._lifetime)
        except (TimeoutError, asyncio.CancelledError):
            pass
        finally:
            self._active -= 1
            if task is not None:
                self._tasks.discard(task)
            await _close(writer)

    async def _dispatch(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
        except Exception:  # noqa: BLE001 (timeout / incomplete / overrun)
            return await _close(writer)
        if self._active > self._max_conn:
            return await _reply_close(writer, b"503 Service Unavailable")
        first, _, rest = head.partition(b"\r\n")
        try:
            method, target, _version = first.split(b" ", 2)
        except ValueError:
            return await _reply_close(writer, b"400 Bad Request")

        if method.upper() == b"CONNECT":  # https / wss tunnel
            host, _, port_b = target.rpartition(b":")
            try:
                port = int(port_b or b"443")
            except ValueError:
                return await _reply_close(writer, b"400 Bad Request")
            if port not in _ALLOWED_PORTS:
                return await _reply_close(writer, b"403 Forbidden")
            await self._tunnel(reader, writer, host.decode("latin1"), port)
        else:  # plain HTTP, absolute-form request line
            u = urlsplit(target.decode("latin1"))
            if u.scheme != "http" or not u.hostname:
                return await _reply_close(writer, b"400 Bad Request")
            if (u.port or 80) not in _ALLOWED_PORTS:
                return await _reply_close(writer, b"403 Forbidden")
            await self._http(reader, writer, u.hostname, u.port or 80, method,
                             u.path or "/", u.query, rest)

    async def _vet(self, host: str, port: int) -> str | None:
        return await resolve_safe_ip(host, port)

    async def _tunnel(self, reader, writer, host: str, port: int) -> None:
        ip = await self._vet(host, port)
        if ip is None:
            return await _reply_close(writer, b"403 Forbidden")
        try:
            up_r, up_w = await asyncio.open_connection(ip, port)
        except OSError as e:
            reply = _upstream_failure(e)
            if reply == BUSY_STATUS:
                self.host_busy = True
            return await _reply_close(writer, reply)
        except Exception:  # noqa: BLE001
            return await _reply_close(writer, b"502 Bad Gateway")
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await _pipe(reader, writer, up_r, up_w, self._idle)

    async def _http(self, reader, writer, host, port, method, path, query, header_block) -> None:
        ip = await self._vet(host, port)
        if ip is None:
            return await _reply_close(writer, b"403 Forbidden")
        try:
            up_r, up_w = await asyncio.open_connection(ip, port)
        except OSError as e:
            reply = _upstream_failure(e)
            if reply == BUSY_STATUS:
                self.host_busy = True
            return await _reply_close(writer, reply)
        except Exception:  # noqa: BLE001
            return await _reply_close(writer, b"502 Bad Gateway")
        origin = path + (("?" + query) if query else "")
        out = [method + b" " + origin.encode("latin1") + b" HTTP/1.1"]
        for line in header_block.split(b"\r\n"):
            if not line:
                continue
            low = line.lower()
            if low.startswith(b"proxy-connection:") or low.startswith(b"connection:"):
                continue
            out.append(line)
        out.append(b"Connection: close")
        up_w.write(b"\r\n".join(out) + b"\r\n\r\n")
        await up_w.drain()
        await _pipe(reader, writer, up_r, up_w, self._idle)


async def _pipe(c_r, c_w, u_r, u_w, idle: float) -> None:
    """Relay both directions. The idle timeout is on COMBINED activity: a direction that is quiet
    (the client after sending its request) never cuts a connection whose other direction is still
    flowing (a long response). Only when both sides are silent for ``idle`` is it closed."""
    import time

    last = {"t": time.monotonic()}

    async def copy(src, dst):
        try:
            while True:
                try:
                    data = await asyncio.wait_for(src.read(65536), timeout=idle)
                except TimeoutError:
                    if time.monotonic() - last["t"] < idle:
                        continue  # the other direction is active: keep the connection
                    break  # both sides silent (slowloris / hung upstream)
                if not data:
                    break
                last["t"] = time.monotonic()
                dst.write(data)
                await dst.drain()
        except Exception:  # noqa: BLE001 (connection errors -> close)
            pass
        finally:
            try:
                dst.close()
            except Exception:  # noqa: BLE001
                pass

    await asyncio.gather(copy(c_r, u_w), copy(u_r, c_w))


async def _reply_close(writer, status: bytes) -> None:
    try:
        writer.write(b"HTTP/1.1 " + status + b"\r\nConnection: close\r\n\r\n")
        await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    await _close(writer)


async def _close(writer) -> None:
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
