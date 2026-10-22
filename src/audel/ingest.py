"""Fetch media from a URL (e.g. an S3 / GCS / Azure signed URL) — SSRF-safe and bounded.

Media pipelines hand work over as object-store URLs, not uploads. This fetches one to a
server-named temp file so it can be graded like an upload.

Off unless the operator enables it (``AUDEL_ALLOW_URL_INGEST=true``): it is egress. When on:

* **https only** by default (``AUDEL_INGEST_ALLOW_HTTP`` opts into http), ports 80/443 only, no
  credentials embedded in the URL.
* optional host allowlist ``AUDEL_INGEST_ALLOWED_HOSTS`` (exact host or ``.suffix``, e.g.
  ``.s3.amazonaws.com``).
* every connection goes through :class:`audel.proxy.VettingProxy`, which resolves once, refuses
  internal / metadata addresses, and pins the TCP connection to the vetted IP (no DNS rebinding).
* redirects: at most 3, http(s) only, each target re-validated against the same rules.
* byte cap (``max_media_bytes``) enforced on the stream, and a wall-clock deadline.

Signed URLs carry secrets in the query string. They are never logged or echoed: only the host is.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .config import Settings
from .errors import BusyError, UnsafeSourceError
from .logging import get_logger
from .proxy import VettingProxy

log = get_logger("ingest")
_MAX_REDIRECTS = 3
_CHUNK = 1 << 16


def url_host(url: str) -> str:
    """The host only — safe to log or report (signed-URL query strings are secrets)."""
    try:
        return (urlsplit(url).hostname or "")[:255]
    except ValueError:
        return ""


def validate_ingest_url(url: str, settings: Settings) -> None:
    if not settings.allow_url_ingest:
        raise UnsafeSourceError("URL ingestion is disabled on this server")
    from .egress import require

    require(settings, "URL ingestion")
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 33 for c in url):
        raise UnsafeSourceError("URL is empty, too long or contains whitespace/control characters")
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError as e:
        raise UnsafeSourceError("URL could not be parsed") from e
    schemes = ("https", "http") if settings.ingest_allow_http else ("https",)
    if u.scheme not in schemes:
        raise UnsafeSourceError(f"URL scheme must be {' or '.join(schemes)}")
    if u.username or u.password:
        raise UnsafeSourceError("URL may not embed credentials")
    if port not in (None, 80, 443):
        raise UnsafeSourceError("URL port must be 80 or 443")
    host = (u.hostname or "").lower()
    if not host:
        raise UnsafeSourceError("URL has no host")
    allowed = [h.strip().lower() for h in settings.ingest_allowed_hosts if h.strip()]
    if allowed and not any(host == a or (a.startswith(".") and host.endswith(a)) for a in allowed):
        raise UnsafeSourceError(f"host {host!r} is not in the ingest allowlist")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, settings: Settings):
        super().__init__()
        self._settings = settings
        self._hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._hops += 1
        if self._hops > _MAX_REDIRECTS:
            raise UnsafeSourceError("too many redirects")
        validate_ingest_url(newurl, self._settings)  # same rules for every hop
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_private(dest: Path):
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(fd, "wb")


# Downloads get their OWN small pool: a stuck fetch can never occupy the default executor that
# decoding, hashing and ASR use for every tenant.
_DOWNLOAD_POOL = None


def _pool():
    global _DOWNLOAD_POOL
    if _DOWNLOAD_POOL is None:
        from concurrent.futures import ThreadPoolExecutor

        # 8 threads, and the service caps each tenant at 2 concurrent fetches, so it takes several
        # tenants together to fill the pool.
        _DOWNLOAD_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="audel-ingest")
    return _DOWNLOAD_POOL


def _download(url: str, dest: Path, proxy_url: str, settings: Settings,
              stop: threading.Event | None = None) -> int:
    try:
        return _download_inner(url, dest, proxy_url, settings, stop)
    except OSError as e:
        dest.unlink(missing_ok=True)  # the thread removes what IT created, however it ends
        if e.errno in _HOST_ERRNOS:  # out of fds / memory / disk here: retry, not a bad source
            raise BusyError("could not download: the host is at capacity; retry later") from None
        raise
    except BaseException:
        dest.unlink(missing_ok=True)
        raise


_HOST_ERRNOS = frozenset(getattr(__import__("errno"), n) for n in
                         ("EMFILE", "ENFILE", "ENOSPC", "ENOMEM", "EDQUOT")
                         if hasattr(__import__("errno"), n))


def _download_inner(url: str, dest: Path, proxy_url: str, settings: Settings,
                    stop: threading.Event | None = None) -> int:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        _SafeRedirect(settings))
    deadline = time.monotonic() + settings.ingest_timeout_s
    cap = settings.max_media_bytes
    req = urllib.request.Request(url, headers={"User-Agent": "audel-ingest"})
    total = 0
    with opener.open(req, timeout=min(30.0, settings.ingest_timeout_s)) as resp:
        declared = resp.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > cap:
            raise UnsafeSourceError(f"remote object is {declared} bytes, over the {cap}-byte cap")
        sock = getattr(getattr(resp.fp, "raw", None), "_sock", None)
        with open_private(dest) as fh:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise UnsafeSourceError("download exceeded the ingest time limit")
                if stop is not None and stop.is_set():
                    raise UnsafeSourceError("download cancelled")
                if resp.isclosed():
                    break  # the whole declared body has been read
                if sock is not None:
                    # Each receive is bounded by the TIME REMAINING, not reset per byte, and
                    # read1 returns whatever arrived, so a trickling server cannot stall the
                    # deadline check inside one large read.
                    try:
                        sock.settimeout(min(30.0, max(0.05, left)))
                    except OSError:
                        pass
                try:
                    chunk = resp.read1(_CHUNK)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    raise UnsafeSourceError(f"remote object exceeds the {cap}-byte cap")
                fh.write(chunk)
    if total == 0:
        raise UnsafeSourceError("remote object is empty")
    if declared and declared.isdigit() and total != int(declared):
        # An early close (proxy, network, or a lying server) must not be graded as the file.
        raise UnsafeSourceError(f"download incomplete: received {total} of {declared} bytes")
    return total


async def fetch_to_file(url: str, tmp_dir: Path, settings: Settings) -> Path:
    """Download ``url`` into ``tmp_dir`` under a server-chosen name. Caller deletes the file."""
    validate_ingest_url(url, settings)
    from .mediaguard import media_suffix

    suffix = media_suffix(urlsplit(url).path)
    dest = Path(tmp_dir) / f"ingest_{uuid.uuid4().hex[:16]}{suffix}"
    proxy = VettingProxy(max_connections=settings.proxy_max_connections,
                         idle_timeout_s=settings.proxy_idle_timeout_s,
                         max_lifetime_s=settings.ingest_timeout_s + 5)
    try:
        await proxy.start()
    except OSError:  # no fds / ports: the host, not the source
        raise BusyError("could not start a download: the host is at capacity; retry later") \
            from None
    stop = threading.Event()
    try:
        loop = asyncio.get_running_loop()
        try:
            fut = loop.run_in_executor(_pool(), _download, url, dest,
                                       f"http://127.0.0.1:{proxy.port}", settings, stop)
        except RuntimeError:  # the download pool can't start a thread
            raise BusyError("could not start a download: the host is at capacity; retry later") \
                from None
        await asyncio.wait_for(fut, timeout=settings.ingest_timeout_s + 5)
    except (UnsafeSourceError, BusyError):
        dest.unlink(missing_ok=True)
        raise
    except Exception as e:  # noqa: BLE001 - normalize: never leak the URL (it may be signed)
        dest.unlink(missing_ok=True)
        log.warning("ingest from %s failed: %s", url_host(url), type(e).__name__)
        raise UnsafeSourceError(f"could not fetch media from {url_host(url)!r}") from None
    except BaseException:  # cancellation / timeout: stop the thread, drop the partial file
        stop.set()
        dest.unlink(missing_ok=True)
        raise
    finally:
        stop.set()  # any exit (success, error, timeout, cancel): the worker thread stops
        try:
            await proxy.stop()
        except BaseException:
            # Cancelled while shutting the proxy down AFTER a successful download: the caller
            # never receives the path, so the file must not be left behind.
            dest.unlink(missing_ok=True)
            raise
    return dest
