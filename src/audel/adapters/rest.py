"""REST service (FastAPI) — for pipelines, CI and networked agents.

Security (mirrors AgentVision's reviewed rest.py, extended for production use):

- **Authentication before anything else.** Every request except ``/healthz`` is resolved to a
  tenant by :mod:`audel.auth` before its body is read; constant-time comparison; a non-loopback
  bind without credentials is refused in :func:`serve`.
- **Bounded.** Request bodies are capped (Content-Length AND the raw stream). Grading runs behind
  a concurrency semaphore; async submissions beyond ``max_queued_jobs`` get 429.
- **No host-file reads.** Media arrives as a multipart upload written to a server-named temp file,
  or (operator opt-in) as an http(s) URL fetched through the SSRF-vetting proxy. A caller can
  never name a path on the server, a spec file, or a backend outside ``rest_enabled_backends``.
- **Tenant isolation.** Async jobs belong to the submitting tenant; anyone else gets 404.
- **No leaks.** Errors are sanitized (only validation / unsafe-source text is returned, with
  workspace paths redacted); ``audio_path`` is stripped from every report; signed-URL query
  strings are never logged, audited or echoed.
- **Observable.** ``X-Request-ID`` on every response, Prometheus ``/metrics``, and a JSON-lines
  audit record per grade (hashes and outcomes, never content).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import time
import uuid
from pathlib import Path

from ..auth import Authenticator, Principal, RateLimiter, client_key
from ..config import Settings, load_settings
from ..errors import (
    AudelError,
    BusyError,
    ConfigError,
    MissingDependencyError,
    UnsafeSourceError,
    sanitize_message,
)
from ..logging import get_logger
from ..models import Brief, Report

try:
    from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
    from fastapi.responses import JSONResponse, PlainTextResponse
except ImportError:  # pragma: no cover - only without the [serve] extra
    FastAPI = None  # type: ignore

log = get_logger("rest")
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}
_KINDS = ("check", "listen", "analyze")
_HEAVY_ROUTES = frozenset({"/check", "/analyze", "/listen", "/render", "/handoff", "/jobs",
                           "/watch"})
_MAX_LIST_ITEMS = 200
_MAX_WATCH_BODY = 64 * 1024
_MAX_ITEM_CHARS = 2000
_REQUEST_ID_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK


def _brief_from(brief: str | None, expect: list[str] | None) -> Brief | None:
    if not (brief or expect):
        return None
    b = Brief.from_inputs(text=brief, expect=expect)
    return None if b.is_empty() else b


def _public(report: Report) -> dict:
    """Serialize a Report for the wire, stripping the server-local audio_path (info leak)."""
    data = report.model_dump(mode="json")
    data.pop("audio_path", None)
    return data


def _request_id(raw: str | None) -> str:
    from ..logging import scrub_text

    # A client id that looks like a credential would be blanked in the audit trail: mint one.
    if raw and 0 < len(raw) <= 64 and set(raw) <= _REQUEST_ID_OK and scrub_text(raw) == raw:
        return raw
    return uuid.uuid4().hex


def _sha256(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def build_app(settings: Settings | None = None):
    if FastAPI is None:
        raise MissingDependencyError("REST service needs FastAPI; pip install audel[serve]")

    from .. import __version__
    from ..jobs import JobStore, QueueFull
    from ..ops import AuditLog, Metrics

    # Service hardening: a remote caller must not read host files via a bare-path source. Grading
    # only ever runs on server-written temp files, so path sources are disabled service-wide.
    settings = settings or load_settings(allow_local_files=False)
    # A separate settings for grading our OWN temp files (server-named paths only — never caller
    # controlled), so validate_source accepts them while caller path-sources stay refused.
    grade_settings = settings.model_copy(update={"allow_local_files": True})
    auth = Authenticator(settings)
    limiter = RateLimiter(settings.rate_limit_per_min, settings.rate_limit_burst)
    fail_limiter = RateLimiter(settings.auth_fail_per_min)
    metrics = Metrics()
    audit = AuditLog(settings.audit_log)
    try:  # reap temp files a crash (or a full disk) left behind; live requests are far younger
        from ..workspace import Workspace as _Ws

        _Ws(settings).purge_tmp(24 * 3600)
    except OSError:
        log.warning("could not sweep the workspace temp directory")
    _job_sem = asyncio.Semaphore(settings.max_concurrent_jobs)
    jobs = JobStore(max_queued=settings.max_queued_jobs, max_stored=settings.max_stored_jobs,
                    ttl_s=settings.job_result_ttl_s, semaphore=_job_sem,
                    max_queued_per_owner=settings.max_queued_jobs_per_tenant,
                    max_stored_per_owner=settings.max_stored_jobs_per_tenant)
    _ws_marker = str(settings.cache_dir)  # redacted from error detail (no temp-path leak)

    def _principal(request: Request) -> Principal:
        p = getattr(request.state, "principal", None)
        if p is None:  # middleware always sets it; defensive fail-closed
            raise HTTPException(status_code=401, detail="Unauthorized")
        return p

    # FastAPI's auto-doc routes (/docs, /redoc, /openapi.json) are not covered by route
    # dependencies, so they'd leak the API schema to unauthenticated callers. When auth is on (the
    # service is meant to be exposed), disable them; keep them for loopback zero-config dev.
    app = FastAPI(title="Audel", version=__version__,
                  openapi_url=(None if auth.required else "/openapi.json"))

    inflight: dict[str, int] = {}
    total_spool = settings.max_spool_bytes
    spool = SpoolQuota(total_spool, settings.max_spool_bytes_per_tenant
                       or min(total_spool, max(total_spool // 4, settings.max_request_bytes)))
    cap_tenant = settings.max_inflight_per_tenant or max(2, settings.max_concurrent_jobs)
    cap_total = settings.max_inflight_total or 4 * settings.max_concurrent_jobs

    @app.middleware("http")
    async def _gate(request: Request, call_next):
        rid = _request_id(request.headers.get("x-request-id"))
        request.state.request_id = rid
        route = request.url.path if request.url.path in _ROUTES else "other"

        def reply(resp):
            resp.headers["X-Request-ID"] = rid
            metrics.request(route, resp.status_code)
            return resp

        if request.url.path == "/healthz":
            # Liveness never reads the body (unauthenticated: must not buffer anything).
            return reply(JSONResponse({"status": "ok", "version": __version__}))
        client = client_key(request.client.host if request.client else None)
        # Credentials are generated 256-bit secrets or signed JWTs, so guessing is infeasible: a
        # VALID credential always passes, and only failures are throttled (to cap noise), so an
        # unauthenticated client cannot lock out users sharing its address.
        # Authenticate BEFORE the body is read: an unauthenticated caller must not be able to
        # make the server read up to max_request_bytes (DoS amplification).
        principal = auth.authenticate(request.headers.get("authorization"))
        if principal is None:
            ok_fail, retry_fail = fail_limiter.allow(client)
            if not ok_fail:
                return reply(JSONResponse({"detail": "Too many failed attempts."},
                                          status_code=429, headers={"Retry-After": str(retry_fail)}))
            return reply(JSONResponse({"detail": "Unauthorized"}, status_code=401))
        ok, retry = limiter.allow(principal.tenant, principal.rate_per_min)
        if not ok:
            return reply(JSONResponse({"detail": "Rate limit exceeded."}, status_code=429,
                                      headers={"Retry-After": str(retry)}))
        request.state.principal = principal
        cl = request.headers.get("content-length")
        if cl is not None and "transfer-encoding" in request.headers:
            # Ambiguous framing (some servers frame by Transfer-Encoding and still pass the
            # length through): the declared size can't be trusted for any budget.
            return reply(JSONResponse({"detail": "Content-Length with Transfer-Encoding."},
                                      status_code=400))
        if cl and cl.isdigit() and int(cl) > settings.max_request_bytes:
            return reply(JSONResponse({"detail": "Request body too large."}, status_code=413))
        if request.url.path == "/watch" and request.method == "POST":
            # Refused BEFORE the body is read or parsed (it would be held while waiting for a
            # slot); an enabled /watch takes only a small JSON body with a declared length.
            if not settings.rest_allow_watch:
                return reply(JSONResponse({"detail": "watch is disabled on this server."},
                                          status_code=403))
            if not (cl and cl.isdigit()):
                return reply(JSONResponse({"detail": "Content-Length required."}, status_code=411))
            if int(cl) > _MAX_WATCH_BODY:
                return reply(JSONResponse({"detail": "Request body too large."}, status_code=413))
        if request.method != "POST" or request.url.path not in _HEAVY_ROUTES:
            return reply(await call_next(request))
        # Admission BEFORE the body is read: in-flight grading requests are capped per tenant and
        # overall, so queued uploads cannot pile up (memory / temp space) behind busy workers.
        t = principal.tenant
        if inflight.get(t, 0) >= cap_tenant or sum(inflight.values()) >= cap_total:
            return reply(JSONResponse({"detail": "Too many requests in progress."},
                                      status_code=429, headers={"Retry-After": "10"}))
        reserved = 0
        if request.url.path != "/watch":
            # An upload is spooled to disk for the request (and, for /jobs, until the queued job
            # runs): reserve the declared size (or the cap, undeclared) against the per-tenant
            # and overall spool budgets, so uploads in flight + queued fit the cache volume.
            reserved = int(cl) if cl and cl.isdigit() else settings.max_request_bytes
            if not spool.reserve(t, reserved):
                return reply(JSONResponse({"detail": "Too much queued upload data; retry later."},
                                          status_code=429, headers={"Retry-After": "30"}))
            request.state.spool = [t, reserved]  # submit_job takes it over for a queued job
        inflight[t] = inflight.get(t, 0) + 1
        try:
            return reply(await call_next(request))
        finally:
            held = getattr(request.state, "spool", None)
            if held is not None and held[1]:
                spool.release(held[0], held[1])  # not handed to a queued job
            left = inflight.get(t, 1) - 1
            if left <= 0:
                inflight.pop(t, None)
            else:
                inflight[t] = left

    app.add_middleware(_BodyLimit, cap=settings.max_request_bytes,
                       max_concurrent=settings.max_concurrent_uploads
                       or 2 * settings.max_concurrent_jobs,
                       read_timeout_s=settings.body_read_timeout_s)

    def _admin_only(request: Request) -> None:
        """/doctor and /metrics expose server internals and cross-tenant totals: when auth is on,
        only the shared-token principal and AUDEL_ADMIN_TENANTS may read them (others: 404)."""
        if not auth.required:
            return
        p = _principal(request)
        if p.method == "token" or p.tenant in settings.admin_tenants:
            return
        raise HTTPException(status_code=404, detail="Not Found")

    _work_sem = asyncio.Semaphore(settings.max_concurrent_jobs)

    _tenant_work = TenantSemaphores(max(1, settings.max_concurrent_jobs // 2))
    _tenant_jobs = TenantSemaphores(max(1, settings.max_concurrent_jobs // 2))

    async def _shielded(coro_factory, timeout: float, tenant: str | None = None):
        """Global work slots plus a per-tenant share of them, both held until the work REALLY
        ends (a cancelled or timed-out request cannot free its tenant's share early).

        The slots are acquired FIRST, within ``queue_wait_s`` (else 429), and only then does the
        request's time limit start: work another tenant abandoned can make a request wait or
        retry, never fail as "grading exceeded" without having run."""
        if tenant is None:
            return await run_shielded(_work_sem, coro_factory, timeout)
        sem = _tenant_work.get(tenant)
        held: list[asyncio.Semaphore] = []
        try:
            for s_ in (sem, _work_sem):
                try:
                    await asyncio.wait_for(s_.acquire(), timeout=settings.queue_wait_s)
                except TimeoutError:
                    raise BusyError("Server busy; retry later.") from None
                held.append(s_)
        except BaseException:
            for s_ in reversed(held):
                s_.release()
            _tenant_work.done(tenant)
            raise

        async def guarded():
            try:
                return await coro_factory()
            finally:
                _work_sem.release()
                sem.release()

        task = asyncio.ensure_future(guarded())
        task.add_done_callback(lambda _t: _tenant_work.done(tenant))  # cleanup when work ENDS
        task.add_done_callback(_retrieve)
        return await asyncio.wait_for(asyncio.shield(task), timeout=timeout)

    _tenant_fetch = TenantSemaphores(2)  # concurrent URL fetches per tenant

    _fetch_holds: dict[str, tuple[str, int]] = {}

    async def _fetch(url: str, tenant: str) -> Path:
        """Fetch a URL under the tenant's fetch share (one tenant cannot fill the download pool)."""
        from ..ingest import fetch_to_file
        from ..workspace import Workspace

        need = settings.max_media_bytes
        if not spool.reserve(tenant, need):  # the fetched file sits on the cache volume
            raise BusyError("Too much downloaded data held; retry later.")
        sem = _tenant_fetch.get(tenant)
        try:
            try:
                await asyncio.wait_for(sem.acquire(), timeout=settings.queue_wait_s)
            except TimeoutError:
                raise BusyError("Too many downloads in progress.") from None
            try:
                path = await fetch_to_file(url, Workspace(settings).tmp, settings)
            finally:
                sem.release()
        except BaseException:
            spool.release(tenant, need)
            raise
        finally:
            _tenant_fetch.done(tenant)
        _fetch_holds[str(path)] = (tenant, need)
        return path

    def _drop(path: Path) -> None:
        """Remove a request's temp media; a fetched file also returns its spool reservation."""
        path.unlink(missing_ok=True)
        held = _fetch_holds.pop(str(path), None)
        if held is not None:
            spool.release(*held)

    @contextlib.asynccontextmanager
    async def _tenant_job_gate(tenant: str):
        tsem = _tenant_jobs.get(tenant)
        try:
            async with tsem:
                yield
        finally:
            _tenant_jobs.done(tenant)

    jobs._owner_gate = _tenant_job_gate  # async jobs: tenant share before the global slot

    @contextlib.asynccontextmanager
    async def _slot_for(tenant: str):
        """A grading slot: the tenant's share FIRST, then a global slot, each with a bounded wait
        (429). Taken only AFTER the input is spooled or fetched, so a slow upload or URL never
        holds a slot other tenants need."""
        tsem = _tenant_jobs.get(tenant)
        try:
            try:
                await asyncio.wait_for(tsem.acquire(), timeout=settings.queue_wait_s)
            except TimeoutError:
                raise HTTPException(status_code=429, detail="Too many requests in progress.",
                                    headers={"Retry-After": "30"}) from None
            try:
                try:
                    await asyncio.wait_for(_job_sem.acquire(), timeout=settings.queue_wait_s)
                except TimeoutError:
                    raise HTTPException(status_code=429, detail="Server busy; retry later.",
                                        headers={"Retry-After": "30"}) from None
                metrics.inflight += 1
                try:
                    yield
                finally:
                    metrics.inflight -= 1
                    _job_sem.release()
            finally:
                tsem.release()
        finally:
            _tenant_jobs.done(tenant)

    @app.exception_handler(OSError)
    @app.exception_handler(MemoryError)
    @app.exception_handler(RuntimeError)
    async def _host_failure(request: Request, exc: Exception):
        """A host at its limits (no fds, no memory, no threads, disk full) is a retry, not a 500.
        Anything else still surfaces as an internal error."""
        from fastapi.responses import JSONResponse

        host = isinstance(exc, (OSError, MemoryError)) or "can't start new thread" in str(exc)
        if not host:
            log.warning("request failed: %s", type(exc).__name__)
            return JSONResponse({"detail": "Internal Server Error"}, status_code=500)
        log.warning("host at capacity: %s", type(exc).__name__)
        return JSONResponse({"detail": "Server busy; retry later."}, status_code=429,
                            headers={"Retry-After": "30"})

    def _http_error(e: Exception) -> HTTPException:
        if isinstance(e, BusyError):
            return HTTPException(status_code=429, detail=str(e), headers={"Retry-After": "30"})
        if isinstance(e, (ConfigError, UnsafeSourceError)):
            # Caller-input validation or an unsafe source. Safe to surface once any workspace
            # path is redacted.
            return HTTPException(status_code=400, detail=sanitize_message(
                str(e).replace(_ws_marker, "<workspace>")))
        log.warning("request failed: %s", type(e).__name__)
        return HTTPException(status_code=400, detail="Could not decode or grade the source.")

    def _check_backend(name: str | None):
        if name and name not in settings.rest_enabled_backends:
            raise HTTPException(
                status_code=400,
                detail=f"Backend {name!r} is not enabled on this server. "
                       f"Allowed: {settings.rest_enabled_backends or '(none — server default only)'}",
            )

    def _spec_for(name: str | None):
        """Remote callers may name a BUILT-IN spec only — never a server file path."""
        if not name:
            return None
        from ..specs import builtin_spec

        try:
            return builtin_spec(name)
        except ConfigError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    def _settings_for(content: str | None) -> Settings:
        if not content:
            return grade_settings
        if content not in ("speech", "music", "mixed"):
            raise HTTPException(status_code=400, detail="content must be speech, music or mixed")
        return grade_settings.model_copy(update={"content_type": content})

    def _languages(items: list[str] | None) -> dict[int, str]:
        langs: dict[int, str] = {}
        for item in items or []:
            idx, sep, code = item.partition("=")
            idx = idx.strip()
            if not sep or not (idx.isascii() and idx.isdigit()) or len(idx) > 3 or len(langs) >= 32:
                raise HTTPException(status_code=400, detail="language must be TRACK=CODE, e.g. 1=es")
            langs[int(idx)] = code.strip()
        return langs

    async def _spool(upload: UploadFile) -> Path:
        """Write an uploaded file to a server-NAMED temp file under the workspace (path is never
        caller-controlled). The body middleware already capped total bytes; re-check defensively."""
        from ..workspace import Workspace

        ws = Workspace(settings)
        from ..mediaguard import media_suffix

        suffix = media_suffix(upload.filename)  # known media extensions only (no .m3u8 etc.)
        dest = ws.tmp / f"upload_{uuid.uuid4().hex[:16]}{suffix}"
        total = 0
        cap = settings.max_request_bytes
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                while True:
                    chunk = await upload.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > cap:
                        raise UnsafeSourceError("uploaded file exceeds the size cap")
                    fh.write(chunk)
        except BaseException:  # over cap, I/O error (disk full), cancellation: leave nothing
            dest.unlink(missing_ok=True)
            raise
        if total == 0:
            dest.unlink(missing_ok=True)
            raise UnsafeSourceError("uploaded file is empty")
        return dest

    async def _acquire(file: UploadFile | None, url: str | None,
                       tenant: str = "anonymous") -> tuple[Path, str, str | None]:
        """(server temp path, source kind, source host). Exactly one of file / url."""
        if (file is None) == (not url):
            raise UnsafeSourceError("send exactly one of: a 'file' upload or a 'url'")
        if file is not None:
            return await _spool(file), "upload", None
        from ..ingest import url_host

        assert url is not None
        return await _fetch(url, tenant), "url", url_host(url)

    async def _grade(kind: str, path: Path, p: dict, gs: Settings):
        from ..core import analyze, check, listen

        brief = _brief_from(p.get("brief"), p.get("expect"))
        if kind == "check":
            return await check(str(path), settings=gs, brief=brief, spec=p.get("spec"))
        if kind == "analyze":
            return await analyze(str(path), settings=gs, brief=brief, backend=p.get("backend"),
                                 spec=p.get("spec"))
        return await listen(str(path), settings=gs, spec=p.get("spec"), brief=brief,
                            script=p.get("script"), captions=p.get("captions"),
                            required=p.get("require"), forbidden=p.get("forbid"),
                            languages=p.get("languages"), key_messages=p.get("key_message"),
                            tone=p.get("tone"), understand=bool(p.get("understand")),
                            backend=p.get("backend"))

    def _validate(kind: str, p: dict) -> tuple[dict, Settings]:
        for name in ("expect", "require", "forbid", "key_message", "language"):
            items = p.get(name) or []
            if len(items) > _MAX_LIST_ITEMS or any(len(x) > _MAX_ITEM_CHARS for x in items):
                raise HTTPException(status_code=400, detail=(
                    f"{name}: at most {_MAX_LIST_ITEMS} values of {_MAX_ITEM_CHARS} characters"))
        if kind not in _KINDS:
            raise HTTPException(status_code=400, detail=f"kind must be one of {', '.join(_KINDS)}")
        if p.get("understand") and not settings.rest_allow_understand:
            raise HTTPException(status_code=403, detail="understand is disabled on this server.")
        _check_backend(p.get("backend"))
        p = {**p, "spec": _spec_for(p.get("spec")), "languages": _languages(p.get("language"))}
        return p, _settings_for(p.get("content"))

    async def _run_and_audit(kind: str, path: Path, src: str, host: str | None, p: dict,
                             gs: Settings, principal: Principal, request_id: str,
                             job_id: str | None = None, as_handoff: bool = False) -> dict:
        t0 = time.monotonic()
        digest = size = None
        status, verdict, n_issues, err = "ok", None, None, None
        try:
            try:
                digest, size = await asyncio.to_thread(_sha256, path)
            except (OSError, MemoryError, RuntimeError) as e:
                raise BusyError("Server busy; retry later.") from e
            report = await _shielded(lambda: _grade(kind, path, p, gs),
                                     settings.request_timeout_s, principal.tenant)
            verdict, n_issues = report.verdict.value, len(report.issues)
            if as_handoff:
                hand = report.to_handoff().model_dump(mode="json")
                hand["artifact"] = digest  # never the server-side temp path
                return hand
            return _public(report)
        except TimeoutError:
            status, err = "timeout", "timeout"
            raise UnsafeSourceError(f"grading exceeded {settings.request_timeout_s:.0f}s") from None
        except asyncio.CancelledError:
            status, err = "cancelled", "cancelled"
            raise
        except Exception as e:
            status, err = "error", type(e).__name__
            raise
        finally:
            secs = time.monotonic() - t0
            if verdict:
                metrics.graded(kind, verdict, secs)
            spec = p.get("spec")
            audit.write(request_id=request_id, tenant=principal.tenant, endpoint=f"/{kind}",
                        job_id=job_id, kind=kind, input_sha256=digest, input_bytes=size,
                        source=src, source_host=host,
                        spec=getattr(spec, "name", None), verdict=verdict, issues=n_issues,
                        status=status, duration_ms=int(secs * 1000), error=err)

    # ---- routes -----------------------------------------------------------------------------

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/doctor")
    def doctor_ep(request: Request):
        _admin_only(request)
        from .doctor import run_checks

        return {"checks": [{"name": c.name, "ok": c.ok, "detail": c.detail}
                           for c in run_checks(settings)]}

    @app.get("/metrics")
    def metrics_ep(request: Request):
        _admin_only(request)
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="Not Found")
        metrics.queued = sum(1 for j in jobs._jobs.values() if j.status == "queued")
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/specs")
    def specs_ep():
        from ..specs import BUILTIN_SPECS

        return {"specs": [s.model_dump(mode="json") for s in BUILTIN_SPECS.values()]}

    async def _sync(request: Request, kind: str, file: UploadFile | None, url: str | None,
                    params: dict) -> dict:
        p, gs = _validate(kind, params)
        path = None
        try:
            path, src, host = await _acquire(file, url, _principal(request).tenant)
            async with _slot_for(_principal(request).tenant):
                return await _run_and_audit(kind, path, src, host, p, gs, _principal(request),
                                            request.state.request_id)
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if path is not None:
                _drop(path)

    @app.post("/check")
    async def check_ep(request: Request, file: UploadFile | None = File(None),
                       url: str | None = Form(None), brief: str | None = Form(None),
                       expect: list[str] | None = Form(None), spec: str | None = Form(None),
                       content: str | None = Form(None)):
        """Deterministic grade (no LLM, no egress except an opted-in URL fetch)."""
        return await _sync(request, "check", file, url, {"brief": brief, "expect": expect,
                                                         "spec": spec, "content": content})

    @app.post("/analyze")
    async def analyze_ep(request: Request, file: UploadFile | None = File(None),
                         url: str | None = Form(None), brief: str | None = Form(None),
                         expect: list[str] | None = Form(None), backend: str | None = Form(None),
                         spec: str | None = Form(None), content: str | None = Form(None)):
        """Full grade (signals + ASR + backend critique). Egress only to the server's backend."""
        return await _sync(request, "analyze", file, url, {
            "brief": brief, "expect": expect, "backend": backend, "spec": spec,
            "content": content})

    @app.post("/listen")
    async def listen_ep(request: Request, file: UploadFile | None = File(None),
                        url: str | None = Form(None), script: str | None = Form(None),
                        captions: str | None = Form(None), require: list[str] | None = Form(None),
                        forbid: list[str] | None = Form(None),
                        language: list[str] | None = Form(None),
                        key_message: list[str] | None = Form(None), tone: str | None = Form(None),
                        understand: bool = Form(False), backend: str | None = Form(None),
                        spec: str | None = Form(None), content: str | None = Form(None),
                        brief: str | None = Form(None), expect: list[str] | None = Form(None)):
        """Hear and listen: signal QC plus script / wording / pace / captions (offline). With
        ``understand`` (operator opt-in), key messages and delivery via the server's backend."""
        return await _sync(request, "listen", file, url, {
            "script": script, "captions": captions, "require": require, "forbid": forbid,
            "language": language, "key_message": key_message, "tone": tone,
            "understand": understand, "backend": backend, "spec": spec, "content": content,
            "brief": brief, "expect": expect})

    @app.post("/render")
    async def render_ep(request: Request, file: UploadFile | None = File(None),
                        url: str | None = Form(None)):
        """Decode to trustworthy signals (loudness / true peak / RMS / silent spans, per track)."""
        from ..core import render

        path = None
        t0 = time.monotonic()
        status = "ok"
        digest = size = src = host = None
        try:
            path, src, host = await _acquire(file, url, _principal(request).tenant)
            digest, size = await asyncio.to_thread(_sha256, path)
            async with _slot_for(_principal(request).tenant):
                rr = await _shielded(lambda: render(str(path), settings=grade_settings),
                                     settings.request_timeout_s, _principal(request).tenant)
            return {"duration_ms": rr.duration_ms, "channels": rr.channels,
                    "sample_rate": rr.sample_rate, "codec": rr.codec, "has_audio": rr.has_audio,
                    "integrated_lufs": rr.integrated_lufs, "true_peak_dbtp": rr.true_peak_dbtp,
                    "rms_dbfs": rr.rms_dbfs, "lra": rr.lra, "silences": len(rr.silences),
                    "tracks": [t.model_dump(mode="json") for t in rr.tracks]}
        except TimeoutError:
            status = "timeout"
            raise HTTPException(status_code=400, detail="render exceeded the time limit") from None
        except AudelError as e:
            status = "error"
            raise _http_error(e) from e
        except HTTPException:
            status = "refused"
            raise
        except BaseException:
            status = "error"
            raise
        finally:
            if path is not None:
                audit.write(request_id=request.state.request_id, tenant=_principal(request).tenant,
                            endpoint="/render", kind="render", status=status,
                            input_sha256=digest, input_bytes=size, source=src, source_host=host,
                            duration_ms=int((time.monotonic() - t0) * 1000))
                _drop(path)

    @app.post("/handoff")
    async def handoff_ep(request: Request, file: UploadFile | None = File(None),
                         url: str | None = Form(None), brief: str | None = Form(None),
                         expect: list[str] | None = Form(None), backend: str | None = Form(None)):
        """Grade + return the distilled ears→brain handoff (verdict + next action + todo)."""
        p, gs = _validate("analyze", {"brief": brief, "expect": expect, "backend": backend})
        path = None
        try:
            path, src, host = await _acquire(file, url, _principal(request).tenant)
            async with _slot_for(_principal(request).tenant):
                return await _run_and_audit("analyze", path, src, host, p, gs, _principal(request),
                                            request.state.request_id, as_handoff=True)
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if path is not None:
                _drop(path)

    @app.post("/watch")
    async def watch_ep(request: Request):
        """Temporal grade of an http(s) URL (does the audio play THROUGH?). SSRF-guarded."""
        import json as _json

        from ..core import watch

        if not settings.rest_allow_watch:
            raise HTTPException(status_code=403, detail="watch is disabled on this server.")
        # The body is read BEFORE a grading slot is taken: a slow sender must not hold one.
        raw = await request.body()  # _gate capped it at _MAX_WATCH_BODY
        try:
            body = _json.loads(raw) if len(raw) <= _MAX_WATCH_BODY else None
        except (ValueError, RecursionError):  # malformed or absurdly nested: a 400, not a 500
            body = None
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="watch requires a JSON {\"source\": url}.")
        source = body.get("source")
        if not isinstance(source, str) or not source:
            raise HTTPException(status_code=400, detail="watch requires a JSON {\"source\": url}.")
        try:
            async with _slot_for(_principal(request).tenant):
                report = await watch(source, settings=settings,  # URL only (no local files)
                                     click_selector=body.get("click_selector"))
            return _public(report)
        except AudelError as e:
            raise _http_error(e) from e

    # ---- async jobs -------------------------------------------------------------------------

    @app.post("/jobs", status_code=202)
    async def submit_job(request: Request, kind: str = Form("check"),
                         file: UploadFile | None = File(None), url: str | None = Form(None),
                         brief: str | None = Form(None), expect: list[str] | None = Form(None),
                         spec: str | None = Form(None), content: str | None = Form(None),
                         backend: str | None = Form(None), script: str | None = Form(None),
                         captions: str | None = Form(None), require: list[str] | None = Form(None),
                         forbid: list[str] | None = Form(None),
                         language: list[str] | None = Form(None),
                         key_message: list[str] | None = Form(None), tone: str | None = Form(None),
                         understand: bool = Form(False)):
        """Queue a grade; poll ``GET /jobs/{id}``. The upload is spooled now; a URL is fetched
        when the job runs. Returns 429 when the queue is full."""
        principal = _principal(request)
        p, gs = _validate(kind, {
            "brief": brief, "expect": expect, "spec": spec, "content": content,
            "backend": backend, "script": script, "captions": captions, "require": require,
            "forbid": forbid, "language": language, "key_message": key_message, "tone": tone,
            "understand": understand})
        if (file is None) == (not url):
            raise HTTPException(status_code=400, detail="send exactly one of: a 'file' upload or a 'url'")
        if jobs.pending() >= settings.max_queued_jobs or \
                jobs.pending(principal.tenant) >= (settings.max_queued_jobs_per_tenant
                                                  or max(1, settings.max_queued_jobs // 4)):
            raise HTTPException(status_code=429, detail="job queue is full; retry later",
                                headers={"Retry-After": "30"})
        spooled: Path | None = None
        try:
            if file is not None:
                spooled = await _spool(file)
            else:
                from ..ingest import validate_ingest_url

                validate_ingest_url(url or "", settings)  # fail fast on a bad URL
        except AudelError as e:
            raise _http_error(e) from e
        rid = request.state.request_id
        holder: dict[str, str] = {}

        fetched: list[Path] = []
        source: dict = {"path": spooled, "src": "upload", "host": None}

        async def prepare() -> None:  # runs BEFORE any grading slot is taken
            if source["path"] is None:
                from ..ingest import url_host

                path = await _fetch(url or "", principal.tenant)
                fetched.append(path)
                source.update(path=path, src="url", host=url_host(url or ""))

        async def work() -> dict:
            return await _run_and_audit(kind, source["path"], source["src"], source["host"], p,
                                        gs, principal, rid, job_id=holder.get("id"))

        def cleanup() -> None:  # runs on done, failure AND cancel (even while still queued)
            for f in ([spooled] if spooled is not None else []) + fetched:
                _drop(f)

        held = getattr(request.state, "spool", None)
        owner, owned = (str(held[0]), int(held[1])) if held is not None else (principal.tenant, 0)
        released = [False]

        def cleanup_and_release() -> None:
            cleanup()
            if owned and not released[0]:
                released[0] = True
                spool.release(owner, owned)

        try:
            job = jobs.submit(principal.tenant, kind, work, cleanup=cleanup_and_release,
                              prepare=prepare)
            if held is not None:
                held[1] = 0  # the queued job owns the reservation now; released by its cleanup
        except QueueFull as e:
            if spooled is not None:
                spooled.unlink(missing_ok=True)
            raise HTTPException(status_code=429, detail=str(e), headers={"Retry-After": "30"}) from e
        holder["id"] = job.id
        return {"job_id": job.id, "status": job.status, "status_url": f"/jobs/{job.id}"}

    @app.get("/jobs")
    def list_jobs(request: Request):
        return {"jobs": [{"job_id": j.id, "kind": j.kind, "status": j.status, "created": j.created}
                         for j in jobs.list(_principal(request).tenant)]}

    @app.get("/jobs/{job_id}")
    def get_job(request: Request, job_id: str):
        job = jobs.get(_principal(request).tenant, job_id)
        if job is None:  # same answer for "not yours" and "does not exist" (no oracle)
            raise HTTPException(status_code=404, detail="Not Found")
        return job.public()

    @app.delete("/jobs/{job_id}")
    def delete_job(request: Request, job_id: str):
        if not jobs.cancel(_principal(request).tenant, job_id):
            raise HTTPException(status_code=404, detail="Not Found")
        return {"job_id": job_id, "status": "deleted"}

    return app


class SpoolQuota:
    """Bytes of queued uploads on disk, per tenant and overall. Reserved at admission (before
    the body is read) and released when the job's spooled file is removed."""

    def __init__(self, total: int, per_tenant: int):
        import threading

        self.total, self.per_tenant = total, per_tenant
        self.held: dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, tenant: str, n: int) -> bool:
        with self._lock:
            mine = self.held.get(tenant, 0)
            if mine + n > self.per_tenant or sum(self.held.values()) + n > self.total:
                return False
            self.held[tenant] = mine + n
            return True

    def release(self, tenant: str, n: int) -> None:
        with self._lock:
            left = self.held.get(tenant, 0) - n
            if left > 0:
                self.held[tenant] = left
            else:
                self.held.pop(tenant, None)


class TenantSemaphores:
    """Per-tenant semaphores that remove themselves when idle (bounded by active tenants)."""

    def __init__(self, cap: int) -> None:
        self.cap = max(1, cap)
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._users: dict[str, int] = {}

    def get(self, tenant: str) -> asyncio.Semaphore:
        self._users[tenant] = self._users.get(tenant, 0) + 1
        return self._sems.setdefault(tenant, asyncio.Semaphore(self.cap))

    def done(self, tenant: str) -> None:
        left = self._users.get(tenant, 1) - 1
        if left <= 0:
            self._users.pop(tenant, None)
            self._sems.pop(tenant, None)
        else:
            self._users[tenant] = left

    def __len__(self) -> int:
        return len(self._sems)


def _retrieve(t: asyncio.Future) -> None:
    """Consume an abandoned task's outcome so asyncio never prints an unscrubbed traceback."""
    if not t.cancelled() and t.exception() is not None:
        log.info("abandoned grading ended with %s", type(t.exception()).__name__)


async def run_shielded(sem: asyncio.Semaphore, coro_factory, timeout: float | None):
    """Run grading so its concurrency slot is held until the work REALLY ends.

    A request timeout or a job cancel must not free the slot while ffmpeg/ASR threads keep
    running (that would let a caller pile up unbounded background work). Work abandoned before it
    acquired a slot is skipped entirely."""
    abandoned = asyncio.Event()
    started = {"v": False}

    async def guarded():
        async with sem:
            if abandoned.is_set():
                return None
            started["v"] = True
            return await coro_factory()

    task = asyncio.create_task(guarded())
    task.add_done_callback(_retrieve)
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
    except (TimeoutError, asyncio.CancelledError):
        abandoned.set()
        if not started["v"]:
            task.cancel()
        raise


class _BodyLimit:
    """Pure-ASGI request-body control, enforced on the STREAM as it is read (chunked uploads
    included), never buffering a whole body:

    * size cap -> 413;
    * intake concurrency: a request takes an intake slot only when it first reads its body
      (i.e. after authentication) and gives it back as soon as the body is fully read, so a
      request waiting for a grading slot does not hold intake;
    * per-tenant intake share (at most half the slots) -> 429, so one tenant cannot occupy them all;
    * body-read deadline -> 408, so a slow sender (slowloris) cannot hold a slot indefinitely.
    """

    def __init__(self, app, cap: int, max_concurrent: int = 8, read_timeout_s: float = 60.0) -> None:
        self.app, self.cap, self.read_timeout_s = app, cap, read_timeout_s
        self._slots = max(1, max_concurrent)
        self._intake = asyncio.Semaphore(self._slots)
        self._per_tenant = max(1, self._slots // 2)
        self._tenant_use: dict[str, int] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        import time as _time

        total = 0
        refusal: tuple[int, bytes] | None = None
        sent_ours = False
        holding = False
        finished = False
        tenant: str | None = None
        deadline = 0.0

        def release() -> None:
            nonlocal holding
            if holding:
                holding = False
                self._intake.release()
                if tenant is not None:  # the reservation taken before acquire
                    left = self._tenant_use.get(tenant, 1) - 1
                    if left <= 0:
                        self._tenant_use.pop(tenant, None)
                    else:
                        self._tenant_use[tenant] = left

        async def recv():
            nonlocal total, refusal, holding, finished, tenant, deadline
            if refusal is not None or finished:
                return {"type": "http.disconnect"} if refusal is not None else await receive()
            if not holding:
                principal = (scope.get("state") or {}).get("principal")
                tenant = getattr(principal, "tenant", None)
                if tenant is not None and self._tenant_use.get(tenant, 0) >= self._per_tenant:
                    refusal = (429, b'{"detail":"Too many uploads in progress for this tenant."}')
                    return {"type": "http.disconnect"}
                # Reserve the tenant's share BEFORE waiting, so concurrent requests of one tenant
                # cannot all pass the check while intake is momentarily full.
                if tenant is not None:
                    self._tenant_use[tenant] = self._tenant_use.get(tenant, 0) + 1
                deadline = _time.monotonic() + self.read_timeout_s
                def unreserve() -> None:
                    if tenant is not None:
                        left = self._tenant_use.get(tenant, 1) - 1
                        if left <= 0:
                            self._tenant_use.pop(tenant, None)
                        else:
                            self._tenant_use[tenant] = left

                try:
                    await asyncio.wait_for(self._intake.acquire(),
                                           max(0.01, deadline - _time.monotonic()))
                except TimeoutError:
                    unreserve()
                    refusal = (408, b'{"detail":"Request body not received in time."}')
                    return {"type": "http.disconnect"}
                except BaseException:
                    unreserve()
                    raise
                holding = True
            try:
                msg = await asyncio.wait_for(receive(), max(0.01, deadline - _time.monotonic()))
            except TimeoutError:
                refusal = (408, b'{"detail":"Request body not received in time."}')
                release()
                return {"type": "http.disconnect"}
            if msg.get("type") == "http.request":
                total += len(msg.get("body", b""))
                if total > self.cap:
                    refusal = (413, b'{"detail":"Request body too large."}')
                    release()
                    return {"type": "http.disconnect"}
                if not msg.get("more_body", False):
                    finished = True
                    release()  # body fully read: free the intake slot now
            else:
                release()
            return msg

        async def snd(msg):
            nonlocal sent_ours
            if refusal is None:
                return await send(msg)
            if sent_ours:
                return None
            sent_ours = True
            status, body = refusal
            await send({"type": "http.response.start", "status": status,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})

        try:
            await self.app(scope, recv, snd)
        except Exception:
            if refusal is None:
                raise
        finally:
            release()
        if refusal is not None and not sent_ours:
            await snd({"type": "http.response.start"})


_ROUTES = frozenset({"/healthz", "/doctor", "/metrics", "/specs", "/check", "/analyze", "/listen",
                     "/render", "/handoff", "/watch", "/jobs"})


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    # Fail closed: never expose a routable interface without auth.
    s = load_settings()
    if not _is_loopback(host) and not Authenticator(s).required:
        raise SystemExit(
            f"Refusing to bind non-loopback host {host!r} without auth. Set AUDEL_API_TOKEN (from "
            "`audel token new`), AUDEL_API_TOKENS_FILE or AUDEL_JWT_JWKS_FILE, or bind 127.0.0.1."
        )
    if bool(s.tls_certfile) != bool(s.tls_keyfile):
        raise SystemExit("TLS needs both AUDEL_TLS_CERTFILE and AUDEL_TLS_KEYFILE.")
    if s.tls_client_ca and not s.tls_certfile:
        raise SystemExit("Mutual TLS (AUDEL_TLS_CLIENT_CA) needs a server certificate too.")
    import ssl

    import uvicorn

    tls: dict = {}
    if s.tls_certfile:
        tls = {"ssl_certfile": str(s.tls_certfile), "ssl_keyfile": str(s.tls_keyfile)}
        if s.tls_client_ca:
            tls.update(ssl_ca_certs=str(s.tls_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED)
    # X-Forwarded-For is trusted ONLY from proxies the operator lists (default: none).
    fwd: dict = {"proxy_headers": bool(s.forwarded_allow_ips)}
    if s.forwarded_allow_ips:
        fwd["forwarded_allow_ips"] = ",".join(s.forwarded_allow_ips)
    from ..logging import uvicorn_log_config

    uvicorn.run(build_app(), host=host, port=port, log_config=uvicorn_log_config(), **tls, **fwd)


def main() -> None:
    serve()


if __name__ == "__main__":
    main()
