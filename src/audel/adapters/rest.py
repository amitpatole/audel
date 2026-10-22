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
import hashlib
import os
import time
import uuid
from pathlib import Path

from ..auth import Authenticator, Principal, RateLimiter, client_key
from ..config import Settings, load_settings
from ..errors import (
    AudelError,
    ConfigError,
    MissingDependencyError,
    UnsafeSourceError,
    sanitize_message,
)
from ..logging import get_logger
from ..models import Brief, Report

try:
    from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
    from fastapi.responses import JSONResponse, PlainTextResponse
except ImportError:  # pragma: no cover - only without the [serve] extra
    FastAPI = None  # type: ignore

log = get_logger("rest")
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}
_KINDS = ("check", "listen", "analyze")
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
    if raw and 0 < len(raw) <= 64 and set(raw) <= _REQUEST_ID_OK:
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
    _job_sem = asyncio.Semaphore(settings.max_concurrent_jobs)
    jobs = JobStore(max_queued=settings.max_queued_jobs, max_stored=settings.max_stored_jobs,
                    ttl_s=settings.job_result_ttl_s, semaphore=_job_sem)
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
        # Authenticate BEFORE the body is read: an unauthenticated caller must not be able to
        # make the server read up to max_request_bytes (DoS amplification).
        principal = auth.authenticate(request.headers.get("authorization"))
        if principal is None:
            # Failures are throttled per client address; a VALID credential is never blocked by
            # someone else's failures (shared NAT / load-balancer addresses).
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
        if cl and cl.isdigit() and int(cl) > settings.max_request_bytes:
            return reply(JSONResponse({"detail": "Request body too large."}, status_code=413))
        # The streamed body is capped by _BodyLimit (no whole-body buffering in memory).
        return reply(await call_next(request))

    app.add_middleware(_BodyLimit, cap=settings.max_request_bytes)

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

    async def _shielded(coro_factory, timeout: float):
        return await run_shielded(_work_sem, coro_factory, timeout)

    async def _job_slot():
        async with _job_sem:
            metrics.inflight += 1
            try:
                yield
            finally:
                metrics.inflight -= 1

    def _http_error(e: Exception) -> HTTPException:
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
            if not sep or not idx.strip().isdigit() or len(langs) >= 32:
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
        with os.fdopen(fd, "wb") as fh:
            while True:
                chunk = await upload.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    fh.close()
                    dest.unlink(missing_ok=True)
                    raise UnsafeSourceError("uploaded file exceeds the size cap")
                fh.write(chunk)
        if total == 0:
            dest.unlink(missing_ok=True)
            raise UnsafeSourceError("uploaded file is empty")
        return dest

    async def _acquire(file: UploadFile | None, url: str | None) -> tuple[Path, str, str | None]:
        """(server temp path, source kind, source host). Exactly one of file / url."""
        if (file is None) == (not url):
            raise UnsafeSourceError("send exactly one of: a 'file' upload or a 'url'")
        if file is not None:
            return await _spool(file), "upload", None
        from ..ingest import fetch_to_file, url_host
        from ..workspace import Workspace

        assert url is not None
        return await fetch_to_file(url, Workspace(settings).tmp, settings), "url", url_host(url)

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
        if kind not in _KINDS:
            raise HTTPException(status_code=400, detail=f"kind must be one of {', '.join(_KINDS)}")
        if p.get("understand") and not settings.rest_allow_understand:
            raise HTTPException(status_code=403, detail="understand is disabled on this server.")
        _check_backend(p.get("backend"))
        p = {**p, "spec": _spec_for(p.get("spec")), "languages": _languages(p.get("language"))}
        return p, _settings_for(p.get("content"))

    async def _run_and_audit(kind: str, path: Path, src: str, host: str | None, p: dict,
                             gs: Settings, principal: Principal, request_id: str,
                             job_id: str | None = None) -> dict:
        t0 = time.monotonic()
        digest, size = await asyncio.to_thread(_sha256, path)
        status, verdict, n_issues, err = "ok", None, None, None
        try:
            report = await _shielded(lambda: _grade(kind, path, p, gs),
                                     settings.request_timeout_s)
            verdict, n_issues = report.verdict.value, len(report.issues)
            return _public(report)
        except TimeoutError:
            status, err = "timeout", "timeout"
            raise UnsafeSourceError(f"grading exceeded {settings.request_timeout_s:.0f}s") from None
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
            path, src, host = await _acquire(file, url)
            return await _run_and_audit(kind, path, src, host, p, gs, _principal(request),
                                        request.state.request_id)
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    @app.post("/check")
    async def check_ep(request: Request, file: UploadFile | None = File(None),
                       url: str | None = Form(None), brief: str | None = Form(None),
                       expect: list[str] | None = Form(None), spec: str | None = Form(None),
                       content: str | None = Form(None), _slot=Depends(_job_slot)):
        """Deterministic grade (no LLM, no egress except an opted-in URL fetch)."""
        return await _sync(request, "check", file, url, {"brief": brief, "expect": expect,
                                                         "spec": spec, "content": content})

    @app.post("/analyze")
    async def analyze_ep(request: Request, file: UploadFile | None = File(None),
                         url: str | None = Form(None), brief: str | None = Form(None),
                         expect: list[str] | None = Form(None), backend: str | None = Form(None),
                         spec: str | None = Form(None), content: str | None = Form(None),
                         _slot=Depends(_job_slot)):
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
                        brief: str | None = Form(None), expect: list[str] | None = Form(None),
                        _slot=Depends(_job_slot)):
        """Hear and listen: signal QC plus script / wording / pace / captions (offline). With
        ``understand`` (operator opt-in), key messages and delivery via the server's backend."""
        return await _sync(request, "listen", file, url, {
            "script": script, "captions": captions, "require": require, "forbid": forbid,
            "language": language, "key_message": key_message, "tone": tone,
            "understand": understand, "backend": backend, "spec": spec, "content": content,
            "brief": brief, "expect": expect})

    @app.post("/render")
    async def render_ep(request: Request, file: UploadFile | None = File(None),
                        url: str | None = Form(None), _slot=Depends(_job_slot)):
        """Decode to trustworthy signals (loudness / true peak / RMS / silent spans, per track)."""
        from ..core import render

        path = None
        try:
            path, _src, _host = await _acquire(file, url)
            rr = await render(str(path), settings=grade_settings)
            return {"duration_ms": rr.duration_ms, "channels": rr.channels,
                    "sample_rate": rr.sample_rate, "codec": rr.codec, "has_audio": rr.has_audio,
                    "integrated_lufs": rr.integrated_lufs, "true_peak_dbtp": rr.true_peak_dbtp,
                    "rms_dbfs": rr.rms_dbfs, "lra": rr.lra, "silences": len(rr.silences),
                    "tracks": [t.model_dump(mode="json") for t in rr.tracks]}
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    @app.post("/handoff")
    async def handoff_ep(request: Request, file: UploadFile | None = File(None),
                         url: str | None = Form(None), brief: str | None = Form(None),
                         expect: list[str] | None = Form(None), backend: str | None = Form(None),
                         _slot=Depends(_job_slot)):
        """Grade + return the distilled ears→brain handoff (verdict + next action + todo)."""
        from ..core import analyze

        _check_backend(backend)
        path = None
        try:
            path, _src, _host = await _acquire(file, url)
            report = await analyze(str(path), settings=grade_settings,
                                   brief=_brief_from(brief, expect), backend=backend)
            return report.to_handoff().model_dump(mode="json")
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    @app.post("/watch")
    async def watch_ep(body: dict, _slot=Depends(_job_slot)):
        """Temporal grade of an http(s) URL (does the audio play THROUGH?). SSRF-guarded."""
        from ..core import watch

        if not settings.rest_allow_watch:
            raise HTTPException(status_code=403, detail="watch is disabled on this server.")
        source = body.get("source")
        if not isinstance(source, str) or not source:
            raise HTTPException(status_code=400, detail="watch requires a JSON {\"source\": url}.")
        try:
            report = await watch(source, settings=settings,  # allow_local_files=False here (URL only)
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
        if jobs.pending() >= settings.max_queued_jobs:
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

        async def work() -> dict:
            path = spooled
            src, host = "upload", None
            try:
                if path is None:
                    path, src, host = await _acquire(None, url)
                return await _run_and_audit(kind, path, src, host, p, gs, principal, rid,
                                            job_id=holder.get("id"))
            finally:
                if path is not None:
                    path.unlink(missing_ok=True)

        try:
            job = jobs.submit(principal.tenant, kind, work)
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


async def run_shielded(sem: asyncio.Semaphore, coro_factory, timeout: float):
    """Run grading so its concurrency slot is held until the work REALLY ends.

    A request timeout or a job cancel must not free the slot while ffmpeg/ASR threads keep
    running (that would let a caller pile up unbounded background work). Work abandoned before it
    acquired a slot is skipped entirely."""
    abandoned = asyncio.Event()

    async def guarded():
        async with sem:
            if abandoned.is_set():
                return None
            return await coro_factory()

    task = asyncio.create_task(guarded())
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
    except (TimeoutError, asyncio.CancelledError):
        abandoned.set()
        raise


class _BodyLimit:
    """Pure-ASGI request-body cap, enforced on the STREAM as it is read (chunked uploads
    included) without buffering the whole body in memory. Past the cap the app's response is
    replaced by 413."""

    def __init__(self, app, cap: int) -> None:
        self.app, self.cap = app, cap

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        total = 0
        exceeded = False
        sent_ours = False

        async def recv():
            nonlocal total, exceeded
            msg = await receive()
            if msg.get("type") == "http.request":
                total += len(msg.get("body", b""))
                if total > self.cap:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return msg

        async def snd(msg):
            nonlocal sent_ours
            if not exceeded:
                return await send(msg)
            if sent_ours:
                return None
            sent_ours = True
            body = b'{"detail":"Request body too large."}'
            await send({"type": "http.response.start", "status": 413,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})

        try:
            await self.app(scope, recv, snd)
        except Exception:
            if not exceeded:
                raise
        if exceeded and not sent_ours:
            await snd({"type": "http.response.start"})


_ROUTES = frozenset({"/healthz", "/doctor", "/metrics", "/specs", "/check", "/analyze", "/listen",
                     "/render", "/handoff", "/watch", "/jobs"})


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    # Fail closed: never expose a routable interface without auth.
    s = load_settings()
    if not _is_loopback(host) and not Authenticator(s).required:
        raise SystemExit(
            f"Refusing to bind non-loopback host {host!r} without auth. Set AUDEL_API_TOKEN, "
            "AUDEL_API_TOKENS_FILE or AUDEL_JWT_JWKS_FILE to expose the service, or bind 127.0.0.1."
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
    uvicorn.run(build_app(), host=host, port=port, **tls, **fwd)


def main() -> None:
    serve()


if __name__ == "__main__":
    main()
