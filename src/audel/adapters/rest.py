"""REST service (FastAPI) — for non-MCP / networked / CI agents.

Security (mirrors AgentVision's rest.py, the reviewed sibling template):
- Provider keys are read server-side only, NEVER accepted in a request; per-request backend
  selection is limited to the server's allowlist (``rest_enabled_backends``), so a remote caller
  cannot redirect egress or pick a paid model.
- Bearer-token auth in CONSTANT time (``hmac.compare_digest``); zero-config on loopback, REQUIRED
  once a token is set; binding a non-loopback host without a token is refused in :func:`serve`.
- Request bodies are capped (Content-Length AND the raw stream, so a chunked upload can't bypass);
  heavy jobs run behind a concurrency semaphore (DoS bound).
- Audio enters ONLY as a multipart upload written to a server-named temp file — a remote caller can
  never make the service read a host file by path (``allow_local_files=False`` for path sources).
  The one URL path (``/watch``) keeps the SSRF guard ON (``block_private_networks``).
- Errors are sanitized: only ``UnsafeSourceError`` text is returned; everything else is logged
  server-side and the caller gets a generic message (no host paths/IPs leak). ``audio_path`` (a
  server temp path) is stripped from every response.
"""

from __future__ import annotations

import asyncio
import hmac
import uuid
from pathlib import Path

from ..config import Settings, load_settings
from ..errors import AudelError, MissingDependencyError, UnsafeSourceError
from ..logging import get_logger
from ..models import Brief, Report

try:
    from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
    from fastapi.responses import JSONResponse
except ImportError:  # pragma: no cover - only without the [serve] extra
    FastAPI = None  # type: ignore

log = get_logger("rest")
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}


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


def build_app(settings: Settings | None = None):
    if FastAPI is None:
        raise MissingDependencyError("REST service needs FastAPI; pip install audel[serve]")

    from .. import __version__

    # Service hardening: a remote caller must not read host files via a bare-path source. Grading
    # only ever runs on server-written temp files, so path sources are disabled service-wide.
    settings = settings or load_settings(allow_local_files=False)
    # A separate settings for grading our OWN temp uploads (server-named paths only — never caller
    # controlled), so validate_source accepts them while caller path-sources stay refused.
    grade_settings = settings.model_copy(update={"allow_local_files": True})

    def _auth(request: Request):
        """Bearer-token auth (constant-time). /healthz is exempt; loopback is zero-config."""
        if request.url.path == "/healthz":
            return
        if _unauthorized(request):
            raise HTTPException(status_code=401, detail="Unauthorized")

    def _unauthorized(request: Request) -> bool:
        """True if the request must be rejected. /healthz is exempt; loopback is zero-config."""
        if request.url.path == "/healthz":
            return False
        token = settings.api_token
        if not token:
            return False
        provided = request.headers.get("authorization", "")
        # Compare as BYTES: headers are latin-1 decoded by Starlette, and hmac.compare_digest on a
        # str with a non-ASCII char raises TypeError (a crafted header would 500 instead of 401).
        return not hmac.compare_digest(provided.encode("utf-8", "ignore"),
                                       f"Bearer {token}".encode())

    # FastAPI's auto-doc routes (/docs, /redoc, /openapi.json) are NOT covered by router-level
    # dependencies, so they'd leak the API schema to unauthenticated callers. When a token is set
    # (the service is meant to be exposed), disable them; keep them for loopback zero-config dev.
    app = FastAPI(title="Audel", version=__version__, dependencies=[Depends(_auth)],
                  openapi_url=(None if settings.api_token else "/openapi.json"))
    _job_sem = asyncio.Semaphore(settings.max_concurrent_jobs)
    _ws_marker = str(settings.cache_dir)  # redacted from error detail (no temp-path leak)

    @app.middleware("http")
    async def _gate(request: Request, call_next):
        # Authenticate BEFORE buffering the body — an unauthenticated caller must not be able to
        # make the server read up to max_request_bytes (DoS amplification).
        if _unauthorized(request):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        cap = settings.max_request_bytes
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > cap:
            return JSONResponse({"detail": "Request body too large."}, status_code=413)
        # Enforce on the stream too — a chunked request (no Content-Length) would otherwise buffer
        # unbounded past the header check.
        total = 0
        chunks: list[bytes] = []
        async for chunk in request.stream():
            total += len(chunk)
            if total > cap:
                return JSONResponse({"detail": "Request body too large."}, status_code=413)
            chunks.append(chunk)
        body = b"".join(chunks)

        async def _replay():
            return {"type": "http.request", "body": body, "more_body": False}

        request._body = body
        request._receive = _replay
        return await call_next(request)

    async def _job_slot():
        async with _job_sem:
            yield

    def _http_error(e: Exception) -> HTTPException:
        if isinstance(e, UnsafeSourceError):
            # Safe to surface, but redact any server workspace path the message may embed.
            return HTTPException(status_code=400, detail=str(e).replace(_ws_marker, "<workspace>"))
        log.warning("request failed: %s: %s", type(e).__name__, e)
        return HTTPException(status_code=400, detail="Could not decode or grade the source.")

    def _check_backend(name: str | None):
        if name and name not in settings.rest_enabled_backends:
            raise HTTPException(
                status_code=400,
                detail=f"Backend {name!r} is not enabled on this server. "
                       f"Allowed: {settings.rest_enabled_backends or '(none — server default only)'}",
            )

    async def _spool(upload: UploadFile) -> Path:
        """Write an uploaded file to a server-NAMED temp file under the workspace (path is never
        caller-controlled). The body middleware already capped total bytes; re-check defensively."""
        from ..workspace import Workspace

        ws = Workspace(settings)
        suffix = Path(upload.filename or "").suffix[:10] if upload.filename else ""
        suffix = "".join(c for c in suffix if c.isalnum() or c == ".")  # strip any path chars
        dest = ws.tmp / f"upload_{uuid.uuid4().hex[:16]}{suffix}"
        total = 0
        cap = settings.max_request_bytes
        with open(dest, "wb") as fh:
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

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/doctor")
    def doctor_ep():
        from .doctor import run_checks

        return {"checks": [{"name": c.name, "ok": c.ok, "detail": c.detail}
                           for c in run_checks(settings)]}

    @app.post("/check")
    async def check_ep(file: UploadFile = File(...), brief: str | None = Form(None),
                       expect: list[str] | None = Form(None), _slot=Depends(_job_slot)):
        """Deterministic grade of an uploaded clip (no LLM, no egress)."""
        from ..core import check

        dest = None
        try:
            dest = await _spool(file)
            report = await check(str(dest), settings=grade_settings, brief=_brief_from(brief, expect))
            return _public(report)
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if dest is not None:
                dest.unlink(missing_ok=True)

    @app.post("/analyze")
    async def analyze_ep(file: UploadFile = File(...), brief: str | None = Form(None),
                         expect: list[str] | None = Form(None), backend: str | None = Form(None),
                         _slot=Depends(_job_slot)):
        """Full grade (signals + ASR + backend critique). Egress only to the server's backend."""
        from ..core import analyze

        _check_backend(backend)
        dest = None
        try:
            dest = await _spool(file)
            report = await analyze(str(dest), settings=grade_settings,
                                   brief=_brief_from(brief, expect), backend=backend)
            return _public(report)
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if dest is not None:
                dest.unlink(missing_ok=True)

    @app.post("/render")
    async def render_ep(file: UploadFile = File(...), _slot=Depends(_job_slot)):
        """Decode to trustworthy signals (loudness/true-peak/RMS/silent spans)."""
        from ..core import render

        dest = None
        try:
            dest = await _spool(file)
            rr = await render(str(dest), settings=grade_settings)
            return {"duration_ms": rr.duration_ms, "channels": rr.channels,
                    "sample_rate": rr.sample_rate, "codec": rr.codec, "has_audio": rr.has_audio,
                    "integrated_lufs": rr.integrated_lufs, "true_peak_dbtp": rr.true_peak_dbtp,
                    "rms_dbfs": rr.rms_dbfs, "lra": rr.lra, "silences": len(rr.silences)}
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if dest is not None:
                dest.unlink(missing_ok=True)

    @app.post("/handoff")
    async def handoff_ep(file: UploadFile = File(...), brief: str | None = Form(None),
                         expect: list[str] | None = Form(None), backend: str | None = Form(None),
                         _slot=Depends(_job_slot)):
        """Grade + return the distilled ears→brain handoff (verdict + next action + todo)."""
        from ..core import analyze

        _check_backend(backend)
        dest = None
        try:
            dest = await _spool(file)
            report = await analyze(str(dest), settings=grade_settings,
                                   brief=_brief_from(brief, expect), backend=backend)
            return report.to_handoff().model_dump(mode="json")
        except AudelError as e:
            raise _http_error(e) from e
        finally:
            if dest is not None:
                dest.unlink(missing_ok=True)

    @app.post("/watch")
    async def watch_ep(body: dict, _slot=Depends(_job_slot)):
        """Temporal grade of an http(s) URL (does the audio play THROUGH?). SSRF-guarded."""
        from ..core import watch

        source = body.get("source")
        if not isinstance(source, str) or not source:
            raise HTTPException(status_code=400, detail="watch requires a JSON {\"source\": url}.")
        try:
            report = await watch(source, settings=settings,  # allow_local_files=False here (URL only)
                                 click_selector=body.get("click_selector"))
            return _public(report)
        except AudelError as e:
            raise _http_error(e) from e

    return app


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    # Fail closed: never expose a routable interface without a token.
    if not _is_loopback(host) and not load_settings().api_token:
        raise SystemExit(
            f"Refusing to bind non-loopback host {host!r} without auth. Set AUDEL_API_TOKEN to "
            "expose the service (clients send 'Authorization: Bearer <token>'), or bind 127.0.0.1."
        )
    import uvicorn

    uvicorn.run(build_app(), host=host, port=port)


def main() -> None:
    serve()


if __name__ == "__main__":
    main()
