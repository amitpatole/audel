"""Phase 11: async jobs, URL ingestion, metrics, audit log, request ids."""

from __future__ import annotations

import asyncio
import http.server
import json
import threading
import time

import pytest

from audel.config import Settings
from audel.errors import UnsafeSourceError
from audel.ingest import fetch_to_file, url_host, validate_ingest_url
from audel.jobs import JobStore, QueueFull

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from audel.adapters.rest import build_app  # noqa: E402

TOKEN = "audel_s2GS5zbClAPZW_BX-zl1O7VUqv193uD1ZB0otjT2Tag_a2oxej7i"
AUTH = {"authorization": f"Bearer {TOKEN}"}


def _client(tmp_path, **kw):
    s = Settings(cache_dir=tmp_path, allow_local_files=False, api_token=TOKEN, **kw)
    return TestClient(build_app(settings=s))


def _wait(c, jid, timeout=60):
    t = time.time()
    while time.time() - t < timeout:
        r = c.get(f"/jobs/{jid}", headers=AUTH).json()
        if r["status"] in ("done", "failed", "cancelled"):
            return r
        time.sleep(0.2)
    raise AssertionError("job did not finish")


# ---- job store ----------------------------------------------------------------------------------

def test_job_store_scopes_by_owner_and_bounds_the_queue():
    async def scenario():
        sem = asyncio.Semaphore(1)
        store = JobStore(max_queued=2, max_stored=10, ttl_s=60, semaphore=sem,
                         max_queued_per_owner=2)
        gate = asyncio.Event()

        async def slow():
            await gate.wait()
            return {"ok": True}

        a = store.submit("tenant-a", "check", slow)
        store.submit("tenant-a", "check", slow)
        with pytest.raises(QueueFull):
            store.submit("tenant-b", "check", slow)
        assert store.get("tenant-b", a.id) is None          # not yours = not found
        assert store.get("tenant-a", a.id) is a
        assert store.list("tenant-b") == []
        gate.set()
        await asyncio.sleep(0.05)
        assert a.status == "done" and a.result == {"ok": True}

    asyncio.run(scenario())


def test_job_failure_is_recorded_not_raised_and_sanitized():
    async def scenario():
        store = JobStore(max_queued=5, max_stored=5, ttl_s=60, semaphore=asyncio.Semaphore(1))

        async def boom():
            raise RuntimeError("/srv/secret/path leaked?")

        j = store.submit("t", "check", boom)
        await asyncio.sleep(0.05)
        assert j.status == "failed" and "/srv/secret" not in (j.error or "")

    asyncio.run(scenario())


# ---- REST jobs ----------------------------------------------------------------------------------

def test_async_job_round_trip_and_audit(tmp_path, media):
    audit = tmp_path / "audit.jsonl"
    with _client(tmp_path, audit_log=audit) as c:  # persistent event loop, as under uvicorn
        _round_trip(c, media, audit)


def _round_trip(c, media, audit):
    with open(media["clipping"], "rb") as fh:
        r = c.post("/jobs", headers={**AUTH, "x-request-id": "req-abc-1"},
                   files={"file": ("a.wav", fh, "audio/wav")}, data={"kind": "check",
                                                                     "spec": "ebu_r128"})
    assert r.status_code == 202 and r.headers["x-request-id"] == "req-abc-1"
    jid = r.json()["job_id"]
    done = _wait(c, jid)
    assert done["status"] == "done" and done["result"]["verdict"] == "fail"
    assert "audio_path" not in done["result"]
    assert any(j["job_id"] == jid for j in c.get("/jobs", headers=AUTH).json()["jobs"])
    rec = [json.loads(x) for x in audit.read_text().splitlines()]
    assert rec and rec[-1]["job_id"] == jid and rec[-1]["verdict"] == "fail"
    assert rec[-1]["tenant"] == "default" and len(rec[-1]["input_sha256"]) == 64
    assert rec[-1]["request_id"] == "req-abc-1" and rec[-1]["spec"] == "ebu_r128"
    assert oct(audit.stat().st_mode & 0o777) == "0o600"
    assert c.delete(f"/jobs/{jid}", headers=AUTH).status_code == 200
    assert c.get(f"/jobs/{jid}", headers=AUTH).status_code == 404


def test_jobs_require_auth_and_unknown_ids_are_404(tmp_path):
    c = _client(tmp_path)
    assert c.get("/jobs/abc").status_code == 401
    assert c.get("/jobs/" + "0" * 32, headers=AUTH).status_code == 404


def test_job_queue_full_returns_429(tmp_path, media):
    c = _client(tmp_path, max_queued_jobs=0)
    with open(media["good"], "rb") as fh:
        r = c.post("/jobs", headers=AUTH, files={"file": ("a.wav", fh, "audio/wav")})
    assert r.status_code == 429 and r.headers.get("retry-after") == "30"


def test_job_rejects_bad_kind_and_both_or_neither_inputs(tmp_path, media):
    c = _client(tmp_path)
    assert c.post("/jobs", headers=AUTH, data={"kind": "rm -rf"}).status_code == 400
    assert c.post("/jobs", headers=AUTH, data={"kind": "check"}).status_code == 400


def test_metrics_exposed_behind_auth(tmp_path, media):
    c = _client(tmp_path)
    assert c.get("/metrics").status_code == 401
    with open(media["good"], "rb") as fh:
        c.post("/check", headers=AUTH, files={"file": ("a.wav", fh, "audio/wav")})
    body = c.get("/metrics", headers=AUTH).text
    assert 'audel_requests_total{route="/check",status="200"} 1' in body
    assert "audel_grade_seconds_count" in body and "audel_build_info" in body


def test_metrics_route_labels_are_closed(tmp_path):
    c = _client(tmp_path)
    for i in range(5):
        c.get(f"/nope-{i}", headers=AUTH)
    body = c.get("/metrics", headers=AUTH).text
    assert "nope" not in body and 'route="other"' in body


def test_request_id_is_sanitized(tmp_path):
    c = _client(tmp_path)
    r = c.get("/healthz", headers={"x-request-id": "evil\nInjected: header"})
    assert "\n" not in r.headers["x-request-id"] and len(r.headers["x-request-id"]) == 32


# ---- URL ingestion ------------------------------------------------------------------------------

def _s(**kw):
    return Settings(allow_url_ingest=True, **kw)


def test_ingest_is_off_by_default():
    with pytest.raises(UnsafeSourceError, match="disabled"):
        validate_ingest_url("https://example.com/a.wav", Settings())


@pytest.mark.parametrize("url", [
    "http://example.com/a.wav",                 # http not allowed by default
    "https://user:pw@example.com/a.wav",        # credentials
    "https://example.com:8443/a.wav",           # odd port
    "file:///etc/passwd", "ftp://example.com/a.wav", "gopher://x/",
    "https://exa mple.com/a.wav", "",
])
def test_ingest_url_shape_rules(url):
    with pytest.raises(UnsafeSourceError):
        validate_ingest_url(url, _s())


def test_ingest_host_allowlist_suffix_match():
    s = _s(ingest_allowed_hosts=[".s3.amazonaws.com"])
    validate_ingest_url("https://media.s3.amazonaws.com/x.wav?X-Amz-Signature=abc", s)
    for bad in ("https://evil.com/x.wav", "https://s3.amazonaws.com.evil.com/x.wav"):
        with pytest.raises(UnsafeSourceError):
            validate_ingest_url(bad, s)


def test_url_host_never_includes_the_signature():
    assert url_host("https://b.s3.amazonaws.com/k.wav?X-Amz-Signature=SECRET") == "b.s3.amazonaws.com"


@pytest.mark.parametrize("target", ["http://127.0.0.1:9/a.wav", "http://169.254.169.254/latest",
                                    "http://10.0.0.5/a.wav", "http://[::1]/a.wav"])
def test_ingest_blocks_internal_targets_through_the_proxy(tmp_path, target):
    with pytest.raises(UnsafeSourceError):
        asyncio.run(fetch_to_file(target, tmp_path, _s(ingest_allow_http=True)))
    assert list(tmp_path.iterdir()) == []  # nothing left behind


class _Srv(http.server.BaseHTTPRequestHandler):
    payload = b""
    redirect_to: str | None = None

    def do_GET(self):  # noqa: N802
        if _Srv.redirect_to:
            self.send_response(302)
            self.send_header("Location", _Srv.redirect_to)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(_Srv.payload)))
        self.end_headers()
        self.wfile.write(_Srv.payload)

    def log_message(self, *a):
        pass


@pytest.fixture
def origin(monkeypatch):
    """A local origin standing in for an object store. Only the proxy's address vetting is
    relaxed for 127.0.0.1 (the SSRF rule itself is covered by the test above)."""
    import audel.proxy as proxy_mod

    real = proxy_mod.resolve_safe_ip

    async def allow_local(host, port):
        return "127.0.0.1" if host in ("127.0.0.1", "localhost") else await real(host, port)

    monkeypatch.setattr(proxy_mod, "resolve_safe_ip", allow_local)
    monkeypatch.setattr(proxy_mod, "_ALLOWED_PORTS", frozenset(range(1, 65536)))  # local origin
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Srv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    _Srv.redirect_to = None


def test_ingest_end_to_end_through_the_proxy(tmp_path, media, origin, monkeypatch):
    import audel.ingest as ing

    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)  # local port is not 80/443
    _Srv.payload = media["good"].read_bytes()
    out = asyncio.run(fetch_to_file(f"{origin}/clip.wav?sig=SECRET", tmp_path,
                                    _s(ingest_allow_http=True)))
    assert out.read_bytes() == _Srv.payload and out.suffix == ".wav"


def test_ingest_byte_cap_enforced(tmp_path, origin, monkeypatch):
    import audel.ingest as ing

    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    _Srv.payload = b"x" * 5000
    with pytest.raises(UnsafeSourceError, match="cap"):
        asyncio.run(fetch_to_file(f"{origin}/big.wav", tmp_path,
                                  _s(ingest_allow_http=True, max_media_bytes=1000)))
    assert list(tmp_path.iterdir()) == []


def test_ingest_redirect_to_ftp_or_internal_is_refused(tmp_path, origin, monkeypatch):
    import audel.ingest as ing

    real = ing.validate_ingest_url
    first = {"done": False}

    def only_first_skips(u, s):  # the initial local URL passes; every redirect hop is checked
        if not first["done"]:
            first["done"] = True
            return None
        return real(u, s)

    for target in ("ftp://example.com/a.wav", "http://169.254.169.254/latest/meta-data"):
        first["done"] = False
        monkeypatch.setattr(ing, "validate_ingest_url", only_first_skips)
        _Srv.redirect_to = target
        with pytest.raises(UnsafeSourceError):
            asyncio.run(fetch_to_file(f"{origin}/r.wav", tmp_path, _s(ingest_allow_http=True)))


def test_rest_url_ingest_disabled_by_default(tmp_path):
    c = _client(tmp_path)
    r = c.post("/check", headers=AUTH, data={"url": "https://example.com/a.wav"})
    assert r.status_code == 400 and "disabled" in r.text


def test_purge_reaps_only_stale_regular_files(tmp_path):
    import os

    from audel.workspace import Workspace

    ws = Workspace(Settings(cache_dir=tmp_path))
    old, new = ws.tmp / "upload_old.wav", ws.tmp / "upload_new.wav"
    old.write_bytes(b"x")
    new.write_bytes(b"x")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    outside = tmp_path / "keep.txt"
    outside.write_text("k")
    link = ws.tmp / "link"
    link.symlink_to(outside)
    os.utime(link, (time.time() - 7200, time.time() - 7200), follow_symlinks=False)
    assert ws.purge_tmp(3600) == 1
    assert not old.exists() and new.exists() and outside.exists()
