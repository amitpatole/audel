"""Phase 6 security: the REST service auth, body caps, backend allowlist, SSRF, and info-leak guards.

Each control is exercised against a live FastAPI TestClient (the real middleware + handlers)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from audel.adapters.rest import build_app, serve  # noqa: E402
from audel.config import Settings  # noqa: E402


def _app(tmp_path, **settings_kw):
    s = Settings(cache_dir=tmp_path, **settings_kw)
    return build_app(settings=s)


# ---- auth (constant-time bearer, loopback zero-config) -------------------------

def test_healthz_is_public(tmp_path):
    c = TestClient(_app(tmp_path, api_token="secrettoken123456"))
    assert c.get("/healthz").status_code == 200


def test_loopback_zero_config_no_token(tmp_path):
    c = TestClient(_app(tmp_path))  # no token set
    assert c.get("/doctor").status_code == 200


def test_token_required_when_set(tmp_path):
    c = TestClient(_app(tmp_path, api_token="secrettoken123456"))
    assert c.get("/doctor").status_code == 401                       # missing
    assert c.get("/doctor", headers={"authorization": "Bearer wrong"}).status_code == 401
    ok = c.get("/doctor", headers={"authorization": "Bearer secrettoken123456"})
    assert ok.status_code == 200


def test_serve_refuses_non_loopback_without_token(tmp_path, monkeypatch):
    monkeypatch.delenv("AUDEL_API_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        serve(host="0.0.0.0", port=8000)  # would expose a routable bind with no auth -> refuse


def test_non_ascii_auth_header_is_401_not_500(tmp_path):
    # R1: a crafted Authorization header with a non-ASCII (latin-1) byte must not crash the auth
    # check (str hmac.compare_digest would TypeError -> 500). Drive the ASGI app with a raw header.
    import asyncio

    app = _app(tmp_path, api_token="secrettoken123456")
    statuses: list[int] = []

    async def drive():
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                statuses.append(msg["status"])

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
                 "path": "/doctor", "raw_path": b"/doctor", "query_string": b"", "root_path": "",
                 "scheme": "http", "server": ("127.0.0.1", 8000), "client": ("127.0.0.1", 9999),
                 "headers": [(b"authorization", b"Bearer \xe9vil")]}
        await app(scope, receive, send)

    asyncio.run(drive())
    assert statuses == [401]


def test_schema_endpoints_hidden_when_token_set(tmp_path):
    # R1: /openapi.json & /docs are NOT covered by the auth dependency; in exposed mode they must
    # not leak the API surface to unauthenticated callers.
    hardened = TestClient(_app(tmp_path, api_token="secrettoken123456"))
    auth = {"authorization": "Bearer secrettoken123456"}
    assert hardened.get("/openapi.json").status_code == 401              # unauth: gated
    assert hardened.get("/openapi.json", headers=auth).status_code == 404  # even authed: disabled
    assert hardened.get("/docs", headers=auth).status_code == 404
    # loopback zero-config (no token) keeps docs for dev convenience
    dev = TestClient(_app(tmp_path))
    assert dev.get("/openapi.json").status_code == 200


# ---- DoS: body-size cap -------------------------------------------------------

def test_oversized_body_rejected_by_header_cap(tmp_path):
    c = TestClient(_app(tmp_path, max_request_bytes=100))
    r = c.post("/check", files={"file": ("a.wav", b"X" * 5000, "audio/wav")})
    assert r.status_code == 413


def test_unauthenticated_request_rejected_before_body_buffered(tmp_path):
    # R2: auth runs in the middleware BEFORE the body is read, so an unauthenticated caller can't
    # make the server buffer up to max_request_bytes (DoS amplification). No token header -> 401,
    # not 413, even with an over-cap body.
    c = TestClient(_app(tmp_path, api_token="secrettoken123456", max_request_bytes=100))
    r = c.post("/check", files={"file": ("a.wav", b"X" * 5000, "audio/wav")})
    assert r.status_code == 401  # rejected on auth, body never buffered/capped


def test_upload_spool_enforces_cap(media, tmp_path):
    # A body that slips under the request cap but a file over a tighter internal limit still 413s.
    c = TestClient(_app(tmp_path, max_request_bytes=200))
    data = media["good"].read_bytes()
    r = c.post("/check", files={"file": ("good.wav", data, "audio/wav")})
    assert r.status_code == 413


# ---- backend allowlist (no remote egress redirection) -------------------------

def test_remote_caller_cannot_pick_backend(media, tmp_path):
    c = TestClient(_app(tmp_path))  # rest_enabled_backends defaults to []
    data = media["good"].read_bytes()
    r = c.post("/analyze", files={"file": ("g.wav", data, "audio/wav")},
               data={"backend": "ollama"})
    assert r.status_code == 400 and "not enabled" in r.json()["detail"]


def test_allowlisted_backend_is_accepted_offline(media, tmp_path):
    # 'local' is offline ASR; allow it and the request is admitted (no egress, no key needed).
    c = TestClient(_app(tmp_path, rest_enabled_backends=["local"]))
    data = media["good"].read_bytes()
    r = c.post("/analyze", files={"file": ("g.wav", data, "audio/wav")},
               data={"backend": "local"})
    assert r.status_code == 200


# ---- SSRF + host-file read (the /watch URL path) ------------------------------

@pytest.mark.parametrize("url", ["http://169.254.169.254/", "http://127.0.0.1:22/", "http://10.0.0.1/"])
def test_watch_internal_url_grades_fail_not_fetched(tmp_path, url):
    c = TestClient(_app(tmp_path))
    r = c.post("/watch", json={"source": url})
    assert r.status_code == 200 and r.json()["verdict"] == "fail"  # SSRF refused -> graded, not fetched


def test_watch_local_path_is_not_read(tmp_path):
    # a bare host path is not http(s); allow_local_files=False -> refused, never read back.
    c = TestClient(_app(tmp_path))
    r = c.post("/watch", json={"source": "/etc/passwd"})
    assert r.status_code == 200
    body = r.text
    assert r.json()["verdict"] == "fail" and "root:" not in body  # no file contents leak


# ---- info leak: server temp path never returned -------------------------------

def test_audio_path_stripped_from_response(media, tmp_path):
    c = TestClient(_app(tmp_path))
    data = media["good"].read_bytes()
    r = c.post("/check", files={"file": ("g.wav", data, "audio/wav")})
    assert r.status_code == 200
    j = r.json()
    assert "audio_path" not in j and j["verdict"] == "pass"
    assert "/tmp" not in r.text and "upload_" not in r.text  # no server temp path leaks


def test_empty_upload_rejected(tmp_path):
    c = TestClient(_app(tmp_path))
    r = c.post("/check", files={"file": ("empty.wav", b"", "audio/wav")})
    assert r.status_code == 400


# ---- error sanitization -------------------------------------------------------

def test_garbage_upload_gives_generic_error_no_internals(media, tmp_path):
    c = TestClient(_app(tmp_path))
    r = c.post("/check", files={"file": ("x.wav", b"not real audio bytes" * 10, "audio/wav")})
    # decode fails -> a clean report (FAIL) or a sanitized 400; never a stack trace / host path.
    assert r.status_code in (200, 400)
    assert "Traceback" not in r.text and "/home/" not in r.text
