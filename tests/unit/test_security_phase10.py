"""Phase 10 security: the on-prem backend path, backend HTTP hardening, and the /listen surface.

Every test is an exploit attempt that must be refused."""

from __future__ import annotations

import http.server
import json
import threading

import pytest

from audel.config import Settings
from audel.errors import UnsafeSourceError
from audel.netguard import assert_backend_url, post_json

# ---- trusted-host vetting ---------------------------------------------------------------------

def test_private_backend_refused_unless_operator_trusts_it():
    with pytest.raises(UnsafeSourceError):
        assert_backend_url("http://10.0.0.100:11434/api/chat")
    assert_backend_url("http://10.0.0.100:11434/api/chat", ["10.0.0.100"])  # trusted: ok


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",     # cloud metadata
    "http://[fe80::1]:11434/api/chat",            # link-local
    "http://0.0.0.0:11434/api/chat",              # unspecified
    "http://224.0.0.1:11434/api/chat",            # multicast
])
def test_trust_never_reaches_metadata_or_link_local(url):
    from urllib.parse import urlparse

    host = urlparse(url).hostname
    with pytest.raises(UnsafeSourceError):
        assert_backend_url(url, [host])


def test_backend_url_rejects_embedded_credentials_and_odd_schemes():
    with pytest.raises(UnsafeSourceError):
        assert_backend_url("http://user:pw@10.0.0.100:11434/", ["10.0.0.100"])
    with pytest.raises(UnsafeSourceError):
        assert_backend_url("file:///etc/passwd", ["localhost"])
    with pytest.raises(UnsafeSourceError):
        assert_backend_url("gopher://10.0.0.100/", ["10.0.0.100"])


def test_trust_is_exact_host_match():
    with pytest.raises(UnsafeSourceError):
        assert_backend_url("http://10.0.0.101:11434/", ["10.0.0.100"])
    with pytest.raises(UnsafeSourceError):
        assert_backend_url("http://10.0.0.1000.example/", ["10.0.0.100"])


# ---- backend HTTP: no redirects, bounded response ---------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    mode = "redirect"

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("content-length") or 0))
        if _Handler.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
            self.end_headers()
        else:
            body = b'{"x": "' + b"A" * 3_000_000 + b'"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/api/chat"
    srv.shutdown()


def test_backend_redirect_to_metadata_is_refused(server):
    _Handler.mode = "redirect"
    with pytest.raises(UnsafeSourceError, match="redirect"):
        post_json(server, {"a": 1}, timeout_s=5)


def test_backend_response_is_size_capped(server):
    _Handler.mode = "big"
    with pytest.raises(UnsafeSourceError, match="bytes"):
        post_json(server, {"a": 1}, timeout_s=5, max_bytes=1_000_000)


def test_local_backend_redirect_surfaces_as_backend_error(server):
    import asyncio

    from audel.backends.ollama_local import LocalLLMBackend
    from audel.errors import BackendError

    _Handler.mode = "redirect"
    be = LocalLLMBackend(Settings(local_llm_url=server.rsplit("/api/chat", 1)[0],
                                  trusted_backend_hosts=["127.0.0.1"]))
    with pytest.raises(BackendError):
        asyncio.run(be.complete_text("s", "u"))


def test_local_backend_refuses_an_oversized_audio_excerpt(tmp_path):
    import asyncio

    from audel.backends.ollama_local import LocalLLMBackend

    big = tmp_path / "big.wav"
    big.write_bytes(b"\0" * 5_000_000)
    be = LocalLLMBackend(Settings(local_llm_url="http://10.0.0.100:11434",
                                  trusted_backend_hosts=["10.0.0.100"]))
    with pytest.raises(UnsafeSourceError):
        asyncio.run(be.critique_audio(str(big), "p"))


# ---- REST /listen -----------------------------------------------------------------------------

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from audel.adapters.rest import build_app  # noqa: E402


def _client(tmp_path, **kw):
    return TestClient(build_app(settings=Settings(cache_dir=tmp_path, allow_local_files=False, **kw)))


def test_rest_understand_is_off_unless_the_operator_enables_it(tmp_path, media):
    c = _client(tmp_path)
    with open(media["good"], "rb") as fh:
        r = c.post("/listen", files={"file": ("a.wav", fh, "audio/wav")},
                   data={"understand": "true"})
    assert r.status_code == 403


def test_rest_listen_backend_allowlist_applies(tmp_path, media):
    c = _client(tmp_path, rest_allow_understand=True)
    with open(media["good"], "rb") as fh:
        r = c.post("/listen", files={"file": ("a.wav", fh, "audio/wav")},
                   data={"understand": "true", "backend": "anthropic"})
    assert r.status_code == 400 and "not enabled" in r.text


@pytest.mark.parametrize("field,value", [("language", "0=xx;rm"), ("language", "one=es"),
                                         ("tone", "sarcastic"), ("spec", "../x.json")])
def test_rest_listen_validates_caller_input(tmp_path, media, field, value):
    pytest.importorskip("faster_whisper")
    c = _client(tmp_path)
    with open(media["good"], "rb") as fh:
        r = c.post("/listen", files={"file": ("a.wav", fh, "audio/wav")}, data={field: value})
    assert r.status_code == 400, r.text


def test_rest_listen_caption_text_is_bounded_by_the_body_cap(tmp_path, media):
    c = _client(tmp_path, max_request_bytes=200_000)
    with open(media["good"], "rb") as fh:
        r = c.post("/listen", files={"file": ("a.wav", fh, "audio/wav")},
                   data={"captions": "1\n00:00:00,000 --> 00:00:01,000\n" + "x" * 300_000})
    assert r.status_code == 413


def test_report_json_round_trips_with_listening():
    from audel.models import ListeningSummary, Report, Verdict

    r = Report(verdict=Verdict.PASS, summary="ok", listening=ListeningSummary(words=3, wpm=150.0))
    assert Report.model_validate_json(r.model_dump_json()).listening.wpm == 150.0
    json.loads(r.model_dump_json())
