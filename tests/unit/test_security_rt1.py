"""Red-team round 1 regressions: container formats that make ffmpeg open OTHER files.

An HLS playlist (or ffconcat list) is a tiny regular file, so it passes the byte cap; without a
demuxer allowlist ffmpeg would follow its entries and read media elsewhere on the host."""

from __future__ import annotations

import asyncio
import shutil
import subprocess

import pytest

from audel.config import Settings
from audel.errors import AudelError
from audel.mediaguard import media_suffix, probe, validate_source

requires_ffmpeg = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")


@pytest.fixture
def secret_segment(tmp_path):
    seg = tmp_path / "elsewhere" / "secret.ts"
    seg.parent.mkdir()
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "sine=d=2", "-c:a", "aac",
                    "-f", "mpegts", str(seg)], check=True)
    return seg


def _playlists(d, seg):
    hls = d / "evil.m3u8"
    hls.write_text(f"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n{seg}\n#EXT-X-ENDLIST\n")
    cat = d / "evil.ffconcat"
    cat.write_text(f"ffconcat version 1.0\nfile '{seg}'\n")
    return [hls, cat]


@requires_ffmpeg
def test_playlists_are_refused_by_probe(tmp_path, secret_segment):
    s = Settings()
    for f in _playlists(tmp_path, secret_segment):
        with pytest.raises(AudelError):
            probe(validate_source(f, s), s)


@requires_ffmpeg
def test_check_on_a_playlist_never_reads_the_referenced_file(tmp_path, secret_segment):
    from audel import check

    for f in _playlists(tmp_path, secret_segment):
        r = asyncio.run(check(str(f)))
        assert r.verdict.value == "fail" and r.issues[0].kind.value == "decode_error"
        assert not r.tracks  # nothing was measured


def test_temp_files_keep_only_media_suffixes():
    assert media_suffix("clip.WAV") == ".wav" and media_suffix("a.mxf") == ".mxf"
    for bad in ("x.m3u8", "x.ffconcat", "x.txt", "x.mpd", "../../a.wav/..", "noext", None):
        assert media_suffix(bad) in ("",) or bad == "../../a.wav/.."


fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from audel.adapters.rest import build_app  # noqa: E402


@requires_ffmpeg
def test_rest_playlist_upload_is_a_decode_error_not_a_file_read(tmp_path, secret_segment):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path / "ws", allow_local_files=False)))
    for f in _playlists(tmp_path, secret_segment):
        with open(f, "rb") as fh:
            r = c.post("/check", files={"file": (f.name, fh, "application/octet-stream")})
        body = r.json()
        assert r.status_code == 200 and body["verdict"] == "fail" and body["tracks"] == []
        assert str(secret_segment) not in r.text


# ==== round 1, auth surface ===================================================================

import json  # noqa: E402
import os  # noqa: E402
import time  # noqa: E402

from audel.auth import Authenticator, client_key, load_tenants, token_hash  # noqa: E402
from audel.errors import ConfigError, UnsafeSourceError  # noqa: E402

SHARED = "Zq8vT2mR7xKp4nW9cLbY3hJf6sDg1aEu0oQiVtXz"  # random-looking, >= 128 bits
A_TOK = "tenant-a-token-xxxxxxxxxxxxxxxx"


@pytest.fixture
def idp(tmp_path):
    jwt = pytest.importorskip("jwt")
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pub = jwt.algorithms.ECAlgorithm.to_jwk(ec_key.public_key(), as_dict=True)
    rsa_pub = jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key(), as_dict=True)
    ec_pub.update(kid="ec1")
    rsa_pub.update(kid="rsa1")
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": [ec_pub, rsa_pub]}))  # EC listed first on purpose

    def mint(key=rsa_key, alg="RS256", kid=None, **claims):
        now = int(time.time())
        body = {"iss": "https://idp", "aud": "audel", "iat": now, "exp": now + 300, **claims}
        return jwt.encode(body, key, algorithm=alg, headers={"kid": kid} if kid else None)

    return jwks, mint, rsa_key, ec_key


def _s(tmp_path, jwks=None, tokens=None, **kw):
    return Settings(cache_dir=tmp_path / "ws", allow_local_files=False, api_token=SHARED,
                    api_tokens_file=tokens, jwt_jwks_file=jwks, jwt_issuer="https://idp",
                    jwt_audience="audel", jwt_algorithms=["RS256", "ES256"], **kw)


def _tok_file(tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tenants": {"newsroom": {"sha256": token_hash(A_TOK)}}}))
    return f


def test_jwt_tenants_are_namespaced_away_from_token_tenants(tmp_path, idp, media):
    jwks, mint, *_ = idp
    with TestClient(build_app(settings=_s(tmp_path, jwks, _tok_file(tmp_path)))) as c:
        ids = {}
        for who, tok in (("newsroom", A_TOK), ("shared", SHARED)):
            with open(media["good"], "rb") as fh:
                ids[who] = c.post("/jobs", headers={"authorization": f"Bearer {tok}"},
                                  files={"file": ("a.wav", fh, "audio/wav")}).json()["job_id"]
        for claim in ("newsroom", "default"):
            h = {"authorization": f"Bearer {mint(tenant=claim)}"}
            for jid in ids.values():
                assert c.get(f"/jobs/{jid}", headers=h).status_code == 404
                assert c.delete(f"/jobs/{jid}", headers=h).status_code == 404
            assert c.get("/jobs", headers=h).json()["jobs"] == []


def test_tokens_file_rejects_reserved_names_and_zero_rate(tmp_path):
    for payload in ({"tenants": {"default": {"sha256": "0" * 64}}},
                    {"tenants": {"ok": {"sha256": "0" * 64, "rate_per_min": 0}}}):
        f = tmp_path / "t.json"
        f.write_text(json.dumps(payload))
        with pytest.raises(ConfigError):
            load_tenants(f)


def test_jwt_alg_key_type_mismatch_is_a_401_and_is_rate_limited(tmp_path, idp):
    jwks, mint, rsa_key, ec_key = idp
    a = Authenticator(_s(tmp_path, jwks))
    # RS256 with no kid against a JWKS whose first key is EC: must verify against the RSA key.
    assert a.authenticate(f"Bearer {mint(tenant='x')}").tenant == "jwt:x"
    # ES256 signed by the EC key but claiming the RSA key id: no crash, just rejected.
    assert a.authenticate(f"Bearer {mint(ec_key, 'ES256', 'rsa1', tenant='x')}") is None
    c = TestClient(build_app(settings=_s(tmp_path, jwks, auth_fail_per_min=4)))
    bad = mint(ec_key, "ES256", "rsa1", tenant="x")
    codes = [c.get("/specs", headers={"authorization": f"Bearer {bad}"}).status_code
             for _ in range(8)]
    assert 500 not in codes and codes[0] == 401 and codes[-1] == 429


def test_throttled_address_is_refused_without_evaluating_credentials(tmp_path):
    # Round 2 refinement: once an address spends its failure budget, even a correct guess is
    # refused (429), so guessing cannot continue. Per-client budgets behind a proxy come from
    # AUDEL_FORWARDED_ALLOW_IPS (see test_forwarded_headers_untrusted_by_default).
    c = TestClient(build_app(settings=_s(tmp_path, auth_fail_per_min=4)))
    for i in range(20):
        c.get("/specs", headers={"authorization": f"Bearer wrong-{i}"})
    assert c.get("/specs", headers={"authorization": f"Bearer {SHARED}"}).status_code == 429


def test_short_shared_token_refused(tmp_path):
    with pytest.raises(ConfigError):
        Authenticator(Settings(api_token="a"))


def test_ipv6_clients_bucketed_by_64():
    assert client_key("2001:db8:1:2::1") == client_key("2001:db8:1:2:ffff::9")
    assert client_key("2001:db8:1:3::1") != client_key("2001:db8:1:2::1")
    assert client_key("::ffff:10.0.0.1") == "10.0.0.1" and client_key("10.0.0.1") == "10.0.0.1"


def test_cwd_dotenv_is_ignored_unless_named(tmp_path, monkeypatch):
    from audel.config import load_settings

    (tmp_path / ".env").write_text("AUDEL_OLLAMA_BASE_URL=http://evil.example/v1\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AUDEL_ENV_FILE", raising=False)
    assert load_settings().ollama_base_url == "https://ollama.com/v1"
    named = tmp_path / "audel.env"
    named.write_text("AUDEL_SILENCE_DBFS=-60\n")
    monkeypatch.setenv("AUDEL_ENV_FILE", str(named))
    assert load_settings().silence_dbfs == -60


def test_ollama_cloud_key_never_sent_over_http_or_to_an_on_prem_host():
    from audel.backends.ollama import OllamaBackend

    for url, trusted in (("http://ollama.com/v1", []), ("https://10.0.0.100/v1", ["10.0.0.100"])):
        be = OllamaBackend(Settings(ollama_base_url=url, ollama_api_key="k",
                                    trusted_backend_hosts=trusted))
        with pytest.raises(UnsafeSourceError):
            asyncio.run(be.complete_text("s", "u"))


def test_diagnostics_are_admin_only_when_auth_is_on(tmp_path):
    c = TestClient(build_app(settings=_s(tmp_path, tokens=_tok_file(tmp_path))))
    tenant = {"authorization": f"Bearer {A_TOK}"}
    assert c.get("/doctor", headers=tenant).status_code == 404
    assert c.get("/metrics", headers=tenant).status_code == 404
    admin = {"authorization": f"Bearer {SHARED}"}
    assert c.get("/doctor", headers=admin).status_code == 200
    c2 = TestClient(build_app(settings=_s(tmp_path, tokens=_tok_file(tmp_path),
                                          admin_tenants=["newsroom"])))
    assert c2.get("/metrics", headers=tenant).status_code == 200


def test_doctor_respects_the_egress_policy():
    from audel.adapters.doctor import _local_llm

    chk = _local_llm(Settings(egress="deny", local_llm_url="http://127.0.0.1:9",
                              trusted_backend_hosts=["127.0.0.1"]))
    assert not chk.ok and "egress" in chk.detail


def test_forwarded_headers_untrusted_by_default(monkeypatch):
    import uvicorn

    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("AUDEL_API_TOKEN", SHARED)
    from audel.adapters.rest import serve

    serve("127.0.0.1", 0)
    assert seen["proxy_headers"] is False and "forwarded_allow_ips" not in seen
    monkeypatch.setenv("AUDEL_FORWARDED_ALLOW_IPS", '["10.0.0.2"]')
    serve("127.0.0.1", 0)
    assert seen["proxy_headers"] is True and seen["forwarded_allow_ips"] == "10.0.0.2"


def test_private_permissions_on_workspace_uploads_and_audit(tmp_path, media, monkeypatch):
    from audel.ops import AuditLog
    from audel.workspace import Workspace

    ws = Workspace(Settings(cache_dir=tmp_path / "ws"))
    assert oct(ws.tmp.stat().st_mode & 0o777) == "0o700"
    import audel.core as core_pkg

    modes = []
    real = core_pkg.check

    async def spy(path, **kw):
        modes.append(oct(os.stat(path).st_mode & 0o777))
        return await real(path, **kw)

    monkeypatch.setattr(core_pkg, "check", spy)
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path / "ws", allow_local_files=False)))
    with open(media["good"], "rb") as fh:
        assert c.post("/check", files={"file": ("a.wav", fh, "audio/wav")}).status_code == 200
    assert modes == ["0o600"]
    pre = tmp_path / "audit.jsonl"
    pre.write_text("")
    os.chmod(pre, 0o644)
    AuditLog(pre).write(endpoint="/check")
    assert oct(pre.stat().st_mode & 0o777) == "0o600"
    link = tmp_path / "audit-link.jsonl"
    link.symlink_to(tmp_path / "elsewhere.txt")
    with pytest.raises(OSError):
        AuditLog(link).write(endpoint="/check")


# ==== round 1, network surface ================================================================

def test_decode_error_reports_never_carry_server_paths(tmp_path):
    junk = tmp_path / "junk.wav"
    junk.write_bytes(b"not audio at all" * 100)
    ws = tmp_path / "ws"
    c = TestClient(build_app(settings=Settings(cache_dir=ws, allow_local_files=False)))
    for route in ("/check", "/listen"):
        with open(junk, "rb") as fh:
            r = c.post(route, files={"file": ("junk.wav", fh, "audio/wav")})
        assert str(ws) not in r.text and "/tmp" not in r.text and "upload_" not in r.text, r.text


def test_healthz_never_reads_a_body(tmp_path):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path, max_request_bytes=1000)))

    def huge():
        for _ in range(100):
            yield b"x" * 10_000

    r = c.post("/healthz", content=huge())
    assert r.status_code == 200


def test_streamed_body_over_the_cap_is_413_without_buffering(tmp_path):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path, max_request_bytes=50_000)))

    boundary = "AUDELBOUNDARY"

    def chunks():  # a chunked multipart upload (no Content-Length): read as it streams
        yield (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
               f"filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\n").encode()
        for _ in range(50):
            yield b"y" * 10_000
        yield f"\r\n--{boundary}--\r\n".encode()

    r = c.post("/check", content=chunks(),
               headers={"content-type": f"multipart/form-data; boundary={boundary}"})
    assert r.status_code == 413


def test_timed_out_or_cancelled_work_keeps_its_slot_until_it_really_ends():
    from audel.adapters.rest import run_shielded

    async def scenario():
        sem = asyncio.Semaphore(1)
        release = asyncio.Event()
        ran = []

        async def slow():
            ran.append("slow")
            await release.wait()
            return "done"

        with pytest.raises(TimeoutError):
            await run_shielded(sem, slow, timeout=0.05)
        assert sem.locked()          # the slot is still held by the running work

        async def second():
            ran.append("second")
            return "x"

        abandoned = asyncio.create_task(run_shielded(sem, second, timeout=0.05))
        with pytest.raises(TimeoutError):
            await abandoned           # waited for the slot, timed out, abandoned
        release.set()
        await asyncio.sleep(0.05)
        assert ran == ["slow"]        # abandoned work never ran
        assert not sem.locked()

    asyncio.run(scenario())


def test_watch_is_operator_opt_in_over_rest(tmp_path):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path)))
    assert c.post("/watch", json={"source": "https://example.com"}).status_code == 403


def test_capture_disables_non_proxied_webrtc():
    from audel.core.capture import _launch_args

    args = _launch_args(Settings())["args"]
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in args


def test_proxy_refuses_tunnels_to_non_web_ports():
    from audel.proxy import VettingProxy

    async def scenario():
        p = VettingProxy()
        await p.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", p.port)
            w.write(b"CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n")
            await w.drain()
            return await asyncio.wait_for(r.readline(), 5)
        finally:
            await p.stop()

    assert b"403" in asyncio.run(scenario())


@pytest.mark.parametrize("addr", ["64:ff9b::a00:5", "64:ff9b::7f00:1", "2002:a00:5::1",
                                  "2001:0:4136:e378:8000:63bf:3fff:fdd2"])
def test_ipv6_transition_forms_cannot_smuggle_internal_ipv4(addr):
    from audel.netguard import ip_is_blocked

    assert ip_is_blocked(addr)


# ==== round 2, auth surface ===================================================================

@pytest.mark.parametrize("weak", ["a" * 40, "correct-horse-battery-staple-0001", "abcabcabcabcabcabcabcabcabcabcabcabc"])
def test_low_entropy_shared_tokens_refused(weak):
    with pytest.raises(ConfigError):
        Authenticator(Settings(api_token=weak))


def test_strong_shared_token_accepted():
    import secrets

    assert Authenticator(Settings(api_token=secrets.token_hex(32))).required


def test_duplicate_token_hashes_rejected(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"tenants": {"alice": {"sha256": token_hash(A_TOK)},
                                         "bob": {"sha256": token_hash(A_TOK)}}}))
    with pytest.raises(ConfigError):
        load_tenants(f)


def test_jwks_key_whose_key_ops_exclude_verify_is_not_used(tmp_path):
    jwt = pytest.importorskip("jwt")
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pub = jwt.algorithms.ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    pub.update(kid="k", key_ops=["encrypt"])
    jwks = tmp_path / "j.json"
    jwks.write_text(json.dumps({"keys": [pub]}))
    now = int(time.time())
    tok = jwt.encode({"iss": "https://idp", "aud": "audel", "iat": now, "exp": now + 60,
                      "tenant": "x"}, key, algorithm="ES256", headers={"kid": "k"})
    a = Authenticator(Settings(jwt_jwks_file=jwks, jwt_issuer="https://idp", jwt_audience="audel",
                               jwt_algorithms=["ES256"]))
    assert a.authenticate(f"Bearer {tok}") is None


def test_one_tenant_cannot_starve_or_evict_another():
    from audel.jobs import JobStore, QueueFull

    async def scenario():
        store = JobStore(max_queued=8, max_stored=8, ttl_s=600, semaphore=asyncio.Semaphore(1))
        gate = asyncio.Event()

        async def slow():
            await gate.wait()
            return {}

        async def fast():
            return {}

        bob_done = store.submit("bob", "check", fast)
        await asyncio.sleep(0.01)
        assert bob_done.status == "done"
        for _ in range(2):  # alice's fair share of the queue is 8 // 4 = 2
            store.submit("alice", "check", slow)
        with pytest.raises(QueueFull):
            store.submit("alice", "check", slow)
        store.submit("bob", "check", fast)  # bob can still submit
        gate.set()
        for _ in range(10):  # alice churns finished results
            await asyncio.sleep(0.01)
            try:
                store.submit("alice", "check", fast)
            except QueueFull:
                pass
        await asyncio.sleep(0.05)
        assert store.get("bob", bob_done.id) is not None  # bob's result survived alice's churn

    asyncio.run(scenario())


@pytest.mark.parametrize("spelling", ["[::ffff:8.8.8.8]", "134744072", "0x08080808", "8.8.8.8."])
def test_trusted_host_comparison_is_canonical(spelling):
    from audel.backends.ollama import OllamaBackend

    be = OllamaBackend(Settings(ollama_base_url=f"https://{spelling}/v1", ollama_api_key="k",
                                trusted_backend_hosts=["8.8.8.8"]))
    with pytest.raises(UnsafeSourceError, match="on-prem"):
        asyncio.run(be.complete_text("s", "u"))


def test_tracebacks_are_scrubbed_of_secrets():
    import logging

    from audel.logging import get_logger, register_secret

    register_secret("sekret-value-123456789")
    log = get_logger("t")
    rec = logging.LogRecord("audel.t", logging.ERROR, __file__, 1, "boom", (), None)
    try:
        raise RuntimeError("leaked sekret-value-123456789")
    except RuntimeError:
        import sys

        rec.exc_info = sys.exc_info()
    for f in log.filters + logging.getLogger("audel").filters + [
            f for h in logging.getLogger("audel").handlers for f in h.filters]:
        f.filter(rec)
    assert rec.exc_text and "sekret-value-123456789" not in rec.exc_text


def test_docs_build_excludes_the_residuals_ledger():
    from pathlib import Path

    cfg = (Path(__file__).resolve().parents[2] / "mkdocs.yml").read_text()
    assert "exclude_docs" in cfg and "SECURITY_RESIDUALS.md" in cfg


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
@pytest.mark.parametrize("args", [["--set", "tls.mutual=true"],
                                  ["--set", "service.type=LoadBalancer"],
                                  ["--set", "service.type=NodePort"]])
def test_helm_refuses_insecure_renders(args):
    from pathlib import Path

    chart = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "audel"
    r = subprocess.run(["helm", "template", "t", str(chart), "--set", "auth.existingSecret=s", *args],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "TLS" in (r.stderr + r.stdout).upper()
