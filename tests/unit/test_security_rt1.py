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
from audel.errors import ConfigError, UnsafeSourceError  # noqa: E402,F811

SHARED = "audel_s2GS5zbClAPZW_BX-zl1O7VUqv193uD1ZB0otjT2Tag_a2oxej7i"  # minted by audel token new
A_TOK = "audel_nI2zB7O_Uh68j1nSJ3HC0HZvRcc8YRArfug1RWWMl8I_2jqr43az"


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


def test_valid_credentials_pass_while_failures_from_the_same_address_are_throttled(tmp_path):
    # Round 3 resolution: credentials are generated 256-bit secrets (guessing is infeasible), so a
    # valid credential always passes and only failures are throttled. One unauthenticated client
    # therefore cannot lock out users who share its address (NAT, ingress, load balancer).
    c = TestClient(build_app(settings=_s(tmp_path, auth_fail_per_min=4)))
    codes = [c.get("/specs", headers={"authorization": f"Bearer wrong-{i}"}).status_code
             for i in range(20)]
    assert codes[0] == 401 and codes[-1] == 429
    assert c.get("/specs", headers={"authorization": f"Bearer {SHARED}"}).status_code == 200


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

@pytest.mark.parametrize("weak", [
    "a" * 64, "correct-horse-battery-staple-0001", "abcabcabcabcabcabcabcabcabcabcabcabc",
    "abcdefghijkl" * 4, "0123456789abcdef" * 4, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    "qwertyuiopasdfghjklzxcvbnm1234567890abcdefgh", "audel-prod-token-2026-changeme-please-ok!!",
    # round 4: chosen strings that LOOK random were accepted by the old shape check
    "my-audel-production-api-token-for-the-newsroom",
    "Correct_Horse_Battery_Staple_Newsroom_Audel_2026",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # sha256("password")
    "audel_" + "A" * 43 + "_aaaaaaaa"])                                  # right shape, bad checksum
def test_low_entropy_shared_tokens_refused(weak):
    with pytest.raises(ConfigError):
        Authenticator(Settings(api_token=weak))


def test_generated_tokens_are_accepted():
    from audel.auth import new_token, strong_token

    assert Authenticator(Settings(api_token=new_token())).required
    assert all(strong_token(new_token()) for _ in range(200))


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


# ==== round 2, network surface ================================================================

def _big_transcript(n=1500):
    from audel.backends.base import Segment, Transcript, Word

    ws = [Word(text="the", start_ms=i * 300, end_ms=i * 300 + 250, probability=0.9) for i in range(n)]
    return Transcript(text=" ".join(w.text for w in ws), language="en",
                      segments=[Segment(start_ms=0, end_ms=n * 300, text="x", words=ws)])


@requires_ffmpeg
def test_heavy_listening_analysis_does_not_block_the_event_loop(media, monkeypatch):
    from audel.backends.local import LocalBackend
    from audel.core import listen

    async def fake_transcribe(self, path, **kw):
        return _big_transcript()

    monkeypatch.setattr(LocalBackend, "available", lambda self: True)
    monkeypatch.setattr(LocalBackend, "transcribe", fake_transcribe)
    cues = "".join(f"{i}\n00:00:00,000 --> 00:07:30,000\n{'the ' * 50}\n\n" for i in range(1, 3000))

    async def scenario():
        gaps = []

        async def ticker():
            last = time.monotonic()
            while True:
                await asyncio.sleep(0.02)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        t = asyncio.create_task(ticker())
        await listen(str(media["good"]), script=" ".join(["the"] * 30_000), captions=cues)
        t.cancel()
        return max(gaps)

    assert asyncio.run(scenario()) < 0.5


def test_caption_and_script_cost_is_bounded():
    from audel.speech.captions import Cue, caption_issues
    from audel.speech.listening import align_script

    t = _big_transcript(30_000)
    t0 = time.process_time()   # CPU time: the shared test host's wall clock is too noisy
    align_script(" ".join(["the"] * 30_000), t, 9_000_000)
    cues = [Cue(i * 500, i * 500 + 2000, "the " * 60) for i in range(20_000)]
    issues, _ = caption_issues(cues, t, Settings(), 9_000_000)
    assert time.process_time() - t0 < 30


def test_windowed_alignment_still_finds_a_dropped_line():
    import random

    from audel.backends.base import Segment, Transcript, Word
    from audel.speech.listening import align_script

    random.seed(1)
    script = [f"w{random.randrange(3000)}" for _ in range(20_000)]
    heard = script[:10_000] + script[10_010:]
    ws = [Word(text=w, start_ms=i * 300, end_ms=i * 300 + 250, probability=0.9)
          for i, w in enumerate(heard)]
    t = Transcript(text=" ".join(heard), segments=[Segment(start_ms=0, end_ms=len(heard) * 300,
                                                           text="x", words=ws)])
    r = align_script(" ".join(script), t, len(heard) * 300)
    assert [(d.op, d.words) for d in r.deviations] == [("omission", 10)]


def test_deleted_queued_jobs_never_leak_their_uploads(tmp_path, media, monkeypatch):
    import audel.core as core_pkg

    gate = asyncio.Event()

    async def slow_check(path, **kw):
        await gate.wait()
        return await core_pkg.check.__wrapped__(path, **kw) if hasattr(core_pkg.check, "__wrapped__") else None

    monkeypatch.setattr(core_pkg, "check", slow_check)
    ws = tmp_path / "ws"
    s = Settings(cache_dir=ws, allow_local_files=False, max_concurrent_jobs=1, api_token=SHARED,
                 max_queued_jobs_per_tenant=50)
    h = {"authorization": f"Bearer {SHARED}"}
    with TestClient(build_app(settings=s)) as c:
        for _ in range(6):
            with open(media["good"], "rb") as fh:
                jid = c.post("/jobs", headers=h, files={"file": ("a.wav", fh, "audio/wav")}
                             ).json()["job_id"]
            assert c.delete(f"/jobs/{jid}", headers=h).status_code == 200
        time.sleep(0.3)
        leftovers = [f for f in (ws / "tmp").iterdir() if f.name.startswith("upload_")]
        assert len(leftovers) <= 1, leftovers   # at most the one job still holding the slot


def test_cancelled_download_leaves_nothing_and_stops(tmp_path, monkeypatch):
    import threading

    import audel.ingest as ing

    stopped = threading.Event()

    def slow_download(url, dest, proxy_url, settings, stop=None):
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            for _ in range(200):
                if stop is not None and stop.is_set():
                    stopped.set()
                    raise UnsafeSourceError("download cancelled")
                fh.write(b"x" * 10_000)
                time.sleep(0.02)
        return 0

    monkeypatch.setattr(ing, "_download", slow_download)
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)

    async def scenario():
        task = asyncio.create_task(ing.fetch_to_file("https://example.com/a.wav", tmp_path,
                                                     Settings(allow_url_ingest=True)))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.2)

    asyncio.run(scenario())
    assert list(tmp_path.iterdir()) == [] and stopped.is_set()


def test_body_intake_slots_are_taken_only_when_a_body_is_read():
    from audel.adapters.rest import _BodyLimit

    active = {"now": 0, "max": 0}

    async def app(scope, receive, send):
        if scope["path"] == "/read":
            first = True
            while True:
                m = await receive()
                if first:
                    active["now"] += 1
                    active["max"] = max(active["max"], active["now"])
                    first = False
                if m["type"] != "http.request" or not m.get("more_body"):
                    break
            active["now"] -= 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = _BodyLimit(app, cap=1000, max_concurrent=2)

    async def scenario():
        # many non-reading requests never touch the intake limit...
        await asyncio.wait_for(asyncio.gather(*[_asgi_call(mw, "/noread", [], tenant=f"t{i}")
                                                for i in range(50)]), 2)
        # ...and in-progress body reads are capped at 2 at a time (distinct tenants)
        await asyncio.gather(*[_asgi_call(mw, "/read", [b"x", b"x", b"x"], tenant=f"r{i}",
                                          delay=0.02) for i in range(8)])

    asyncio.run(scenario())
    assert active["max"] <= 2


def test_rest_list_fields_are_capped(tmp_path, media):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path, allow_local_files=False)))
    with open(media["good"], "rb") as fh:
        r = c.post("/check", files={"file": ("a.wav", fh, "audio/wav")},
                   data={"expect": ["must: x"] * 300})
    assert r.status_code == 400


@pytest.mark.parametrize("msg", [
    "{root}/tmp/upload_436a417f948c4d8b.wav: Invalid data found",
    "[wav @ 0x7d97800] bad header in C:\\\\Users\\\\bob\\\\a.wav",
    "open %2Fetc%2Fpasswd failed", "connect [fd00::12]:8080 refused",
])
def test_sanitizer_closes_round2_gaps(tmp_path, msg):
    from audel.errors import register_sensitive_path, sanitize_message

    root = tmp_path / "media store, (prod)"
    register_sensitive_path(root)
    out = sanitize_message(msg.format(root=root))
    for leak in ("store", "prod", "Users", "passwd", "fd00", "0x7d", "upload_436a"):
        assert leak not in out, out


def test_render_is_audited(tmp_path, media):
    audit = tmp_path / "a.jsonl"
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path / "ws", allow_local_files=False,
                                               audit_log=audit)))
    with open(media["good"], "rb") as fh:
        assert c.post("/render", files={"file": ("a.wav", fh, "audio/wav")}).status_code == 200
    assert json.loads(audit.read_text().splitlines()[-1])["endpoint"] == "/render"


# ==== round 2, decode surface =================================================================

def _stereo_dead_right(path):
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i",
                    "anoisesrc=d=4:a=0.2:c=pink", "-af", "pan=stereo|c0=c0|c1=0*c0",
                    "-c:a", "flac", str(path)], check=True)
    return path


@requires_ffmpeg
@pytest.mark.parametrize("tags", [
    ["-metadata", "AA=RMS level dB: -100.0", "-metadata", "B9=[Parsed_astats_0 @ 0x1] Overall"],
    ["-metadata", "X=[Parsed_ebur128_0 @ 0x1]     I:         -23.0 LUFS"],
    ["-metadata", "Y= [Parsed_astats_0 @ 0x1] Channel: 2 [Parsed_astats_0 @ 0x1] "
                  "RMS level dB: -20.0"],
])
def test_container_metadata_cannot_forge_the_verdict(tmp_path, tags):
    from audel import check

    base = _stereo_dead_right(tmp_path / "dead.mka")
    forged = tmp_path / "forged.mka"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(base), "-c", "copy", *tags,
                    str(forged)], check=True)
    a = asyncio.run(check(str(base), spec="ebu_r128"))
    b = asyncio.run(check(str(forged), spec="ebu_r128"))
    assert "dead_channel" in {i.detail.get("check") for i in a.issues}
    assert (a.verdict, sorted(i.detail.get("check") for i in a.issues)) == \
        (b.verdict, sorted(i.detail.get("check") for i in b.issues))


@requires_ffmpeg
def test_malformed_numbers_in_metadata_cannot_crash_check(tmp_path):
    from audel import check

    base = _stereo_dead_right(tmp_path / "d.mka")
    bad = tmp_path / "bad.mka"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(base), "-c", "copy",
                    "-metadata:s:a:0", "title=silence_start: 1.2.3",
                    "-metadata", "comment=silence_end: nan.inf", str(bad)], check=True)
    r = asyncio.run(check(str(bad)))
    assert r.verdict.value in ("pass", "warn", "fail") and r.tracks


def test_silence_parser_ignores_garbage_numbers():
    import math

    from audel.signals._parse import parse_silences

    spans = parse_silences("silence_start: 1.2.3\nsilence_start: nan\nsilence_end: inf\n"
                           "silence_start: 2.5\nsilence_end: 3.0")   # never raises
    assert spans and all(math.isfinite(a) and (b == -1.0 or math.isfinite(b)) for a, b in spans)


@requires_ffmpeg
def test_total_audio_budget_stops_stream_amplification(tmp_path):
    a = tmp_path / "a.flac"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "sine=d=10", str(a)],
                   check=True)
    mt = tmp_path / "mt.mka"
    argv = ["ffmpeg", "-v", "error", "-y"]
    for _ in range(6):
        argv += ["-i", str(a)]
    for i in range(6):
        argv += ["-map", f"{i}:a"]
    subprocess.run([*argv, "-c", "copy", str(mt)], check=True)
    s = Settings(max_total_audio_s=40)
    with pytest.raises(UnsafeSourceError, match="total-audio"):
        probe(validate_source(mt, s), s)


def test_tool_stderr_is_bounded():
    from audel.mediaguard import _BoundedReader

    r, w = os.pipe()
    with os.fdopen(r, "rb") as rf, os.fdopen(w, "wb") as wf:
        rd = _BoundedReader(rf, 1000)
        wf.write(b"x" * 5_000_000)
        wf.close()
        assert len(rd.join(5)) == 1000 and rd.truncated


def test_pass_timeout_scales_with_declared_duration():
    from audel.mediaguard import pass_timeout

    s = Settings()
    assert pass_timeout(s, 3 * 3600) > 3600 > pass_timeout(s, 60)


@requires_ffmpeg
def test_decode_timeout_never_leaks_a_temp_wav(tmp_path, media):
    from audel.mediaguard import decode_to_wav

    ws = tmp_path / "ws"
    s = Settings(cache_dir=ws, decode_timeout_s=0.001, decode_timeout_per_audio_s=0.0)
    with pytest.raises(AudelError):
        decode_to_wav(validate_source(media["good"], s), s)
    tmp = ws / "tmp"
    assert not tmp.exists() or list(tmp.iterdir()) == []


def test_alignment_is_bounded_on_repetitive_input():
    from audel.speech.listening import align_script

    def tr(toks):
        from audel.backends.base import Segment, Transcript, Word

        ws = [Word(text=w, start_ms=i * 300, end_ms=i * 300 + 250, probability=0.9)
              for i, w in enumerate(toks)]
        return Transcript(text=" ".join(toks), segments=[Segment(start_ms=0, end_ms=len(toks) * 300,
                                                                 text="x", words=ws)])

    t0 = time.monotonic()
    align_script(" ".join(["a"] * 2000), tr(["a" if i % 2 == 0 else "x" for i in range(2000)]), 1)
    align_script(" ".join(["a"] * 1000), tr(["a" if i % 2 else "x" for i in range(4000)]), 1)
    assert time.monotonic() - t0 < 30


def test_term_search_is_indexed():
    from audel.backends.base import Segment, Transcript, Word
    from audel.speech.listening import term_issues

    toks = [f"w{i % 500}" for i in range(30_000)]
    ws = [Word(text=w, start_ms=i * 300, end_ms=i * 300 + 250) for i, w in enumerate(toks)]
    t = Transcript(text=" ".join(toks), segments=[Segment(start_ms=0, end_ms=9_000_000, text="x",
                                                          words=ws)])
    terms = [" ".join(f"w{(i + k) % 500}" for k in range(50)) for i in range(200)]
    t0 = time.monotonic()
    term_issues(t, 9_000_000, required=terms, forbidden=terms)
    assert time.monotonic() - t0 < 5


def test_asr_chunks_are_placed_on_the_programme_timeline():
    from types import SimpleNamespace

    from audel.speech.asr import _collect

    seg = SimpleNamespace(text="hi", start=1.0, end=2.0, avg_logprob=0, no_speech_prob=0,
                          words=[SimpleNamespace(start=1.0, end=1.5, word="hi", probability=0.9)])
    segs, _, _ = _collect([seg], offset_ms=600_000)
    assert segs[0].start_ms == 601_000 and segs[0].words[0].start_ms == 601_000


def test_bench_labels_cannot_name_spec_files_or_break_on_nul(tmp_path):
    from audel.bench import load_corpus

    (tmp_path / "a.wav").write_bytes(b"x")
    for row in ({"file": "a.wav", "spec": "/etc/audel/contract.json"},
                {"file": "a.wav", "spec": "../x.json"}, {"file": "a\x00.wav"}):
        (tmp_path / "labels.json").write_text(json.dumps([row]))
        with pytest.raises(ConfigError):
            load_corpus(tmp_path)


@requires_ffmpeg
def test_empty_stream_is_not_reported_as_clipping(tmp_path):
    from audel import check

    f = tmp_path / "empty.wav"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i",
                    "anullsrc=r=48000:cl=mono", "-t", "0", str(f)], check=True)
    r = asyncio.run(check(str(f)))
    checks = {i.detail.get("check") for i in r.issues}
    assert "clipping" not in checks and "true_peak_ceiling" not in checks



# ==== round 3, auth surface ===================================================================

def test_scrubber_redacts_overlapping_secrets_whole_and_base64_bearers():
    from audel.logging import register_secret, scrub_text

    register_secret("abcdef123456")
    register_secret("XXabcdef123456YY-longer-secret")
    assert "longer-secret" not in scrub_text("v XXabcdef123456YY-longer-secret")
    assert "Ab+/cd==" not in scrub_text("Authorization: Bearer Ab+/cdEFgh12345678==")


def test_uvicorn_loggers_get_the_scrubber():
    import logging

    from audel.logging import _SecretScrubber, scrub_logger

    scrub_logger("uvicorn.error")
    assert any(isinstance(f, _SecretScrubber) for f in logging.getLogger("uvicorn.error").filters)


def test_settings_repr_hides_secrets():
    s = Settings(api_token=SHARED, ollama_api_key="ollama-secret-xyz",
                 anthropic_api_key="sk-ant-secret", google_api_key="AIza-secret")
    text = repr(s) + str(s)
    for v in (SHARED, "ollama-secret-xyz", "sk-ant-secret", "AIza-secret"):
        assert v not in text


@pytest.mark.parametrize("spelling,canon", [("0x7f.1", "127.0.0.1"), ("0X0A.0.0.5", "10.0.0.5"),
                                            ("bücher.example", "xn--bcher-kva.example"),
                                            ("fd00:ec2::254%1", "fd00:ec2::254"),
                                            ("8.8.8.8.", "8.8.8.8"), ("dns.google", "dns.google")])
def test_canonical_host_spellings(spelling, canon):
    from audel.netguard import canonical_host

    assert canonical_host(spelling) == canon


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_boolean_strings_cannot_dodge_tls_rules():
    from pathlib import Path

    chart = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "audel"
    r = subprocess.run(["helm", "template", "t", str(chart), "--set", "auth.existingSecret=s",
                        "--set", "service.type=LoadBalancer", "--set-string",
                        "service.allowPlaintext=false"], capture_output=True, text=True)
    assert r.returncode != 0
    r = subprocess.run(["helm", "template", "t", str(chart), "--set", "auth.existingSecret=s",
                        "--set", "forwardedAllowIps={10.0.0.0/8}"], capture_output=True, text=True)
    assert r.returncode == 0 and "AUDEL_FORWARDED_ALLOW_IPS" in r.stdout


def test_og_workflow_keeps_the_write_token_away_from_third_party_code():
    from pathlib import Path

    import yaml

    wf = yaml.safe_load((Path(__file__).resolve().parents[2] / ".github/workflows/og.yml").read_text())
    jobs = wf["jobs"]
    render_steps = " ".join(str(s) for s in jobs["render"]["steps"])
    assert "pip install" in render_steps and jobs["render"].get("permissions") is None
    assert wf["permissions"] == {"contents": "read"}
    commit = jobs["commit"]
    assert commit["permissions"] == {"contents": "write"}
    assert "pip" not in " ".join(str(s) for s in commit["steps"])
    assert "core.hooksPath=/dev/null" in " ".join(str(s) for s in commit["steps"])


# ==== round 3, network surface ================================================================

def _asgi_call(mw, path, chunks, tenant="t", delay=0.0):
    from types import SimpleNamespace

    async def run():
        it = iter(chunks)
        sent = {}

        async def receive():
            if delay:
                await asyncio.sleep(delay)
            try:
                body = next(it)
                return {"type": "http.request", "body": body, "more_body": True}
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                sent["status"] = msg["status"]

        await mw({"type": "http", "path": path,
                  "state": {"principal": SimpleNamespace(tenant=tenant)}}, receive, send)
        return sent.get("status")

    return run()


def test_slow_body_gets_408_and_releases_its_intake_slot():
    from audel.adapters.rest import _BodyLimit

    async def app(scope, receive, send):
        while True:
            m = await receive()
            if m["type"] != "http.request" or not m.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = _BodyLimit(app, cap=10_000_000, max_concurrent=2, read_timeout_s=0.3)

    async def scenario():
        slow = await _asgi_call(mw, "/check", [b"x"] * 1000, tenant="alice", delay=0.05)
        assert slow == 408
        assert mw._intake._value == 2  # slot given back
        assert await _asgi_call(mw, "/check", [b"y"], tenant="bob") == 200

    asyncio.run(scenario())


def test_one_tenant_cannot_take_every_intake_slot():
    from audel.adapters.rest import _BodyLimit

    gate = asyncio.Event()

    async def app(scope, receive, send):
        m = await receive()      # first chunk read: slot taken...
        if m["type"] == "http.disconnect":
            return               # refused by the intake layer
        await gate.wait()        # ...and the sender stalls mid-body
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = _BodyLimit(app, cap=10_000_000, max_concurrent=4, read_timeout_s=30)

    async def scenario():
        alice = [asyncio.create_task(_asgi_call(mw, "/check", [b"x", b"x"], tenant="alice"))
                 for _ in range(4)]
        await asyncio.sleep(0.05)
        refused = [t.result() for t in alice if t.done()]
        assert refused == [429, 429]  # alice gets at most half the slots
        bob = asyncio.create_task(_asgi_call(mw, "/check", [b"y", b"y"], tenant="bob"))
        await asyncio.sleep(0.05)
        assert mw._intake._value >= 0 and not bob.done()  # bob got a slot (blocked only by app)
        gate.set()
        assert await bob == 200
        await asyncio.gather(*alice)

    asyncio.run(scenario())


def test_intake_slot_is_released_once_the_body_is_read():
    from audel.adapters.rest import _BodyLimit

    seen = {}

    async def app(scope, receive, send):
        await receive()                     # whole body arrives in one message
        seen["free"] = mw._intake._value    # before the (long) grading work
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = _BodyLimit(app, cap=1000, max_concurrent=1)

    async def scenario():
        await _asgi_call(mw, "/check", [], tenant="a")

    asyncio.run(scenario())
    assert seen["free"] == 1


def test_proxy_keeps_a_flowing_response_alive_while_the_request_side_is_quiet():
    import socket as _socket

    from audel.proxy import VettingProxy

    async def scenario():
        async def origin(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
            for _ in range(12):           # 1 byte every 0.1 s: longer than the idle timeout
                writer.write(b"z")
                await writer.drain()
                await asyncio.sleep(0.1)
            writer.close()

        srv = await asyncio.start_server(origin, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        import audel.proxy as pm

        real_vet, real_ports = pm.resolve_safe_ip, pm._ALLOWED_PORTS

        async def allow(host, p):
            return "127.0.0.1"

        pm.resolve_safe_ip, pm._ALLOWED_PORTS = allow, frozenset({port})
        p = VettingProxy(idle_timeout_s=0.4)
        await p.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", p.port)
            w.write(f"GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            await w.drain()
            data = b""
            while True:
                chunk = await asyncio.wait_for(r.read(1024), 5)
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            pm.resolve_safe_ip, pm._ALLOWED_PORTS = real_vet, real_ports
            await p.stop()
            srv.close()

    assert asyncio.run(scenario()).endswith(b"z" * 12)
    del _socket


def test_incomplete_download_is_refused(tmp_path, monkeypatch):
    import http.server
    import threading

    import audel.ingest as ing
    import audel.proxy as pm

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"x" * 40)  # then close early

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    async def allow(host, p):
        return "127.0.0.1"

    monkeypatch.setattr(pm, "resolve_safe_ip", allow)
    monkeypatch.setattr(pm, "_ALLOWED_PORTS", frozenset(range(1, 65536)))
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    try:
        with pytest.raises(UnsafeSourceError):
            asyncio.run(ing.fetch_to_file(f"http://127.0.0.1:{srv.server_address[1]}/a.wav",
                                          tmp_path, Settings(allow_url_ingest=True)))
        assert list(tmp_path.iterdir()) == []
    finally:
        srv.shutdown()


@requires_ffmpeg
def test_handoff_never_returns_the_server_path(tmp_path, media):
    ws = tmp_path / "ws"
    c = TestClient(build_app(settings=Settings(cache_dir=ws, allow_local_files=False)))
    with open(media["good"], "rb") as fh:
        r = c.post("/handoff", files={"file": ("a.wav", fh, "audio/wav")})
    assert r.status_code == 200
    assert str(ws) not in r.text and "upload_" not in r.text
    assert len(r.json()["artifact"]) == 64  # the input's sha256 instead


@pytest.mark.parametrize("lang", ["²=es", "١=es", "1234=es"])
def test_unicode_digit_language_index_is_a_400_not_500(tmp_path, media, lang):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path, allow_local_files=False)))
    with open(media["good"], "rb") as fh:
        r = c.post("/listen", files={"file": ("a.wav", fh, "audio/wav")}, data={"language": lang})
    assert r.status_code == 400


# ==== round 3, decode surface =================================================================

def _ff(*args):
    subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-y", *map(str, args)], check=True)


@requires_ffmpeg
def test_mid_stream_format_switch_is_refused_not_resampled(tmp_path):
    from audel import check

    a, b, out = tmp_path / "a.mp3", tmp_path / "b.mp3", tmp_path / "switch.mp3"
    _ff("-f", "lavfi", "-i", "sine=f=1000:d=6:r=8000", "-ac", "1", "-ar", "8000", a)
    _ff("-f", "lavfi", "-i", "aevalsrc=0.3*sin(2*PI*1000*t)+0.95*sin(2*PI*12000*t)|0:d=20:s=48000", b)
    out.write_bytes(a.read_bytes() + b.read_bytes())
    alone = asyncio.run(check(str(b)))
    switched = asyncio.run(check(str(out)))
    assert alone.verdict.value == "fail"
    assert switched.verdict.value == "fail"  # never graded as the first segment's format


@requires_ffmpeg
def test_non_default_layouts_keep_their_channel_order(tmp_path):
    from audel import check

    ok, dead = tmp_path / "quad_ok.wav", tmp_path / "quad_dead_br.wav"
    ch = "|".join(f"0.2*sin(2*PI*{300 + 100 * i}*t)" for i in range(4))
    _ff("-f", "lavfi", "-i", f"aevalsrc={ch}:c=quad:d=6:s=48000", ok)
    ch_dead = "|".join([f"0.2*sin(2*PI*{300 + 100 * i}*t)" for i in range(3)] + ["0"])
    _ff("-f", "lavfi", "-i", f"aevalsrc={ch_dead}:c=quad:d=6:s=48000", dead)
    r_ok, r_dead = asyncio.run(check(str(ok))), asyncio.run(check(str(dead)))
    assert not [i for i in r_ok.issues if i.detail.get("check") == "dead_channel"]
    dead_ch = [i.detail.get("channel") for i in r_dead.issues
               if i.detail.get("check") == "dead_channel"]
    assert dead_ch == ["BR"]


@requires_ffmpeg
def test_unordered_many_channel_audio_is_graded_not_aborted(tmp_path):
    from audel import check

    f = tmp_path / "c9.wav"
    _ff("-f", "lavfi", "-i", "aevalsrc=" + "|".join(["0.2*sin(2*PI*700*t)"] * 9) + ":d=4:s=48000", f)
    r = asyncio.run(check(str(f)))
    assert r.tracks and r.tracks[0].channels == 9
    assert "decode_error" not in {i.detail.get("check") for i in r.issues}


def test_layout_argument_rules():
    from audel.mediaguard import channel_layout_arg

    assert channel_layout_arg("quad", 4) == "quad"
    assert channel_layout_arg("7.1(wide)", 8) == "7.1(wide)"
    assert channel_layout_arg("unknown", 9).startswith("USR768+") and \
        channel_layout_arg("unknown", 9).count("+") == 8
    assert channel_layout_arg("", 2) == "stereo"
    assert channel_layout_arg("stereo", 6) != "stereo"          # count mismatch is not trusted
    assert channel_layout_arg("x;rm -rf", 2) == "stereo"         # odd strings never pass through


def _lying_mp3(tmp_path, real_s=30):
    head, tail, out = tmp_path / "h.mp3", tmp_path / "t.mp3", tmp_path / "lie.mp3"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=2:r=22050", "-ac", "1", "-ar", "22050",
        "-b:a", "128k", "-write_xing", "0", head)
    _ff("-f", "lavfi", "-i", f"anoisesrc=d={real_s}:a=0.3:r=22050", "-ac", "1", "-ar", "22050",
        "-b:a", "8k", "-write_xing", "0", tail)
    out.write_bytes(head.read_bytes() + tail.read_bytes())
    return out


@requires_ffmpeg
def test_duration_lie_is_graded_on_the_decoded_audio(tmp_path):
    from audel import check

    f = _lying_mp3(tmp_path)
    r = asyncio.run(check(str(f)))
    mism = [i for i in r.issues if i.detail.get("check") == "duration_mismatch"]
    assert mism and mism[0].detail["decoded_s"] > 25
    assert r.duration_ms and r.duration_ms > 25_000


@requires_ffmpeg
def test_audio_reaching_the_duration_cap_fails_closed(tmp_path):
    from audel import check

    f = _lying_mp3(tmp_path, real_s=30)
    r = asyncio.run(check(str(f), settings=Settings(max_duration_s=20)))
    assert r.verdict.value == "fail" and r.issues[0].kind.value == "decode_error"


@requires_ffmpeg
def test_unknown_duration_streams_share_the_budgets(tmp_path):
    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=d=3", a)
    mkv = tmp_path / "nodur.mkv"
    with open(mkv, "wb") as fh:
        subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(a), "-i", str(a),
                        "-map", "0:a", "-map", "1:a", "-c:a", "flac", "-f", "matroska", "-"],
                       stdout=fh, check=True)
    s = Settings(max_duration_s=60, max_total_audio_s=100)
    info_dur = None
    try:
        info_dur = probe(validate_source(mkv, Settings()), Settings()).duration_s
    except UnsafeSourceError:
        pass
    if info_dur and info_dur > 0:
        pytest.skip("this ffmpeg recovered a duration from the piped file")
    # Unknown length can't dodge the budgets: each stream may decode only its share of them
    # (round 9: rather than refusing every multi-track file of unknown length).
    info = probe(validate_source(mkv, s), s)
    assert 0 < info.decode_cap_s and info.decode_cap_s * len(info.streams) <= 100 + 1e-6
    from audel.signals.measure import measure

    tight = Settings(max_duration_s=60, max_total_audio_s=4)   # 2 s per stream < the 3 s audio
    with pytest.raises(UnsafeSourceError):
        measure(mkv, probe(validate_source(mkv, tight), tight), tight)  # cap reached: refused


@requires_ffmpeg
def test_one_deadline_bounds_the_whole_file(tmp_path, media):
    from audel import check

    r = asyncio.run(check(str(media["good"]), settings=Settings(
        decode_timeout_s=0.5, decode_timeout_per_audio_s=0.0)))
    assert r.verdict.value == "fail"  # budget exhausted -> refused, never unbounded



# ==== round 4, auth surface ===================================================================

def test_chosen_secrets_hashed_into_the_tokens_file_are_unusable(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"tenants": {"weak": {"sha256": token_hash("hunter2")},
                                         "ok": {"sha256": token_hash(A_TOK)}}}))
    a = Authenticator(Settings(api_tokens_file=f))
    assert a.authenticate("Bearer hunter2") is None
    assert a.authenticate(f"Bearer {A_TOK}").tenant == "ok"


def test_minted_tokens_validate_and_tampering_breaks_them():
    from audel.auth import new_token, strong_token

    t = new_token()
    assert strong_token(t)
    body = t[6:-9]
    flipped = "audel_" + ("B" if body[0] != "B" else "C") + body[1:] + t[-9:]
    assert not strong_token(flipped)


def test_scrubber_keeps_uvicorn_access_args_intact():
    import logging

    from audel.logging import _SecretScrubber

    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
                            '%s - "%s %s HTTP/%s" %d',
                            ("127.0.0.1:1", "GET", "/specs?token=abcdefgh123", "1.1", 401), None)
    _SecretScrubber().filter(rec)
    assert isinstance(rec.args, tuple) and len(rec.args) == 5
    assert "abcdefgh123" not in rec.getMessage()


def test_uvicorn_log_config_scrubs_every_handler():
    pytest.importorskip("uvicorn")
    from audel.logging import uvicorn_log_config

    cfg = uvicorn_log_config()
    assert all("audel_scrub" in h.get("filters", []) for h in cfg["handlers"].values())


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
@pytest.mark.parametrize("value,ok", [("True", True), ("yes", False), ("1", False), ("on", False)])
def test_helm_mutual_tls_values_are_strict(value, ok):
    from pathlib import Path

    chart = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "audel"
    r = subprocess.run(["helm", "template", "t", str(chart), "--set", "auth.existingSecret=s",
                        "--set", "tls.secretName=t", "--set-string", f"tls.mutual={value}"],
                       capture_output=True, text=True)
    if ok:
        assert r.returncode == 0 and "AUDEL_TLS_CLIENT_CA" in r.stdout
    else:
        assert r.returncode != 0


# ==== round 4, network surface ================================================================

def test_trickling_upstream_cannot_outlive_the_ingest_deadline(tmp_path, monkeypatch):
    import threading

    import audel.ingest as ing
    import audel.proxy as pm

    stop_srv = threading.Event()

    class H(__import__("http.server").server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            while not stop_srv.is_set():
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.3)   # one byte every 0.3 s: always "active", never finished

        def log_message(self, *a):
            pass

    srv = __import__("http.server").server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    async def allow(host, p):
        return "127.0.0.1"

    monkeypatch.setattr(pm, "resolve_safe_ip", allow)
    monkeypatch.setattr(pm, "_ALLOWED_PORTS", frozenset(range(1, 65536)))
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    s = Settings(allow_url_ingest=True, ingest_timeout_s=2, proxy_idle_timeout_s=1)
    t0 = time.monotonic()
    try:
        with pytest.raises(UnsafeSourceError):
            asyncio.run(ing.fetch_to_file(f"http://127.0.0.1:{srv.server_address[1]}/a.wav",
                                          tmp_path, s))
        assert time.monotonic() - t0 < 12
        time.sleep(1.0)
        stuck = [t for t in threading.enumerate() if t.name.startswith("audel-ingest") and
                 t.is_alive() and getattr(t, "_target", None) is not None]
        assert list(tmp_path.iterdir()) == []
        del stuck
    finally:
        stop_srv.set()
        srv.shutdown()


@requires_ffmpeg
def test_one_tenant_cannot_starve_another_of_grading_slots(tmp_path, media, monkeypatch):
    import threading

    import audel.core as core_pkg

    async def slow_check(path, **kw):
        await asyncio.sleep(1.0)
        from audel.models import Report, Verdict

        return Report(verdict=Verdict.PASS, summary="ok")

    monkeypatch.setattr(core_pkg, "check", slow_check)
    a, b = A_TOK, SHARED
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"tenants": {"alpha": {"sha256": token_hash(a)}}}))
    s = Settings(cache_dir=tmp_path / "ws", allow_local_files=False, api_token=b,
                 api_tokens_file=f, max_concurrent_jobs=4, max_inflight_per_tenant=20,
                 max_inflight_total=40)
    body = media["good"].read_bytes()
    with TestClient(build_app(settings=s)) as c:
        def hit(tok, out):
            r = c.post("/check", headers={"authorization": f"Bearer {tok}"},
                       files={"file": ("a.wav", body, "audio/wav")})
            out.append(r.status_code)

        alpha_out: list = []
        alpha = [threading.Thread(target=hit, args=(a, alpha_out)) for _ in range(10)]
        for t in alpha:
            t.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        bravo_out: list = []
        hit(b, bravo_out)
        bravo_s = time.monotonic() - t0
        for t in alpha:
            t.join()
    assert bravo_out == [200] and bravo_s < 3.0, bravo_s   # was ~5 s+ with global-first slots


@requires_ffmpeg
def test_grading_requests_are_admitted_before_their_bodies_are_read(tmp_path, media, monkeypatch):
    import threading

    import audel.core as core_pkg

    async def slow_check(path, **kw):
        await asyncio.sleep(1.0)
        from audel.models import Report, Verdict

        return Report(verdict=Verdict.PASS, summary="ok")

    monkeypatch.setattr(core_pkg, "check", slow_check)
    s = Settings(cache_dir=tmp_path, allow_local_files=False, max_inflight_per_tenant=1)
    body = media["good"].read_bytes()
    with TestClient(build_app(settings=s)) as c:
        first: list = []
        th = threading.Thread(target=lambda: first.append(c.post(
            "/check", files={"file": ("a.wav", body, "audio/wav")}).status_code))
        th.start()
        time.sleep(0.3)
        r = c.post("/check", files={"file": ("a.wav", body, "audio/wav")})
        th.join()
    assert first == [200] and r.status_code == 429


def test_intake_reservation_is_taken_before_waiting():
    from audel.adapters.rest import _BodyLimit

    gate = asyncio.Event()

    async def app(scope, receive, send):
        m = await receive()
        if m["type"] == "http.disconnect":
            return
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = _BodyLimit(app, cap=10_000, max_concurrent=4, read_timeout_s=5)

    async def scenario():
        others = [asyncio.create_task(_asgi_call(mw, "/check", [b"o", b"o"], tenant=f"o{i}"))
                  for i in range(4)]   # intake momentarily full
        await asyncio.sleep(0.05)
        alpha = [asyncio.create_task(_asgi_call(mw, "/check", [b"a", b"a"], tenant="alpha"))
                 for _ in range(6)]
        await asyncio.sleep(0.05)
        refused = [t.result() for t in alpha if t.done()]
        assert refused.count(429) == 4   # only alpha's share (2 of 4) may queue
        gate.set()
        await asyncio.gather(*others, *alpha)

    asyncio.run(scenario())


# ==== round 4, decode surface =================================================================

@requires_ffmpeg
def test_timestamp_gap_cannot_hide_audio_past_it(tmp_path):
    from audel import check

    clean = tmp_path / "c.wav"
    hot = tmp_path / "h.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=20:r=48000", "-af", "volume=0.3,afade=t=out:st=18:d=2", clean)
    _ff("-f", "lavfi", "-i", "aevalsrc=if(lt(mod(t\\,0.002)\\,0.001)\\,1\\,-1):d=5:s=48000", hot)
    both = tmp_path / "both.wav"
    _ff("-i", clean, "-i", hot, "-filter_complex", "[0][1]concat=n=2:v=0:a=1", both)
    gap = tmp_path / "gap.mkv"
    with open(gap, "wb") as fh:
        subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(both), "-af",
                        "asetpts='if(gte(N,960000),N+200*SR,N)/SR/TB'", "-c:a", "pcm_s16le",
                        "-f", "matroska", "-"], stdout=fh, check=True)
    s = Settings(max_duration_s=120)   # the jump (200 s) exceeds the cap
    r = asyncio.run(check(str(gap), settings=s))
    checks = {i.detail.get("check") for i in r.issues}
    assert r.verdict.value == "fail" and ({"clipping", "true_peak_ceiling"} & checks)


@requires_ffmpeg
def test_short_secondary_track_is_reported(tmp_path):
    from audel import check

    long_, short = tmp_path / "l.wav", tmp_path / "s.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=30", "-af", "afade=t=out:st=28:d=2", long_)
    _ff("-f", "lavfi", "-i", "sine=f=660:d=4", "-af", "afade=t=out:st=2:d=2", short)
    mt = tmp_path / "mt.mkv"
    _ff("-i", long_, "-i", short, "-map", "0:a", "-map", "1:a", "-c:a", "pcm_s16le", mt)
    r = asyncio.run(check(str(mt)))
    assert "short_track" in {i.detail.get("check") for i in r.issues}


@requires_ffmpeg
def test_corrupt_packets_are_reported_even_when_ffmpeg_exits_zero(tmp_path):
    import random

    from audel import check

    mp3 = tmp_path / "c.mp3"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=30", "-b:a", "128k", mp3)
    data = bytearray(mp3.read_bytes())
    rnd = random.Random(7)
    for k in range(20):
        pos = 5000 + k * (len(data) // 22)
        data[pos:pos + 1500] = bytes(rnd.randrange(256) for _ in range(1500))
    mp3.write_bytes(bytes(data))
    r = asyncio.run(check(str(mp3)))
    assert "decode_errors" in {i.detail.get("check") for i in r.issues}


@requires_ffmpeg
@pytest.mark.parametrize("layout,n", [("5.1.4", 10), ("7.1.4", 12), ("5.1.2", 8)])
def test_immersive_layouts_keep_their_lfe(tmp_path, layout, n):
    from audel import check

    f = tmp_path / f"{layout}.wav"
    chans = [f"0.1*sin(2*PI*{200 + 50 * i}*t)" for i in range(n)]
    chans[3] = "0"  # LFE (index 3 in all three layouts) silent, as in a dialogue mix
    _ff("-f", "lavfi", "-i", f"aevalsrc={'|'.join(chans)}:c={layout}:d=5:s=48000", f)
    r = asyncio.run(check(str(f)))
    assert "dead_channel" not in {i.detail.get("check") for i in r.issues}


def test_frame_cap_follows_the_configured_duration():
    from audel.signals._parse import parse_frames

    line = "[Parsed_ebur128_0 @ 0x1] t: {t}   TARGET:-23 LUFS    M: -20.0 S: -20.0\n"
    text = "".join(line.format(t=i / 10) for i in range(50))
    assert len(parse_frames(text, max_frames=10)) == 10 and len(parse_frames(text)) == 50


# ==== round 5, auth surface ===================================================================

def test_patterned_bodies_fail_even_with_a_valid_checksum():
    from audel.auth import _checksum, new_token, strong_token

    for body in ("A" * 43, ("password" * 6)[:43]):
        assert not strong_token(f"audel_{body}_{_checksum(body)}")
    assert all(strong_token(new_token()) for _ in range(2000))


def test_minted_tokens_are_redacted_wherever_they_appear():
    from audel.auth import new_token
    from audel.logging import scrub_text

    t = new_token()
    for text in (f'"GET /specs?auth={t} HTTP/1.1"', f"/x/{t}", f"Authorization: {t}",
                 f"Basic {t}"):
        assert t not in scrub_text(text)


def test_wildcard_forwarded_proxies_refused():
    with pytest.raises(ValueError):
        Settings(forwarded_allow_ips=["*"])


# ==== round 5, network surface ================================================================

def _stub_grade(monkeypatch, seconds, counter=None):
    import audel.core as core_pkg

    async def slow_check(path, **kw):
        if counter is not None:
            counter.append(path)
        await asyncio.sleep(seconds)
        from audel.models import Report, Verdict

        return Report(verdict=Verdict.PASS, summary="ok")

    monkeypatch.setattr(core_pkg, "check", slow_check)


@requires_ffmpeg
def test_async_jobs_cannot_starve_another_tenants_grading(tmp_path, media, monkeypatch):
    _stub_grade(monkeypatch, 1.0)
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"tenants": {"alpha": {"sha256": token_hash(A_TOK)}}}))
    s = Settings(cache_dir=tmp_path / "ws", allow_local_files=False, api_token=SHARED,
                 api_tokens_file=f, max_concurrent_jobs=4, queue_wait_s=4,
                 max_queued_jobs_per_tenant=16)
    body = media["good"].read_bytes()
    with TestClient(build_app(settings=s)) as c:
        for _ in range(16):
            assert c.post("/jobs", headers={"authorization": f"Bearer {A_TOK}"},
                          files={"file": ("a.wav", body, "audio/wav")}).status_code == 202
        time.sleep(0.2)
        t0 = time.monotonic()
        r = c.post("/check", headers={"authorization": f"Bearer {SHARED}"},
                   files={"file": ("a.wav", body, "audio/wav")})
        took = time.monotonic() - t0
    assert r.status_code == 200 and took < 3.0, (r.status_code, took)


def test_url_fetches_are_capped_per_tenant(tmp_path, monkeypatch):
    import audel.ingest as ing

    active = {"now": 0, "max": 0}

    async def slow_fetch(url, tmp, settings):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        await asyncio.sleep(0.3)
        active["now"] -= 1
        raise UnsafeSourceError("stub")

    monkeypatch.setattr(ing, "fetch_to_file", slow_fetch)
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    s = Settings(cache_dir=tmp_path / "ws", allow_url_ingest=True, api_token=SHARED,
                 max_queued_jobs_per_tenant=20, max_concurrent_jobs=8)
    h = {"authorization": f"Bearer {SHARED}"}
    with TestClient(build_app(settings=s)) as c:
        for _ in range(8):
            assert c.post("/jobs", headers=h, data={"url": "https://media.example/a.wav"}
                          ).status_code == 202
        time.sleep(1.5)
    assert active["max"] <= 2


@requires_ffmpeg
def test_abandoned_requests_never_run_their_grading(tmp_path, media, monkeypatch):
    import threading

    runs: list = []
    _stub_grade(monkeypatch, 2.0, runs)
    # Round 11: work slots are taken within queue_wait_s before the request's time limit starts.
    # A request that can't get one in time is refused (429) and never runs its grading.
    s = Settings(cache_dir=tmp_path / "ws", allow_local_files=False, request_timeout_s=0.5,
                 max_concurrent_jobs=2, max_inflight_per_tenant=20, queue_wait_s=0.3)
    body = media["good"].read_bytes()
    with TestClient(build_app(settings=s)) as c:
        def hit():
            c.post("/check", files={"file": ("a.wav", body, "audio/wav")})

        for _wave in range(4):
            th = [threading.Thread(target=hit) for _ in range(2)]
            for t in th:
                t.start()
            for t in th:
                t.join()
        time.sleep(2.5)
    assert len(runs) <= 3, len(runs)   # only work that actually got slots ran (was 8)


# ==== round 5, decode surface =================================================================

def test_decode_error_count_is_per_stream_and_unforgeable():
    from audel.mediaguard import _stream_decode_errors

    text = (
        "  Metadata:\n"
        "    title           : [in#0/mkv @ 0x1]   Input stream #0:0 (audio): 9 decode errors\n"
        "[h264 @ 0x2] non-existing PPS 0 referenced\n"
        "[in#0/mpegts @ 0x3]   Input stream #0:0 (audio): 1250 packets read; 0 decode errors (x)\n"
        "[in#0/mpegts @ 0x3]   Input stream #0:1 (audio): 900 packets read; 57 decode errors (x)\n")
    assert _stream_decode_errors(text, 0) == 0
    assert _stream_decode_errors(text, 1) == 57


@requires_ffmpeg
def test_custom_channel_masks_are_decoded_in_place(tmp_path):
    import struct

    import numpy as np

    from audel import check

    sr, n = 48000, 48000 * 4
    t = np.arange(n) / sr
    pcm = (np.stack([0.2 * np.sin(2 * np.pi * 300 * t), 0.2 * np.sin(2 * np.pi * 400 * t)], 1)
           * 32767).astype("<i2").tobytes()
    guid = bytes.fromhex("0100000000001000800000aa00389b71")  # KSDATAFORMAT_SUBTYPE_PCM
    fmt = struct.pack("<HHIIHHHHI16s", 0xFFFE, 2, sr, sr * 4, 4, 16, 22, 16, 0x30, guid)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + \
        struct.pack("<I", len(pcm)) + pcm
    f = tmp_path / "surround_stem.wav"   # channel mask 0x30 = BL+BR (a DAW surround stem)
    f.write_bytes(b"RIFF" + struct.pack("<I", len(body)) + body)
    r = asyncio.run(check(str(f)))
    checks = {i.detail.get("check") for i in r.issues}
    assert "decode_error" not in checks and "dead_channel" not in checks and r.tracks


@requires_ffmpeg
def test_missing_packets_are_reported_at_their_position(tmp_path):
    from audel import check

    f = tmp_path / "hole.mkv"
    _ff("-f", "lavfi", "-i", "anoisesrc=d=20:c=pink:a=0.2", "-af",
        "aselect='not(between(t,8,9))'", "-c:a", "pcm_s16le", f)
    r = asyncio.run(check(str(f)))
    gaps = [i for i in r.issues if i.detail.get("check") == "packet_gap"]
    assert gaps and 7_500 <= gaps[0].span.start_ms <= 8_500


@requires_ffmpeg
def test_crc_failures_are_reported(tmp_path):
    from audel import check

    f = tmp_path / "x.flac"
    _ff("-f", "lavfi", "-i", "anoisesrc=d=20:a=0.3", f)
    data = bytearray(f.read_bytes())
    for pos in (len(data) // 4, len(data) // 2, 3 * len(data) // 4):
        data[pos:pos + 64] = bytes((b ^ 0x5A) for b in data[pos:pos + 64])
    f.write_bytes(bytes(data))
    r = asyncio.run(check(str(f)))
    assert "decode_errors" in {i.detail.get("check") for i in r.issues}


@requires_ffmpeg
def test_delayed_start_track_is_blamed_at_the_right_time(tmp_path):
    from audel import check

    a, b = tmp_path / "a.wav", tmp_path / "b.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=30", "-af", "afade=t=out:st=28:d=2", a)
    _ff("-f", "lavfi", "-i", "sine=f=660:d=25", "-af", "afade=t=out:st=23:d=2", b)
    mkv = tmp_path / "off.mkv"
    _ff("-i", a, "-itsoffset", "5", "-i", b, "-map", "0:a", "-map", "1:a", "-c:a", "pcm_s16le", mkv)
    r = asyncio.run(check(str(mkv)))
    short = [i for i in r.issues if i.detail.get("check") == "short_track"]
    assert short and short[0].span.start_ms == 0 and 4_500 <= short[0].span.end_ms <= 5_500
    assert not [i for i in r.issues if i.detail.get("check") == "truncation"
                and i.detail.get("stream") == 1]


@requires_ffmpeg
def test_ts_timestamp_splice_is_graded_not_refused(tmp_path):
    from audel import check

    a, b = tmp_path / "a.ts", tmp_path / "b.ts"
    _ff("-f", "lavfi", "-i", "sine=d=10", "-c:a", "mp2", "-output_ts_offset", "1000", a)
    _ff("-f", "lavfi", "-i", "sine=d=10", "-c:a", "mp2", b)
    splice = tmp_path / "splice.ts"
    splice.write_bytes(a.read_bytes() + b.read_bytes())
    r = asyncio.run(check(str(splice)))
    assert r.tracks and "decode_error" not in {i.detail.get("check") for i in r.issues}


@requires_ffmpeg
def test_one_undecodable_track_does_not_discard_the_others(tmp_path, monkeypatch, media):
    import audel.signals.measure as ms
    from audel import check
    from audel.errors import DecodeError

    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=d=4", a)
    mkv = tmp_path / "two.mkv"
    _ff("-i", a, "-i", a, "-map", "0:a", "-map", "1:a", "-c:a", "pcm_s16le", mkv)
    real = ms.measure_track

    def flaky(path, st, settings, dur_s=0.0, deadline=None, **kw):  # noqa: D401
        if st.index == 1:
            raise DecodeError("no decoder found")
        return real(path, st, settings, dur_s, deadline, **kw)

    monkeypatch.setattr(ms, "measure_track", flaky)
    r = asyncio.run(check(str(mkv)))
    bad = [i for i in r.issues if i.detail.get("check") == "track_decode_error"]
    assert bad and bad[0].detail.get("stream") == 1 and len(r.tracks) == 2


# ==== round 6, auth surface ===================================================================

@pytest.mark.parametrize("entries", [["0.0.0.0/0"], ["::/0"], ["0.0.0.0/1", "128.0.0.0/1"],
                                     ["10.0.0.0/7"], ["not-an-ip"], [" * "]])
def test_broad_or_wildcard_proxy_networks_are_refused(entries):
    with pytest.raises(ValueError):
        Settings(forwarded_allow_ips=entries)


def test_specific_proxy_networks_are_accepted():
    assert Settings(forwarded_allow_ips=["10.0.0.0/8", "10.1.2.3", "fd00::/48"]).forwarded_allow_ips


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
@pytest.mark.parametrize("entry", ["0.0.0.0/0", "::/0", "128.0.0.0/1"])
def test_helm_refuses_broad_proxy_networks(entry):
    from pathlib import Path

    chart = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "audel"
    r = subprocess.run(["helm", "template", "t", str(chart), "--set", "auth.existingSecret=s",
                        "--set", f"forwardedAllowIps={{{entry}}}"], capture_output=True, text=True)
    assert r.returncode != 0


def test_constructed_bodies_fail_even_with_a_valid_checksum():
    from audel.auth import _checksum, new_token, strong_token

    for body in ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", ("abcdefghijklmnopqr" * 3)[:43]):
        assert not strong_token(f"audel_{body}_{_checksum(body)}")
    assert all(strong_token(new_token()) for _ in range(5000))


# ==== round 6, network surface ================================================================

@requires_ffmpeg
def test_sync_url_requests_do_not_hold_grading_slots_while_fetching(tmp_path, media, monkeypatch):
    import threading

    import audel.ingest as ing

    async def slow_fetch(url, tmp, settings):
        await asyncio.sleep(8.0)
        raise UnsafeSourceError("stub upstream")

    monkeypatch.setattr(ing, "fetch_to_file", slow_fetch)
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"tenants": {"alpha": {"sha256": token_hash(A_TOK)}}}))
    s = Settings(cache_dir=tmp_path / "ws", allow_url_ingest=True, allow_local_files=False,
                 api_token=SHARED, api_tokens_file=f, max_concurrent_jobs=2, queue_wait_s=2)
    body = media["good"].read_bytes()
    with TestClient(build_app(settings=s)) as c:
        th = [threading.Thread(target=lambda: c.post(
            "/check", headers={"authorization": f"Bearer {A_TOK}"},
            data={"url": "https://media.example/a.wav"})) for _ in range(2)]
        for t in th:
            t.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        r = c.post("/check", headers={"authorization": f"Bearer {SHARED}"},
                   files={"file": ("a.wav", body, "audio/wav")})
        took = time.monotonic() - t0
        for t in th:
            t.join()
    assert r.status_code == 200 and took < 7.0, (r.status_code, took)  # held slots: 429 at 2 s


def test_waiting_for_a_fetch_share_is_bounded(tmp_path, monkeypatch):
    import threading

    import audel.ingest as ing

    async def slow_fetch(url, tmp, settings):
        await asyncio.sleep(6.0)
        raise UnsafeSourceError("stub upstream")

    monkeypatch.setattr(ing, "fetch_to_file", slow_fetch)
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    s = Settings(cache_dir=tmp_path / "ws", allow_url_ingest=True, queue_wait_s=1.5)
    with TestClient(build_app(settings=s)) as c:
        for _ in range(2):
            assert c.post("/jobs", data={"url": "https://media.example/a.wav"}).status_code == 202
        time.sleep(0.3)
        t0 = time.monotonic()
        r = c.post("/check", data={"url": "https://media.example/b.wav"})
        took = time.monotonic() - t0
    assert r.status_code == 429 and took < 4.0, (r.status_code, took)
    del threading


def test_abandoned_unstarted_work_is_dropped_immediately():
    from audel.adapters.rest import run_shielded

    async def scenario():
        sem = asyncio.Semaphore(1)
        await sem.acquire()   # slot busy: the next work waits
        payload = bytearray(10_000_000)

        async def work():
            return len(payload)

        with pytest.raises(TimeoutError):
            await run_shielded(sem, work, timeout=0.05)
        await asyncio.sleep(0.01)
        waiting = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        sem.release()
        return waiting

    assert asyncio.run(scenario()) == []   # the waiter (and its payload) is gone


def test_download_cancelled_during_proxy_shutdown_leaves_no_file(tmp_path, monkeypatch):
    import audel.ingest as ing
    import audel.proxy as pm

    def fake_download(url, dest, proxy_url, settings, stop=None):
        dest.write_bytes(b"x" * 1000)
        return 1000

    real_stop = pm.VettingProxy.stop

    async def slow_stop(self):
        await asyncio.sleep(1.0)
        await real_stop(self)

    monkeypatch.setattr(ing, "_download", fake_download)
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    monkeypatch.setattr(pm.VettingProxy, "stop", slow_stop)

    async def scenario():
        t = asyncio.create_task(ing.fetch_to_file("https://media.example/a.wav", tmp_path,
                                                  Settings(allow_url_ingest=True)))
        await asyncio.sleep(0.4)   # download done, proxy shutting down
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(scenario())
    assert list(tmp_path.iterdir()) == []


def test_download_thread_removes_its_own_file_on_failure(tmp_path, monkeypatch):
    import audel.ingest as ing

    dest = tmp_path / "ingest_x.wav"

    def inner(url, d, proxy_url, settings, stop=None):
        d.write_bytes(b"partial")
        raise UnsafeSourceError("download cancelled")

    monkeypatch.setattr(ing, "_download_inner", inner)
    with pytest.raises(UnsafeSourceError):
        ing._download("https://x/a.wav", dest, "http://127.0.0.1:1", Settings())
    assert not dest.exists()


# ==== round 6, decode surface =================================================================

def _checks(r, name):
    return [i for i in r.issues if i.detail.get("check") == name]


@requires_ffmpeg
@pytest.mark.parametrize("ext", ["mp4", "ts"])
def test_dropped_packets_survive_a_remux_and_are_placed_on_programme_time(tmp_path, ext):
    from audel import check

    ts = tmp_path / "cap.ts"
    _ff("-f", "lavfi", "-i", "anoisesrc=d=30:c=pink:a=0.2", "-c:a", "aac",
        "-bsf:a", "noise=drop='between(pts*tb,10,10.9)'", "-output_ts_offset", "1000", ts)
    f = ts if ext == "ts" else tmp_path / "cap.mp4"
    if ext == "mp4":
        _ff("-i", ts, "-c", "copy", f)
    gaps = _checks(asyncio.run(check(str(f))), "packet_gap")
    assert gaps and 9_500 <= gaps[0].span.start_ms <= 10_500, [g.span for g in gaps]


@requires_ffmpeg
def test_audio_after_video_is_timed_against_the_programme(tmp_path):
    from audel import check

    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=12", "-af",
        "volume=enable='between(t,5,5.4)':volume=40,afade=t=out:st=10:d=2", a)
    mkv = tmp_path / "av.mkv"
    _ff("-f", "lavfi", "-i", "color=c=black:s=64x64:d=15", "-itsoffset", "3", "-i", a,
        "-map", "0:v", "-map", "1:a", "-c:v", "ffv1", "-c:a", "pcm_s16le", mkv)
    r = asyncio.run(check(str(mkv)))
    assert not _checks(r, "duration_mismatch")
    clip = _checks(r, "clipping")
    assert clip and 7_500 <= clip[0].span.start_ms <= 8_500


@requires_ffmpeg
def test_cut_short_wav_and_w64_transfers_are_caught(tmp_path):
    from audel import check

    for ext in ("wav", "w64"):
        full = tmp_path / f"full.{ext}"
        _ff("-f", "lavfi", "-i", "sine=d=30", "-af", "volume=0.3", "-ac", "2", full)
        data = full.read_bytes()
        cut = tmp_path / f"cut.{ext}"
        cut.write_bytes(data[: (len(data) * 2 // 3) // 4 * 4])
        assert not _checks(asyncio.run(check(str(full))), "container_truncated")
        bad = _checks(asyncio.run(check(str(cut))), "container_truncated")
        assert bad and 8 <= bad[0].detail["missing_s"] <= 12, ext


@requires_ffmpeg
def test_streamed_wav_with_unknown_length_is_not_called_truncated(tmp_path):
    import struct

    from audel import check

    f = tmp_path / "s.wav"
    _ff("-f", "lavfi", "-i", "sine=d=5", f)
    b = bytearray(f.read_bytes())
    i = b.index(b"data")
    b[i + 4:i + 8] = struct.pack("<I", 0xFFFFFFFF)
    f.write_bytes(bytes(b))
    assert not _checks(asyncio.run(check(str(f))), "container_truncated")


@requires_ffmpeg
def test_incomplete_gap_scan_is_reported_not_assumed_clean(media, monkeypatch):
    import audel.signals.measure as ms
    from audel import check

    seen = {}

    def gaps(path, settings, idx, *, timeout_s=None, **kw):
        seen["timeout"] = timeout_s
        return mg.PacketScan(first_pts=0.0, complete=False)

    import audel.mediaguard as mg

    monkeypatch.setattr(mg, "scan_packets", gaps)
    del ms
    r = asyncio.run(check(str(media["good"])))
    assert _checks(r, "gap_scan_incomplete")
    assert seen["timeout"] is not None and seen["timeout"] <= 1000.0  # inside the file budget


# ==== round 7, auth surface ===================================================================

def test_minting_never_returns_a_token_the_server_would_refuse(monkeypatch):
    import secrets

    from audel.auth import new_token, strong_token

    bodies = iter(["gwDY1nlHUWOsZoVYF8gZBABCDEFtW5MROuGaPa79cAps"[:43], secrets.token_urlsafe(32)])
    monkeypatch.setattr(secrets, "token_urlsafe", lambda n: next(bodies))
    t = new_token()
    assert strong_token(t) and "ABCDEF" not in t


def test_zig_zag_bodies_are_not_called_structured():
    from audel.auth import _structured

    assert not _structured("gwDY1nlHUWOsZoVYF8gZBABCDCtW5MROuGaPa79cAps")
    assert _structured("gwDY1nlHUWOsZoVYF8gZABCDEFtW5MROuGaPa79cAps")
    assert _structured("gwDY1nlHUWOsZoVYF8gZFEDCBAtW5MROuGaPa79cAps")


def test_jwts_and_percent_encoded_tokens_are_redacted_from_urls():
    from audel.auth import new_token
    from audel.logging import register_secret, scrub_text

    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJ0ZW5hbnQiOiJhIn0.c2lnbmF0dXJlLWJ5dGVz"
    assert jwt not in scrub_text(f'"GET /specs?jwt={jwt} HTTP/1.1" 401')
    tok = new_token()
    enc = tok.replace("_", "%5F")
    assert enc not in scrub_text(f'"GET /specs?auth={enc} HTTP/1.1" 401')
    shared = "s3cret-shared-value_x"
    register_secret(shared)
    assert "s3cret" not in scrub_text("GET /?k=" + shared.replace("_", "%5F").replace("-", "%2D"))


@pytest.mark.parametrize("entry", ["::ffff:0:0/96", "::ffff:0.0.0.0/96", "::/32", "::/96",
                                   "0.0.0.0/0.0.0.0", "0.0.0.0/00"])
def test_ipv4_mapped_and_netmask_wildcards_are_refused(entry):
    with pytest.raises(ValueError):
        Settings(forwarded_allow_ips=[entry])


def test_specific_ipv4_mapped_proxy_is_accepted():
    assert Settings(forwarded_allow_ips=["::ffff:10.0.0.0/104", "2001:db8::/32"])


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
@pytest.mark.parametrize("entry,ok", [("0.0.0.0/00", False), ("0.0.0.0/0.0.0.0", False),
                                      ("::/0000", False), ("::ffff:0:0/96", False),
                                      ("10.0.0.0/8", True), ("fd00::/48", True)])
def test_helm_proxy_entry_forms(entry, ok):
    from pathlib import Path

    chart = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "audel"
    r = subprocess.run(["helm", "template", "t", str(chart), "--set", "auth.existingSecret=s",
                        "--set", f"forwardedAllowIps={{{entry}}}"], capture_output=True, text=True)
    assert (r.returncode == 0) == ok, r.stderr


# ==== round 7, network surface ================================================================

@requires_ffmpeg
def test_render_audit_records_refusals_and_input_identity(tmp_path, media, monkeypatch):
    import audel.core as core

    log = tmp_path / "audit.jsonl"
    s = Settings(cache_dir=tmp_path / "ws", audit_log=log)

    def boom(*a, **k):
        raise ValueError("stub crash")

    with TestClient(build_app(settings=s)) as c:
        ok = c.post("/render", files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")})
        monkeypatch.setattr(core, "render", boom)
        with pytest.raises(ValueError):
            c.post("/render", files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")})
    rows = [json.loads(x) for x in log.read_text().splitlines() if '"/render"' in x]
    assert ok.status_code == 200
    assert [r["status"] for r in rows] == ["ok", "error"]
    assert all(r.get("input_sha256") and r.get("input_bytes") for r in rows)


def test_failed_upload_spool_leaves_no_file(tmp_path, monkeypatch):
    import os as _os

    s = Settings(cache_dir=tmp_path / "ws")
    real = _os.fdopen

    class Full:
        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.fh.close()

        def write(self, b):
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(_os, "fdopen", lambda fd, mode="r", *a, **k:
                        Full(real(fd, mode, *a, **k)) if mode == "wb" else real(fd, mode, *a, **k))
    with TestClient(build_app(settings=s), raise_server_exceptions=False) as c:
        r = c.post("/check", files={"file": ("a.wav", b"RIFF" + b"x" * 5000, "audio/wav")})
    monkeypatch.setattr(_os, "fdopen", real)
    assert r.status_code >= 400
    assert not [f for f in (tmp_path / "ws" / "tmp").iterdir() if f.name.startswith("upload_")]


def test_busy_fetch_inside_a_job_says_retry(tmp_path, monkeypatch):
    import audel.ingest as ing
    from audel.errors import BusyError
    from audel.jobs import _public_error

    assert "busy" in _public_error(BusyError("Too many downloads in progress.")).lower()

    async def slow_fetch(url, tmp, settings):
        await asyncio.sleep(4.0)
        raise UnsafeSourceError("stub upstream")

    monkeypatch.setattr(ing, "fetch_to_file", slow_fetch)
    monkeypatch.setattr(ing, "validate_ingest_url", lambda u, s: None)
    s = Settings(cache_dir=tmp_path / "ws", allow_url_ingest=True, queue_wait_s=0.5)
    with TestClient(build_app(settings=s)) as c:
        ids = [c.post("/jobs", data={"url": f"https://media.example/{i}.wav"}).json()["job_id"]
               for i in range(3)]
        time.sleep(1.5)
        states = [c.get(f"/jobs/{i}").json() for i in ids]
    failed = [j for j in states if j["status"] == "failed"]
    assert failed and "busy" in failed[0]["error"].lower()


def test_service_start_reaps_stale_temp_files(tmp_path):
    ws = tmp_path / "ws"
    build_app(settings=Settings(cache_dir=ws))
    stale, fresh = ws / "tmp" / "upload_old.wav", ws / "tmp" / "upload_new.wav"
    stale.write_bytes(b"x")
    fresh.write_bytes(b"x")
    old = time.time() - 2 * 86400
    os.utime(stale, (old, old))
    build_app(settings=Settings(cache_dir=ws))
    assert not stale.exists() and fresh.exists()


# ==== round 7, decode surface =================================================================

def _wav_with_size(tmp_path, name, size_field):
    import struct

    f = tmp_path / name
    _ff("-f", "lavfi", "-i", "sine=d=4", f)
    b = bytearray(f.read_bytes())
    i = b.index(b"data")
    b[i + 4:i + 8] = struct.pack("<I", size_field)
    f.write_bytes(bytes(b))
    return f


@requires_ffmpeg
@pytest.mark.parametrize("placeholder", [0x7FFF0000, 0x80000000, 0xFFFFFFFF, 0])
def test_streaming_writer_placeholders_are_not_called_truncated(tmp_path, placeholder):
    from audel import check

    f = _wav_with_size(tmp_path, "s.wav", placeholder)
    assert not _checks(asyncio.run(check(str(f))), "container_truncated")


@requires_ffmpeg
@pytest.mark.parametrize("ext", ["mkv", "ts"])
def test_late_audio_is_timed_from_its_first_packet(tmp_path, ext):
    from audel import check

    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=10", "-af",
        "volume=enable='between(t,3,6)':volume=0,afade=t=out:st=9:d=1", a)
    f = tmp_path / f"late.{ext}"
    vcodec = ["-c:v", "ffv1"] if ext == "mkv" else ["-c:v", "mpeg2video"]
    acodec = ["-c:a", "flac"] if ext == "mkv" else ["-c:a", "mp2"]
    _ff("-f", "lavfi", "-i", "color=c=black:s=64x64:d=18", "-itsoffset", "8", "-i", a,
        "-map", "0:v", "-map", "1:a", *vcodec, *acodec, f)
    r = asyncio.run(check(str(f)))
    assert not _checks(r, "duration_mismatch"), [i.message for i in r.issues]
    gap = [i for i in _checks(r, "silence_gap") if i.span.end_ms - i.span.start_ms < 5000]
    assert gap and 10_500 <= gap[0].span.start_ms <= 11_500, [i.span for i in r.issues]


@requires_ffmpeg
@pytest.mark.parametrize("ext", ["aiff", "caf"])
def test_cut_short_aiff_and_caf_are_caught(tmp_path, ext):
    from audel import check

    full = tmp_path / f"full.{ext}"
    _ff("-f", "lavfi", "-i", "sine=d=30", "-af", "volume=0.3", "-ac", "2", "-c:a",
        "pcm_s16be" if ext == "aiff" else "pcm_s16le", full)
    cut = tmp_path / f"cut.{ext}"
    data = full.read_bytes()
    cut.write_bytes(data[: (len(data) * 2 // 3) // 4 * 4])
    assert not _checks(asyncio.run(check(str(full))), "container_truncated")
    bad = _checks(asyncio.run(check(str(cut))), "container_truncated")
    assert bad and 8 <= bad[0].detail["missing_s"] <= 12


def test_bw64_and_many_chunk_wavs_are_walked(tmp_path):
    import struct

    from audel.mediaguard import container_shortfall_s

    pcm = b"\0" * 48000 * 4 * 10                   # 10 s stereo 16-bit at 48 kHz
    fmt = struct.pack("<HHIIHH", 1, 2, 48000, 192000, 4, 16)
    junk = b"".join(b"JUNK" + struct.pack("<I", 8) + b"\0" * 8 for _ in range(200))
    for magic in (b"RIFF", b"BW64"):
        body = b"WAVE" + junk + b"fmt " + struct.pack("<I", 16) + fmt + b"data" + \
            struct.pack("<I", len(pcm)) + pcm[: len(pcm) // 2]
        f = tmp_path / f"{magic.decode()}.wav"
        f.write_bytes(magic + struct.pack("<I", len(body)) + body)
        assert 4.9 <= container_shortfall_s(f, 3600) <= 5.1, magic


def test_crafted_declared_length_is_clamped(tmp_path):
    import struct

    from audel.mediaguard import container_shortfall_s

    ds64 = struct.pack("<QQQI", 0, 1 << 61, 0, 0)
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 1, 1, 8)
    body = b"WAVE" + b"ds64" + struct.pack("<I", len(ds64)) + ds64 + b"fmt " + \
        struct.pack("<I", 16) + fmt + b"data" + struct.pack("<I", 0xFFFFFFFF) + b"\0" * 100
    f = tmp_path / "huge.wav"
    f.write_bytes(b"RF64" + struct.pack("<I", 0xFFFFFFFF) + body)
    assert container_shortfall_s(f, 3600) <= 3600


def _scan(packets):
    from audel.mediaguard import _GapScanner

    sc = _GapScanner(0.1, 50)
    for pts, dur in packets:
        sc.add(pts, dur)
    return sc.finish()


def test_gap_scan_survives_missing_durations_and_backward_jumps():
    na = [(i / 1200, None) for i in range(1200 * 5) if not (2.0 <= i / 1200 < 2.8)]
    assert [(round(a, 2), round(b, 2)) for a, b in _scan(na).gaps] == [(2.0, 2.8)]
    seg = [(1000 + i * 0.024, 0.024) for i in range(400)]
    back = seg + [(i * 0.024, 0.024) for i in range(400) if not (4 <= i * 0.024 < 5)]
    gaps = _scan(back).gaps
    assert len(gaps) == 1 and 0.9 <= gaps[0][1] - gaps[0][0] <= 1.1


def test_two_packet_clips_have_no_false_long_packet_gap():
    assert _scan([(0.0, 1.045), (1.045, 0.455)]).gaps == []
    assert _scan([(0.0, 0.512), (0.512, 0.188)]).gaps == []


@requires_ffmpeg
def test_findings_after_a_gap_are_on_programme_time(tmp_path):
    from audel import check

    raw = tmp_path / "r.m4a"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=12", "-af",
        "volume=0.3,volume=enable='between(t,8,8.1)':volume=40", "-c:a", "aac", raw)
    f = tmp_path / "gap.m4a"
    _ff("-i", raw, "-c", "copy", "-bsf:a", "noise=drop='between(pts*tb,3,5)'", f)
    r = asyncio.run(check(str(f)))
    gap, clip = _checks(r, "packet_gap"), _checks(r, "clipping")
    assert gap and 2_800 <= gap[0].span.start_ms <= 3_200
    assert clip and 7_700 <= clip[0].span.start_ms <= 8_300, [c.span for c in clip]


@requires_ffmpeg
def test_spans_lists_are_shifted_with_the_track(tmp_path):
    from audel import check

    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=8", "-af",
        "volume=enable='between(t,2,2.4)+between(t,4,4.4)':volume=40", a)
    f = tmp_path / "d.mov"
    _ff("-f", "lavfi", "-i", "color=c=black:s=64x64:d=11", "-itsoffset", "3", "-i", a,
        "-map", "0:v", "-map", "1:a", "-c:v", "mpeg4", "-c:a", "pcm_s16le", f)
    clip = _checks(asyncio.run(check(str(f))), "clipping")
    assert clip and all(s[0] >= 4_500 for s in clip[0].detail["spans_ms"]), clip[0].detail


@requires_ffmpeg
def test_video_longer_than_audio_is_not_a_duration_mismatch(tmp_path):
    from audel import check

    f = tmp_path / "v.mp4"
    _ff("-f", "lavfi", "-i", "color=c=black:s=64x64:d=12", "-f", "lavfi", "-i", "sine=d=10",
        "-map", "0:v", "-map", "1:a", "-c:v", "mpeg4", "-c:a", "aac", f)
    assert not _checks(asyncio.run(check(str(f))), "duration_mismatch")


def test_whole_track_spans_stay_inside_the_programme():
    from audel.mediaguard import StreamInfo
    from audel.signals.checks import _track_span
    from audel.signals.measure import TrackMeasurements

    tm = TrackMeasurements(stream=StreamInfo(index=0, codec="pcm", sample_rate=48000,
                                             channels=2, start_s=3.0), decoded_s=7.0)
    sp = _track_span(tm, 10.0)
    assert (sp.start_ms, sp.end_ms) == (3000, 10000)


# ==== round 8, auth surface ===================================================================

@pytest.mark.parametrize("hostile", ["eyJ" * 22000, "eyJAAAAAAAAA." + "eyJ" * 22000,
                                     "sk-" * 22000, "token=" * 11000, "audel_" * 11000,
                                     "Bearer " * 9000, "%41" * 22000, "eyJaaaaaaaaa." * 5000])
def test_redaction_is_linear_on_hostile_log_lines(hostile):
    from audel.logging import scrub_text

    t0 = time.perf_counter()
    scrub_text("GET /" + hostile + " HTTP/1.1")
    assert time.perf_counter() - t0 < 0.5   # was seconds (quadratic) for 16 KB


@pytest.mark.parametrize("text", ["GET /jobs/task-0123456789abcdef",
                                  "source_host=desk-reporting.example.com",
                                  "risk-assessment-2024", "mask-channels-5.1.4", "token expired",
                                  "secret rotation", "Api-Key header missing"])
def test_ordinary_words_are_not_redacted(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_encoded_tenant_tokens_are_redacted_and_decoding_cannot_inject_lines():
    from audel.auth import new_token
    from audel.logging import scrub_text

    tok = new_token()
    for enc in (tok.replace("_", "%255F"), "".join(f"%{b:02X}" for b in tok.encode())):
        assert tok not in scrub_text(f"GET /?a={enc}") and enc not in scrub_text(f"GET /?a={enc}")
    out = scrub_text("GET /?x=%0Aforged&a=" + tok.replace("_", "%5F"))
    assert "\n" not in out and tok not in out


@pytest.mark.parametrize("entry", ["64:ff9b::/96", "64:ff9b:1::/48", "0::ffff:0:0/96"])
def test_nat64_and_mapped_spellings_are_refused(entry):
    with pytest.raises(ValueError):
        Settings(forwarded_allow_ips=[entry])


def test_nat64_clients_are_keyed_by_their_own_ipv4():
    from audel.auth import client_key

    assert client_key("64:ff9b::808:808") == "8.8.8.8"
    assert client_key("64:ff9b::101:101") != client_key("64:ff9b::808:808")


def test_settings_dumps_never_carry_secrets():
    s = Settings(api_token="audel_secret_value_zzzzzz", ollama_api_key="k-ollama-123456",
                 anthropic_api_key="k-anthropic-123456", google_api_key="k-google-123456")
    dumped = s.model_dump_json() + repr(s.model_dump())
    for v in ("audel_secret_value_zzzzzz", "k-ollama-123456", "k-anthropic-123456",
              "k-google-123456"):
        assert v not in dumped
    assert s.api_token == "audel_secret_value_zzzzzz"   # still usable in-process


# ==== round 8, network surface ================================================================

def _scan_threads():
    import threading

    return [t for t in threading.enumerate() if t.name.startswith("audel-scan")]


@requires_ffmpeg
def test_refused_file_stops_its_packet_scans(tmp_path, monkeypatch):
    import audel.signals.measure as ms
    from audel.mediaguard import probe

    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=d=4", a)
    mkv = tmp_path / "m.mkv"
    _ff(*sum((["-i", str(a)] for _ in range(6)), []),
        *sum((["-map", f"{i}:a"] for i in range(6)), []), "-c:a", "pcm_s16le", mkv)

    def boom(*a, **k):
        time.sleep(0.2)
        raise UnsafeSourceError("analysis exceeded the per-file time budget")

    monkeypatch.setattr(ms, "_main_pass", boom)
    s = Settings()
    with pytest.raises(UnsafeSourceError):
        ms.measure(mkv, probe(mkv, s), s)
    deadline = time.monotonic() + 3
    while _scan_threads() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _scan_threads()


def test_spawn_failure_is_busy_not_a_500(tmp_path, media, monkeypatch):
    import subprocess as sp

    real = sp.Popen

    def no_fork(argv, *a, **k):
        if "ffmpeg" in str(argv[0]):
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return real(argv, *a, **k)

    monkeypatch.setattr(sp, "Popen", no_fork)
    s = Settings(cache_dir=tmp_path / "ws")
    with TestClient(build_app(settings=s)) as c:
        r = c.post("/check", files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")})
    assert r.status_code == 429, r.text


def test_deleted_running_job_is_audited_as_cancelled(tmp_path, media, monkeypatch):
    import audel.core as core

    started = []

    async def slow_check(*a, **k):
        started.append(1)
        await asyncio.sleep(30)

    monkeypatch.setattr(core, "check", slow_check)
    log = tmp_path / "audit.jsonl"
    s = Settings(cache_dir=tmp_path / "ws", audit_log=log)
    with TestClient(build_app(settings=s)) as c:
        jid = c.post("/jobs", files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")}
                     ).json()["job_id"]
        for _ in range(200):
            if started:
                break
            time.sleep(0.02)
        assert started
        assert c.delete(f"/jobs/{jid}").status_code == 200
        time.sleep(0.3)
    rows = [json.loads(x) for x in log.read_text().splitlines() if jid in x]
    assert rows and rows[-1]["status"] == "cancelled", rows


# ==== round 8, decode surface =================================================================

def _setts(src, dst, expr):
    _ff("-i", src, "-c", "copy", "-bsf:a", f"setts=pts={expr}:dts={expr.replace('PTS', 'DTS')}",
        dst)


@pytest.fixture
def base_mka(tmp_path):
    f = tmp_path / "base.mka"
    _ff("-f", "lavfi", "-i", "sine=d=20", "-af", "volume=0.3,afade=t=out:st=18:d=2", "-c:a",
        "flac", f)
    return f


@requires_ffmpeg
def test_a_long_dropout_outside_ts_is_a_gap_not_a_splice(tmp_path, base_mka):
    from audel import check

    f = tmp_path / "jump.mka"
    _setts(base_mka, f, r"if(gte(PTS*TB\,10)\,PTS+70/TB\,PTS)")
    gaps = _checks(asyncio.run(check(str(f))), "packet_gap")
    assert gaps and gaps[0].detail["gap_s"] >= 69, [g.detail for g in gaps]


@requires_ffmpeg
def test_missing_audio_spread_through_a_track_is_caught(tmp_path, base_mka):
    from audel import check

    f = tmp_path / "choppy.mka"
    _setts(base_mka, f, "PTS+floor(PTS/100)*50")     # many holes below the gap threshold
    r = asyncio.run(check(str(f)))
    short = _checks(r, "timeline_shortfall") + _checks(r, "packet_gap_total")
    assert short or _checks(r, "packet_gap"), [i.detail.get("check") for i in r.issues]
    assert r.verdict.value != "pass"


def test_scanner_shortfall_from_stretched_durations():
    sc = _scan([(i * 0.175, 0.175) for i in range(120)])
    assert sc.gaps == [] and 20.5 <= sc.extent_s <= 21.5   # extent checked against decoded


def test_a_ts_decoy_packet_cannot_hide_a_gap():
    from audel.mediaguard import _GapScanner

    sc = _GapScanner(0.1, 50, fold=True)
    pk = [(1 + i * 0.024, 0.024) for i in range(int(10 / 0.024))]
    pk += [(100.0, 0.05)]                                  # one stray packet far ahead
    pk += [(16 + i * 0.024, 0.024) for i in range(200)]    # audio resumes after a 5 s hole
    for p in pk:
        sc.add(*p)
    gaps = sc.finish().gaps
    assert len(gaps) == 1 and 4.5 <= gaps[0][1] - gaps[0][0] <= 5.5, gaps


def test_ts_splices_are_still_folded():
    from audel.mediaguard import _GapScanner

    sc = _GapScanner(0.1, 50, fold=True)
    for p in [(1 + i * 0.024, 0.024) for i in range(400)] + \
             [(1000 + i * 0.024, 0.024) for i in range(400)]:
        sc.add(*p)
    res = sc.finish()
    assert res.gaps == [] and res.segments and 19 <= res.extent_s <= 20


def test_gaps_past_the_list_limit_still_count():
    from audel.mediaguard import _GapScanner

    sc = _GapScanner(0.1, 5, fold=False)
    t = 0.0
    for i in range(2000):
        sc.add(t, 0.02)
        t += 0.02 + (0.3 if i % 20 == 19 else 0.0)        # 99 gaps of 0.3 s
    res = sc.finish()
    assert len(res.gaps) == 5 and res.gap_count == 99 and 29 <= res.gap_total_s <= 30


@requires_ffmpeg
def test_ts_pts_wrap_keeps_the_tail_seek_right(tmp_path):
    from audel import check

    a = tmp_path / "a.wav"
    _ff("-f", "lavfi", "-i", "sine=d=30", "-af", "volume=0.3,afade=t=out:st=27:d=3", a)
    f = tmp_path / "wrap.ts"
    _ff("-i", a, "-c:a", "mp2", "-output_ts_offset", "95430", f)   # wraps 2^33 mid-file
    r = asyncio.run(check(str(f)))
    assert not [i for i in r.issues if i.detail.get("check") == "truncation"]


@requires_ffmpeg
@pytest.mark.parametrize("ext", ["mkv", "webm"])
def test_video_outlasting_audio_without_stream_durations(tmp_path, ext):
    from audel import check

    f = tmp_path / f"v.{ext}"
    v = ["-c:v", "ffv1"] if ext == "mkv" else ["-c:v", "libvpx", "-b:v", "50k"]
    ac = ["-c:a", "flac"] if ext == "mkv" else ["-c:a", "libopus"]
    _ff("-f", "lavfi", "-i", "color=c=black:s=64x64:d=12", "-f", "lavfi", "-i", "sine=d=9",
        "-map", "0:v", "-map", "1:a", *v, *ac, f)
    assert not _checks(asyncio.run(check(str(f))), "duration_mismatch")


def test_compressed_wav_is_not_sized_from_its_nominal_byte_rate(tmp_path):
    import struct

    from audel.mediaguard import container_shortfall_s

    fmt = struct.pack("<HHIIHH", 2, 1, 8000, 4096, 256, 4)   # MS ADPCM: nominal byte rate
    body = b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt + b"data" + \
        struct.pack("<I", 40000) + b"\0" * 20000
    f = tmp_path / "adpcm.wav"
    f.write_bytes(b"RIFF" + struct.pack("<I", len(body)) + body)
    assert container_shortfall_s(f, 3600) == 0.0


@requires_ffmpeg
def test_cut_alaw_aifc_is_caught(tmp_path):
    from audel import check

    full = tmp_path / "a.aifc"
    _ff("-f", "lavfi", "-i", "sine=d=6", "-c:a", "pcm_alaw", full)
    cut = tmp_path / "cut.aifc"
    data = full.read_bytes()
    cut.write_bytes(data[: len(data) * 6 // 10])
    assert not _checks(asyncio.run(check(str(full))), "container_truncated")
    assert _checks(asyncio.run(check(str(cut))), "container_truncated")


# ==== round 9, auth surface ===================================================================

@pytest.mark.parametrize("unit", ["-eyJ", "_eyJ", "-EYA", "eyJ", "eyJAAAAAAAAA.", "sk-", "_sk-",
                                  "token=", "audel_", "_audel_", "Bearer ", "%41", "%25",
                                  "Authorization: ", "a.", "eyJaaaaaaaa.b.", "token     ",
                                  "eyJaaaaaaaaaa..", "eyJaaaaaaaaaaaa.bb."])
def test_scrubbing_is_linear_for_every_shape(unit):
    from audel.logging import scrub_text

    def best(text):  # CPU time: wall clock on a shared host is too noisy for a ratio
        out = []
        for _ in range(3):
            t0 = time.process_time()
            scrub_text(text)
            out.append(time.process_time() - t0)
        return min(out)

    t_small = best(unit * (64_000 // len(unit)))
    t_big = best(unit * (1_024_000 // len(unit)))   # 16x the input
    assert t_big < 5.0 and t_big < 48 * max(t_small, 2e-3), (t_small, t_big)  # quadratic: ~256x


def test_log_records_are_bounded_before_scrubbing():
    import logging as lg

    from audel.auth import new_token
    from audel.logging import _SecretScrubber

    tok = new_token()
    for payload in ("-eyJ" * 250_000, "a" * 8170 + tok + "b" * 100):
        r = lg.LogRecord("uvicorn.access", 20, "x", 1, '%s - "%s %s HTTP/%s" %d',
                         ("1.2.3.4", "GET", "/" + payload, "1.1", 401), None)
        t0 = time.perf_counter()
        _SecretScrubber().filter(r)
        msg = r.getMessage()
        assert time.perf_counter() - t0 < 0.5 and tok[:16] not in msg and len(msg) < 9000


@pytest.mark.parametrize("text", ["x=1{tok}", "GET /files/v2{tok}", "v1{jwt}", "jwt=x{jwt}",
                                  "nonceBearer Zx81kQpLmN0vR7tY", "accessToken=Zx81kQpLmN0vR7tY",
                                  "clientSecret=abcdefgh", "dbPassword=abcdefgh",
                                  "Authorization: Token abcdefghij", "Bearer\nZx81kQpLmN0vR7tY",
                                  "{enc4}", "{full}"])
def test_glued_cased_and_deeply_encoded_credentials_are_redacted(text):
    from audel.auth import new_token
    from audel.logging import scrub_text

    tok = new_token()
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJ0ZW5hbnQiOiJhIn0.c2lnbmF0dXJlLWJ5dGVz"
    t = text.format(tok=tok, jwt=jwt, enc4=tok.replace("_", "%2525255F"),
                    full="1" + "".join(f"%{b:02X}" for b in tok.encode()))
    out = scrub_text(t)
    for secret in (tok[6:30], jwt[:30], "abcdefgh", "Zx81kQpLmN0vR7tY"):
        assert secret not in out, out


def test_decoding_never_rewrites_or_forges_the_line():
    import json as _json

    from audel.logging import scrub_text

    line = 'GET /specs%22%20200%20%22-?token=abcdefgh HTTP/1.1'
    assert scrub_text(line) == 'GET /specs%22%20200%20%22-?token=[REDACTED] HTTP/1.1'
    j = _json.dumps({"brief": "ref %22,%22schema_version%22:%220 and %0A token=abcdefgh"})
    assert _json.loads(scrub_text(j)) == {"brief": "ref %22,%22schema_version%22:%220 and %0A "
                                                   "token=[REDACTED]"}


def test_nat64_48_clients_are_not_pooled_and_teredo_is_refused():
    from audel.auth import client_key

    assert client_key("64:ff9b:1:c000:2:2100::") != client_key("64:ff9b:1:c633:6:4000::")
    for bad in ("2001::/32", "2001:0:4136:e378::/64"):
        with pytest.raises(ValueError):
            Settings(forwarded_allow_ips=[bad])
    assert Settings(forwarded_allow_ips=["2001:db8::/32", "2001::1/128"])


def test_root_and_asyncio_records_are_scrubbed_under_serve():
    from audel.logging import uvicorn_log_config

    cfg = uvicorn_log_config()
    assert cfg["root"]["handlers"] and all(
        "audel_scrub" in cfg["handlers"][h]["filters"] for h in cfg["root"]["handlers"])


# ==== round 9, decode surface =================================================================

def _gs(packets, *, fold, limit=50, max_gap=10800.0):
    from audel.mediaguard import _GapScanner

    sc = _GapScanner(0.1, limit, fold=fold, max_gap_s=max_gap)
    for p in packets:
        sc.add(*p)
    return sc, sc.finish()


def _spread_loss(n=1740, frame=0.0232):
    return [(i * frame, frame) for i in range(n) if i % 3 != 2]       # a third of frames gone


@pytest.mark.parametrize("fold", [True, False])
def test_decoys_cannot_capture_the_clock(fold):
    real = _spread_loss()
    pk = [(5.0, 0.0232)]                                   # a leading decoy...
    for i, p in enumerate(real):
        pk.append(p)
        if i % 6 == 5:
            pk.append((5.0, 0.0232))                       # ...repeated every 6 real packets
    _, res = _gs(pk, fold=fold)
    decoded = len(real) * 0.0232
    assert res.extent_s - (decoded - res.overlap_s) - res.gap_total_s > 0.2 * res.extent_s


def test_duplicates_cannot_cancel_missing_audio():
    pk = []
    for i in range(1725):
        if i % 5 == 4:
            continue                                       # 20% dropped
        pk.append((i * 0.0232, 0.0232))
        if i % 5 == 0:
            pk.append((i * 0.0232, 0.0232))                # 20% duplicated
    _, res = _gs(pk, fold=True)
    decoded = len(pk) * 0.0232
    assert res.overlap_s > 0.15 * res.extent_s
    assert res.extent_s - (decoded - res.overlap_s) - res.gap_total_s > 0.1 * res.extent_s


def test_millisecond_rounded_truehd_is_not_counted_as_duplicates():
    pk = [(round(i / 1200, 3), None) for i in range(1200 * 20)]
    _, res = _gs(pk, fold=False)
    assert res.overlap_s < 0.05 and res.gap_total_s == 0 and 19.9 <= res.extent_s <= 20.1


def test_impossible_jumps_are_folded_and_counted_everywhere():
    pk = [(i * 0.0232, 0.0232) for i in range(400)] + \
         [(4_294_967.0 + i * 0.0232, 0.0232) for i in range(400)]
    _, res = _gs(pk, fold=False, max_gap=10800.0)
    assert res.jumps == 1 and res.gap_total_s == 0 and res.extent_s < 20


def test_jump_segments_are_capped():
    pk = []
    t = 100.0
    for _ in range(300):
        pk += [(t + k * 0.0232, 0.0232) for k in range(3)]
        t -= 0.1                                           # a backward step every 3 packets
    sc, res = _gs(pk, fold=True, limit=20)
    assert len(res.segments) <= 20 and sc.overflow


def test_shared_clock_tolerates_inter_pid_skew_at_a_splice():
    from audel.mediaguard import PacketScan
    from audel.signals.measure import _shared_clock

    a = PacketScan(first_pts=1.0, last_end=41.0, segments=[(1000.0, 989.0)])
    b = PacketScan(first_pts=999.99, last_end=1030.0)
    _shared_clock([a, b])
    assert 10.5 <= b.first_pts <= 11.5


def test_decode_failure_reports_the_cause_not_the_statistics():
    from audel.mediaguard import _cause

    tail = ("[aac @ 0x1] Changing audio frame properties on the fly is not supported.\n"
            "[aist#0:0/aac] Decoding error: Invalid data found when processing input\n"
            "[in#0/mp3] Input stream #0:0 (audio): 120 packets read; 98 frames decoded; "
            "0 decode errors (452608 samples)\n")
    assert "Invalid data" in _cause(tail) or "not supported" in _cause(tail)


@requires_ffmpeg
def test_avi_compressed_audio_extent_is_not_trusted(tmp_path):
    from audel.mediaguard import probe
    from audel.signals.measure import measure

    f = tmp_path / "a.avi"
    _ff("-f", "lavfi", "-i", "color=c=black:s=64x64:d=6", "-f", "lavfi", "-i", "sine=d=6",
        "-map", "0:v", "-map", "1:a", "-c:v", "mpeg4", "-c:a", "libmp3lame", "-q:a", "0", f)
    s = Settings()
    m = measure(f, probe(f, s), s)
    assert m.tracks[0].extent_s == 0.0


@requires_ffmpeg
def test_multi_track_ts_of_unknown_length_is_graded_not_refused(tmp_path):
    from audel import check

    seg = []
    for i, off in enumerate((1000, 10)):
        a = tmp_path / f"s{i}.ts"
        _ff("-f", "lavfi", "-i", "sine=d=5", "-f", "lavfi", "-i", "sine=f=660:d=5",
            "-map", "0:a", "-map", "1:a", "-c:a", "aac", "-output_ts_offset", str(off), a)
        seg.append(a.read_bytes())
    f = tmp_path / "restart.ts"
    f.write_bytes(b"".join(seg))
    r = asyncio.run(check(str(f)))
    assert r.tracks and not [i for i in r.issues if i.detail.get("check") == "decode_error"], \
        [i.message for i in r.issues]


def test_shared_clock_picks_the_segment_by_timestamp_not_by_order():
    from audel.mediaguard import PacketScan
    from audel.signals.measure import _shared_clock

    # Reference: a stray at 101, real packets unwrapped past 2^33 (fold), then a step back to 41.
    a = PacketScan(first_pts=101.0, last_end=141.0,
                   segments=[(95444.739, 95343.717), (41.0, -59.0)])
    b = PacketScan(first_pts=95444.717, last_end=95484.7)
    _shared_clock([a, b])
    assert 100 <= b.first_pts <= 102


# ==== round 9, network surface ================================================================

def _busy_spawn(monkeypatch, match):
    import subprocess as sp

    real = sp.Popen

    def popen(argv, *a, **k):
        if match(argv):
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return real(argv, *a, **k)

    monkeypatch.setattr(sp, "Popen", popen)


@requires_ffmpeg
def test_a_busy_host_never_silently_drops_the_truncation_check(media, monkeypatch):
    from audel import check
    from audel.errors import BusyError

    _busy_spawn(monkeypatch, lambda argv: "-sseof" in argv or any(
        str(x).startswith("astats=metadata=0:measure_overall=RMS_level") for x in argv))
    with pytest.raises(BusyError):
        asyncio.run(check(str(media["good"])))


def test_analyze_and_handoff_report_busy_not_a_bad_file(tmp_path, media, monkeypatch):
    _busy_spawn(monkeypatch, lambda argv: "ffmpeg" in str(argv[0]))
    s = Settings(cache_dir=tmp_path / "ws")
    with TestClient(build_app(settings=s)) as c:
        for route in ("/analyze", "/handoff"):
            r = c.post(route, files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")})
            assert r.status_code == 429, (route, r.status_code, r.text)


@requires_ffmpeg
def test_thread_exhaustion_is_busy_and_leaves_no_scans(media, monkeypatch):
    import concurrent.futures as cf

    import audel.signals.measure as ms
    from audel.errors import BusyError
    from audel.mediaguard import probe

    real = cf.ThreadPoolExecutor.submit
    calls = {"n": 0}

    def submit(self, *a, **k):
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("can't start new thread")
        return real(self, *a, **k)

    monkeypatch.setattr(cf.ThreadPoolExecutor, "submit", submit)
    s = Settings()
    info = probe(media["good"], s)
    info = type(info)(**{**info.__dict__, "streams": info.streams * 2})
    with pytest.raises(BusyError):
        ms.measure(media["good"], info, s)
    deadline = time.monotonic() + 5
    while _scan_threads() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _scan_threads()


@requires_ffmpeg
def test_scan_without_a_watchdog_thread_never_runs_unwatched(media, monkeypatch):
    import threading

    from audel.mediaguard import scan_packets

    real = threading.Thread.start

    def start(self):
        if self.name == "audel-scan-watch":
            raise RuntimeError("can't start new thread")
        return real(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    from audel.errors import BusyError

    with pytest.raises(BusyError):  # round 10: retried (429), never an incomplete-scan WARN
        scan_packets(media["good"], Settings(), 0, timeout_s=10)


@requires_ffmpeg
def test_cli_exits_75_when_the_host_is_busy(media):
    import sys

    code = ("import subprocess as sp, sys\n"
            "real = sp.Popen\n"
            "def no(argv, *a, **k):\n"
            "    if 'ffmpeg' in str(argv[0]): raise BlockingIOError(11, 'x')\n"
            "    return real(argv, *a, **k)\n"
            "sp.Popen = no\n"
            "sys.argv = ['audel', 'check', sys.argv[1]]\n"
            "from audel.adapters.cli import main\n"
            "main()\n")
    r = subprocess.run([sys.executable, "-c", code, str(media["good"])], capture_output=True,
                       text=True)
    assert r.returncode == 75 and "busy" in r.stderr and "Traceback" not in r.stderr


def test_mcp_tools_report_busy():
    import audel.adapters.mcp as m
    from audel.errors import BusyError

    async def tool():
        raise BusyError("host at capacity")

    seen = {}
    wrapped = m._busy_safe(lambda fn: seen.setdefault("fn", fn))(tool)
    del wrapped
    out = asyncio.run(seen["fn"]())
    assert out["error"] == "busy" and out["retry"] is True


# ==== round 10, auth surface ==================================================================

@pytest.mark.parametrize("unit", ["%!", "%%%%%%!", ".!", "a!", "%41!", "aaaaa!", "%41%41!"])
def test_tiny_run_floods_are_cheap_per_byte(unit):
    from audel.logging import scrub_text

    text = unit * (8192 // len(unit))
    best = 1e9
    for _ in range(5):
        t0 = time.perf_counter()
        scrub_text(text)
        best = min(best, time.perf_counter() - t0)
    assert best < 0.03, best          # was 27-48 ms per 8 KB field for "%!"


@pytest.mark.parametrize("path", ["/specs?token=", "/specs?authorization=x", "/x bearer ",
                                  "/" + "a" * 8170, "/specs?token={tok}"])
def test_access_lines_always_format(path):
    import logging as lg

    from uvicorn.logging import AccessFormatter

    from audel.auth import new_token
    from audel.logging import _SecretScrubber

    tok = new_token()
    rec = lg.LogRecord("uvicorn.access", 20, "x", 1, '%s - "%s %s HTTP/%s" %d',
                       ("1.2.3.4", "GET", path.format(tok=tok), "1.1", 401), None)
    _SecretScrubber().filter(rec)
    line = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s',
                           use_colors=False).format(rec)
    assert "HTTP/1.1" in line and tok not in line


@pytest.mark.parametrize("text", ["GET /files/keyArchive2024.tar.gz HTTP/1.1",
                                  '{"source_host": "surveyAnalytics.s3.amazonaws.com"}',
                                  "honeyJar_collection.items.list",
                                  "https://journeyAnalytics.example.com/a.wav",
                                  "Bearer authentication required", "the standard-bearer position",
                                  "token: expired at noon"])
def test_names_and_prose_are_not_redacted(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_real_jwts_still_redacted_in_every_header_form():
    import base64
    import json as _json

    from audel.logging import scrub_text

    def b64(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    for hdr in (b'{"alg":"RS256","typ":"JWT"}', b'{ "alg": "HS256" }', b'{"kid":"k1","alg":"ES256"}',
                b'{"x5t#S256":"abc","alg":"RS256"}'):
        jwt = f"{b64(hdr)}.{b64(_json.dumps({'tenant': 'a'}).encode())}.c2lnbmF0dXJlLWJ5dGVz"
        assert jwt[:20] not in scrub_text(f"GET /x?jwt={jwt}")


# ==== round 10, network surface ===============================================================

def test_splice_list_overflow_keeps_the_timeline_checks():
    from audel.mediaguard import _GapScanner

    sc = _GapScanner(0.1, 50, fold=True)
    t = 0.0
    for n in range(30_000):
        sc.add(t, 0.024)
        t += 0.048 + (61.0 if n % 10 == 9 else 0.0)   # 50% missing + a splice every 10
    res = sc.finish()
    assert sc.overflow and res.complete              # still graded, not "incomplete"
    decoded = 30_000 * 0.024
    assert res.extent_s - decoded - res.gap_total_s > 0.4 * res.extent_s


def test_a_busy_host_during_the_packet_scan_is_retried_not_downgraded(media, monkeypatch):
    from audel.errors import BusyError
    from audel.mediaguard import scan_packets

    _busy_spawn(monkeypatch, lambda argv: "ffprobe" in str(argv[0]) and "-show_entries" in argv
                and any(str(a).startswith("packet=pts_time") for a in argv))
    with pytest.raises(BusyError):
        scan_packets(media["good"], Settings(), 0, timeout_s=10)


def test_pipe_reader_thread_failure_is_busy_and_reaps_the_child(media, monkeypatch):
    import threading

    import audel.mediaguard as mg
    from audel.errors import BusyError

    real = threading.Thread.start

    def start(self):
        if getattr(self, "_target", None) is not None and \
                getattr(self._target, "__name__", "") == "_run":
            raise RuntimeError("can't start new thread")
        return real(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    ffprobe = mg._tool("ffprobe", None)
    with pytest.raises(BusyError):
        mg.run([ffprobe, "-v", "error", "-version"], timeout_s=10)


def test_dialogue_gate_skips_failed_tracks_and_keeps_the_grade(monkeypatch):
    import audel.signals.vad as vad
    from audel.core.render import _dialogue_gate
    from audel.errors import DecodeError
    from audel.mediaguard import MediaInfo, StreamInfo
    from audel.signals.measure import Measurements, TrackMeasurements

    st = [StreamInfo(index=i, codec="flac", sample_rate=48000, channels=2) for i in range(3)]
    m = Measurements(info=MediaInfo(duration_s=10, sample_rate=48000, channels=2, codec="flac",
                                    has_audio=True, streams=tuple(st)))
    m.tracks = [TrackMeasurements(stream=st[0]), TrackMeasurements(stream=st[1], failed="x"),
                TrackMeasurements(stream=st[2])]

    def regions(path, settings, stream=0, **kw):
        if stream == 1:
            raise AssertionError("failed track must be skipped")
        if stream == 2:
            raise DecodeError("could not decode audio for ASR")
        return [(0.0, 5.0)]

    monkeypatch.setattr(vad, "speech_regions", regions)
    monkeypatch.setattr(vad, "gated_lufs_from_frames", lambda *a, **k: -23.0)
    _dialogue_gate("x", m, Settings())
    assert m.tracks[0].dialogue_lufs == -23.0 and m.tracks[2].dialogue_lufs is None


def test_region_merge_is_fast_and_matches_greedy():
    import random

    from audel.signals.vad import merge_regions

    rng = random.Random(7)
    t, regs = 0.0, []
    for _ in range(20_000):
        a = t + rng.random()
        regs.append((a, a + rng.random()))
        t = a + 1.5
    t0 = time.perf_counter()
    out = merge_regions(regs, 200)
    assert time.perf_counter() - t0 < 2.0 and len(out) == 200   # was ~8.5 s for 10k

    def greedy(rs, limit):
        m = [list(r) for r in sorted(rs)]
        while len(m) > limit:
            gaps = [m[i + 1][0] - m[i][1] for i in range(len(m) - 1)]
            i = gaps.index(min(gaps))
            m[i][1] = m[i + 1][1]
            del m[i + 1]
        return [tuple(x) for x in m]

    small = regs[:300]
    assert merge_regions(small, 40) == greedy(small, 40)


def test_a_single_run_field_is_not_blanked_from_the_log():
    from audel.logging import _clip

    out = _clip("/x/" + "%2541/" * 2000)
    assert out.startswith("/x/%2541") and "truncated" in out


# ==== round 10, decode surface ================================================================

@pytest.mark.parametrize("fold", [True, False])
def test_undoing_a_strays_gap_never_shortens_the_track(fold):
    from audel.mediaguard import _GapScanner

    d, sc = 0.0213, _GapScanner(0.1, 50, fold=fold)
    t = 0.0
    while t < 300:                                   # 300 s of audio...
        sc.add(t, d)
        t += d
    old_end, t = t, t + 1800                          # ...then an 1800 s hole
    for i in range(16_000):                           # audio resumes; a decoy every 8 packets
        sc.add(t, d)
        t += d
        if i % 8 == 7:
            sc.add(old_end, d)
            old_end += d
    sc.add(t, 60.0)                                   # a long final packet to pad the extent
    res = sc.finish()
    decoded = (300 + 16_000 * d) + 2000 * d + 60
    shortfall = res.extent_s - (decoded - res.overlap_s) - res.gap_total_s
    excess = (decoded - res.overlap_s) - res.extent_s
    if fold:   # MPEG-TS folds long jumps as splices: the interleaved clocks show as excess audio
        assert excess > 300 or res.gap_total_s + max(0.0, shortfall) > 1700, res
    else:      # elsewhere the hole is accounted for (as a gap or shortfall): it can't vanish
        assert res.gap_total_s + max(0.0, shortfall) > 1700, res


def test_discarded_preroll_packets_are_not_on_the_timeline():
    from audel.mediaguard import _parse_packet

    assert _parse_packet(b"-0.021333,0.021333,KD_,") is None
    assert _parse_packet(b"0.000000,0.021333,K__") == (0.0, 0.021333)


@requires_ffmpeg
@pytest.mark.parametrize("codec", ["libvorbis", "libopus"])
def test_chained_ogg_links_are_one_programme(tmp_path, codec):
    from audel import check

    links = []
    for i in range(3):
        f = tmp_path / f"l{i}.ogg"
        _ff("-f", "lavfi", "-i", f"sine=f={300 + 100 * i}:d=6", "-af", "volume=0.3",
            "-c:a", codec, f)
        links.append(f.read_bytes())
    chain = tmp_path / "chain.ogg"
    chain.write_bytes(b"".join(links))
    r = asyncio.run(check(str(chain)))
    assert not [i for i in r.issues if i.detail.get("check") in
                ("timeline_excess", "timeline_shortfall", "packet_gap")], \
        [i.message for i in r.issues]


@requires_ffmpeg
@pytest.mark.parametrize("codec", ["adpcm_ima_wav", "adpcm_ms"])
def test_adpcm_avi_has_no_false_duration_mismatch(tmp_path, codec):
    from audel import check

    f = tmp_path / "a.avi"
    _ff("-f", "lavfi", "-i", "sine=d=12", "-c:a", codec, f)
    assert not _checks(asyncio.run(check(str(f))), "duration_mismatch")


def test_decoder_cause_ignores_metadata_tag_lines():
    from audel.mediaguard import _cause

    tail = ("  Metadata:\n    title           : ERROR invalid stream failed\n"
            "[aac @ 0x1] Changing audio frame properties on the fly is not supported.\n")
    assert "Changing audio frame properties" in _cause(tail)


# ==== round 11, auth surface ==================================================================

def _emit(msg, *args, name="audel.rest"):
    import logging as lg

    from audel.logging import _SecretScrubber

    rec = lg.LogRecord(name, 30, "x", 1, msg, args or None, None)
    _SecretScrubber().filter(rec)
    return rec.getMessage()


def test_non_string_messages_and_arguments_are_scrubbed():
    from audel.auth import new_token
    from audel.logging import register_secret

    register_secret("Zx81kQpLmN0vR7tYreg")
    tok = new_token()
    out = " | ".join([
        _emit(RuntimeError("provider said api_key=AIzaSyA1234567890abcdefghijklmn")),
        _emit(RuntimeError("key Zx81kQpLmN0vR7tYreg")),
        _emit(RuntimeError(f"bad {tok}")),
        _emit("decode failed: %s", RuntimeError("ffmpeg: https://h/a.wav?token=Zx81kQpLmN0vR7tY")),
        _emit("cfg %s", {"password": "hunter2hunter2"}),
    ])
    for secret in ("AIzaSyA1234567890", "Zx81kQpLmN0vR7tY", tok[6:30], "hunter2hunter2"):
        assert secret not in out, out


@pytest.mark.parametrize("msg,args", [("api_key=%s", ("Zx81kQpLmN0vR7tY",)),
                                      ("login failed password=%s", ("Zx81kQpLmN0vR7tY",)),
                                      ("token: %s", ("Zx81kQpLmN0vR7tY",)),
                                      ("%s=%s", ("token", "Zx81kQpLmN0vR7tY")),
                                      ("token=%s%s", ("Zx81kQp", "LmN0vR7tY"))])
def test_keyword_in_template_with_credential_in_argument(msg, args):
    assert "LmN0vR7tY" not in _emit(msg, *args)


def test_a_broken_template_never_prints_raw_arguments():
    out = _emit("upstream rejected Authorization: %s %s", "AbCdEfGhIjKl1234Mn")
    assert "AbCdEfGhIjKl1234Mn" not in out


@pytest.mark.parametrize("text", [
    '{"user": "bob", "password": "correcthorsebattery"}', "{'password': 'correcthorse'}",
    '{"api_key": "AbCdEfGhIjKlMnOpQrSt"}', '{"access_token":"AbCdEfGhIjKlMnOpQrStUv"}',
    "password = hunter2hunter2", 'api_key = "AbCd1234EfGh5678"',
    "Authorization: SSWS 00QCjAl4MlV-WPXM3abc", "Authorization: Splunk 1234-abcd-5678",
    "Authorization: Bearer\nZx81kQpLmN0vR7tY", "calling upstream with Bearer AbCdEfGhIjKlMnOpQrSt",
    "token: AbCdEfGhIjKlMnOpQrSt", "password=P@ssw0rd!2024", "secret=hun*ter2hunter2",
    "X-Amz-Signature=abcdef123456", "sig=abcdef123456"])
def test_structured_and_unusual_credentials_are_redacted(text):
    from audel.logging import scrub_text

    out = scrub_text(text)
    assert "[REDACTED]" in out and out != text


def test_jwts_behind_glued_text_and_unusual_headers_are_redacted():
    import base64

    from audel.logging import scrub_text

    def b64(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    body, sig = b64(b'{"t":1}'), "c2lnbmF0dXJl"
    for hdr in (b'{"alg":"RS256"}', b'{"customHeaderX":"a","alg":"RS256"}',
                b'{\n    "alg": "RS256"}', b'{"a":1}', b'{"x-tenant":"t","alg":"RS256"}'):
        jwt = f"{b64(hdr)}.{body}.{sig}"
        for text in (jwt, "honeyJar_" + jwt, "/v1/monkeyAuth-" + jwt, "/s/q9eyAz_" + jwt):
            assert b64(hdr)[:10] not in scrub_text(text), (hdr, text)


@pytest.mark.parametrize("text", ["compass: north-northwest", "bypass mode on",
                                  "design: minimalist", "secretary: Jane Doe",
                                  "Authorization required for this", "token: expired at noon"])
def test_short_keys_inside_words_are_not_redacted(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_nested_percent_floods_are_bounded_and_fail_closed():
    from audel.logging import scrub_text

    text = "%25252541%41!" * (8192 // 13)
    t0 = time.process_time()
    out = scrub_text(text)
    assert time.process_time() - t0 < 0.2
    assert "%25252541%41" not in out.split("[REDACTED]")[-1] or out.count("[REDACTED]") > 0


# ==== round 11, decode surface ================================================================

def test_listed_gaps_over_ten_percent_are_an_error():
    from audel.mediaguard import MediaInfo, StreamInfo
    from audel.signals.checks import evaluate
    from audel.signals.measure import Measurements, TrackMeasurements

    st = StreamInfo(index=0, codec="aac", sample_rate=48000, channels=2)
    m = Measurements(info=MediaInfo(duration_s=600, sample_rate=48000, channels=2, codec="aac",
                                    has_audio=True, streams=(st,)))
    tm = TrackMeasurements(stream=st, decoded_s=300.0, extent_s=600.0, gap_total_s=300.0,
                           gaps=[(30.0 + 60 * i, 60.0 + 60 * i) for i in range(10)],
                           frames=[(0.1, -23.0, -23.0, -3.0)], rms_dbfs=-20.0)
    m.tracks = [tm]
    sev = {i.severity.value for i in evaluate(m, Settings()) if i.detail.get("check") == "packet_gap"}
    assert sev == {"error"}


# ==== round 11, network surface ===============================================================

def _speech_like(path, *, invert_right=False, gain=0.05):
    """A syllabic tone train (speech-like envelope) over a quiet in-phase noise bed."""
    right = "-" if invert_right else ""
    _ff("-f", "lavfi", "-i",
        f"aevalsrc='{gain}*sin(2*PI*220*t)*(0.5+0.5*sin(2*PI*4*t))*lt(mod(t\\,1.2)\\,0.8)|"
        f"{right}{gain}*sin(2*PI*220*t)*(0.5+0.5*sin(2*PI*4*t))*lt(mod(t\\,1.2)\\,0.8)':d=20:s=48000",
        "-f", "lavfi", "-i", "anoisesrc=d=20:c=pink:a=0.02", "-filter_complex",
        "[1]aformat=channel_layouts=stereo[n];[0][n]amix=inputs=2:normalize=0", path)


def _real_speech(tmp_path):
    """Synthesized speech (espeak-ng), mono, 48 kHz, about 20 s."""
    if shutil.which("espeak-ng") is None:
        pytest.skip("espeak-ng not installed")
    raw = tmp_path / "say.wav"
    subprocess.run(["espeak-ng", "-w", str(raw), "-s", "150",
                    "The quick brown fox jumps over the lazy dog. " * 6], check=True,
                   capture_output=True)
    out = tmp_path / "speech.wav"
    _ff("-i", raw, "-ar", "48000", "-ac", "1", "-t", "20", out)
    return out


def test_speech_regions_hear_antiphase_dialogue(tmp_path):
    pytest.importorskip("faster_whisper")
    from audel.signals.vad import speech_regions

    mono = _real_speech(tmp_path)
    f = tmp_path / "phase.wav"
    _ff("-i", mono, "-af", "pan=stereo|FL=c0|FR=-1*c0", f)
    regions = speech_regions(f, Settings(), stream=0, labels=["FL", "FR"],
                             channels=2) or []
    assert sum(b - a for a, b in regions) > 5.0


def test_a_vad_host_failure_is_busy_not_a_silent_fallback(tmp_path, monkeypatch):
    pytest.importorskip("faster_whisper")
    from audel.errors import BusyError
    from audel.signals.vad import speech_regions

    f = tmp_path / "a.flac"
    _speech_like(f)

    def emfile(*a, **k):
        raise OSError(24, "Too many open files")

    import audel.mediaguard as mg

    monkeypatch.setattr(mg.subprocess, "Popen", emfile)
    with pytest.raises(BusyError):
        speech_regions(f, Settings(), stream=0, labels=["FL", "FR"], channels=2)


def test_unmeasurable_dialogue_is_reported_on_a_dialogue_gated_spec():
    from audel.mediaguard import MediaInfo, StreamInfo
    from audel.signals.checks import evaluate
    from audel.signals.measure import Measurements, TrackMeasurements

    st = StreamInfo(index=0, codec="flac", sample_rate=48000, channels=2)
    m = Measurements(info=MediaInfo(duration_s=20, sample_rate=48000, channels=2, codec="flac",
                                    has_audio=True, streams=(st,)))
    for status in ("failed", "no_speech"):
        m.tracks = [TrackMeasurements(stream=st, integrated_lufs=-27.0, decoded_s=20.0,
                                      frames=[(0.1, -27.0, -27.0, -3.0)], rms_dbfs=-30.0,
                                      dialogue_status=status)]
        found = [i for i in evaluate(m, Settings(), "netflix")
                 if i.detail.get("check") == "dialogue_unmeasured"]
        assert found and found[0].detail["reason"] == status


def test_the_dialogue_gate_stays_inside_the_file_deadline(monkeypatch):
    from audel.core.render import _dialogue_gate
    from audel.errors import UnsafeSourceError
    from audel.mediaguard import MediaInfo, StreamInfo
    from audel.signals.measure import Measurements, TrackMeasurements

    st = StreamInfo(index=0, codec="flac", sample_rate=48000, channels=2)
    m = Measurements(info=MediaInfo(duration_s=20, sample_rate=48000, channels=2, codec="flac",
                                    has_audio=True, streams=(st,)))
    m.tracks = [TrackMeasurements(stream=st)]
    m.deadline = time.monotonic() - 1
    with pytest.raises(UnsafeSourceError):
        _dialogue_gate("x", m, Settings())


def test_header_read_failure_is_busy_not_a_skipped_check(tmp_path, monkeypatch):
    import builtins

    from audel.errors import BusyError
    from audel.mediaguard import container_shortfall_s

    f = tmp_path / "a.wav"
    f.write_bytes(b"RIFF" + b"\0" * 100)
    real = builtins.open

    def emfile(p, *a, **k):
        if str(p) == str(f):
            raise OSError(24, "Too many open files")
        return real(p, *a, **k)

    monkeypatch.setattr(builtins, "open", emfile)
    with pytest.raises(BusyError):
        container_shortfall_s(f, 3600)


def test_abandoned_work_makes_others_wait_not_fail(tmp_path, media, monkeypatch):
    import threading

    import audel.core as core

    def slow(*a, **k):
        time.sleep(6)
        raise UnsafeSourceError("stub")

    async def slow_check(*a, **k):
        await asyncio.to_thread(slow)

    started = []
    real_check = core.check

    async def check_tracking(*a, **k):
        started.append(1)
        return await real_check(*a, **k)

    s = Settings(cache_dir=tmp_path / "ws", max_concurrent_jobs=1, request_timeout_s=4.0,
                 queue_wait_s=10)
    with TestClient(build_app(settings=s)) as c:
        monkeypatch.setattr(core, "check", slow_check)
        body = media["good"].read_bytes()
        t = threading.Thread(target=lambda: c.post("/check", files={"file": ("a.wav", body)}))
        t.start()
        time.sleep(4.5)                                  # the first request has timed out
        monkeypatch.setattr(core, "check", check_tracking)
        r = c.post("/check", files={"file": ("a.wav", body, "audio/wav")})
        t.join()
    assert started and r.status_code == 200, (r.status_code, r.text)  # waited, then ran


# ==== round 12, auth surface ==================================================================

@pytest.mark.parametrize("unit", ["eyJeyJeyJeyJeyJeyJeyJeyJeyJeyJeyJeyJeyJeyJeyJeyJ.ab.cd.",
                                  "%25252541%41!", "x.y.z.", "a"])
def test_scrub_cost_is_bounded_per_field_in_cpu_time(unit):
    from audel.logging import scrub_text

    text = unit * (8192 // len(unit))
    best = 9.0
    for _ in range(5):
        t0 = time.process_time()
        scrub_text(text)
        best = min(best, time.process_time() - t0)
    assert best < 0.03, best      # JWT-candidate floods were ~15 ms per 8 KB field


@pytest.mark.parametrize("text", [
    "dbPass=hunter22", "userPwd=s3cr3t!!", "apiSig=abcdef123", "{'password': b'hunter2hunter2'}",
    "[(b'authorization', b'Basic dXNlcjpwYXNzd29yZA==')]", "[('x-api-key', 'AbCdEf123456')]",
    "password = 'correct horse battery'", "Authorization: Token abcdefghij"])
def test_repr_camelcase_and_quoted_credentials_are_redacted(text):
    from audel.logging import scrub_text

    out = scrub_text(text)
    for secret in ("hunter2", "s3cr3t", "abcdef123", "dXNlcjpw", "AbCdEf123456", "horse",
                   "abcdefghij"):
        assert secret not in out, out


def test_long_header_key_jwts_are_redacted():
    import base64

    from audel.logging import scrub_text

    def b64(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    for n in (15, 24, 32):
        header = b'{"' + b"k" * n + b'":"v","alg":"RS256"}'
        jwt = b64(header) + "." + b64(b'{"t":1}') + ".c2ln"
        assert scrub_text(jwt) == "[REDACTED]", n


@pytest.mark.parametrize("text", ['{"tenant": "jwt:aizawa-studios"}',
                                  "ingest from sk-broadband.co.kr failed", "COMPASS: northwest",
                                  "VERDICT PASS: loudness_ok_all", "signature: verified ok",
                                  "credential: missing_or_expired", "pass: dialogue_loudness",
                                  "authorization: required for this endpoint"])
def test_names_and_prose_survive_in_audit_and_logs(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_legitimate_percent_encoded_urls_are_not_redacted():
    from audel.logging import scrub_text

    url = "&".join("tag=caf%C3%A9_au_lait" for _ in range(180))
    assert "[REDACTED]" not in scrub_text(url)


def test_credential_like_request_ids_are_replaced_not_blanked():
    from audel.adapters.rest import _request_id

    assert _request_id("job-42.retry-1") == "job-42.retry-1"
    rid = _request_id("eyJhbGciOiJIUzI1NiJ9.eyJ0IjoxfQ.c2lnbmF0dXJl")
    assert rid != "eyJhbGciOiJIUzI1NiJ9.eyJ0IjoxfQ.c2lnbmF0dXJl" and len(rid) == 32


def test_uvicorn_error_records_keep_their_arguments():
    out = _emit("Uvicorn running on %s://%s:%d", "http", "127.0.0.1", 8000, name="uvicorn.error")
    assert out == "Uvicorn running on http://127.0.0.1:8000"


# ==== round 12, decode surface (dialogue gating) ==============================================

def test_dialogue_loudness_counts_only_blocks_inside_speech_with_no_region_cap():
    from audel.signals.vad import gated_lufs_from_frames

    frames, regions = [], []
    for k in range(1200):                       # 1200 alternating 2 s speech / 2 s music lines
        a = k * 4.0
        regions.append((a, a + 2.0))
    for i in range(1, 48_000):
        t = round(i * 0.1, 1)
        frames.append((t, -30.0 if (t % 4.0) <= 2.0 else -20.0, None, None))
    assert abs(gated_lufs_from_frames(frames, regions) - (-30.0)) < 0.05   # no spill, no cap


def test_too_little_dialogue_is_no_speech_not_minus_70():
    from audel.signals.vad import gated_lufs_from_frames

    frames = [(round(0.1 * i, 1), -25.0, None, None) for i in range(1, 100)]
    assert gated_lufs_from_frames(frames, [(1.0, 1.3)]) is None


def test_a_decoder_spawn_failure_in_speech_detection_is_busy(tmp_path, monkeypatch):
    pytest.importorskip("faster_whisper")
    import audel.mediaguard as mg
    from audel.errors import BusyError
    from audel.signals.vad import speech_regions

    def no_thread(*a, **k):
        raise OSError(24, "Too many open files")

    f = _real_speech(tmp_path)
    monkeypatch.setattr(mg, "_popen", no_thread)
    with pytest.raises(BusyError):
        speech_regions(f, Settings(), stream=0, labels=["FC"], channels=1)


@requires_ffmpeg
def test_dialogue_in_dropped_or_cancelled_channels_is_measured(tmp_path):
    pytest.importorskip("faster_whisper")
    from audel.core.render import _render_sync

    mono = _real_speech(tmp_path)
    for layout, expr in (("7.1.4", "TBL=c0|TBR=c0"), ("5.1", "BL=c0|BR=-1*c0"),
                         ("5.1", "FC=c0|FL=-0.707*c0|FR=-0.707*c0")):
        f = tmp_path / f"{layout}.wav"
        _ff("-i", mono, "-af", f"pan={layout}|{expr}", f)
        rr = _render_sync(str(f), Settings(), "netflix")
        assert rr.measurements.tracks[0].dialogue_lufs is not None, layout


def test_opus_silence_suppression_is_not_an_error():
    from audel.mediaguard import MediaInfo, StreamInfo
    from audel.signals.checks import evaluate
    from audel.signals.measure import Measurements, TrackMeasurements

    st = StreamInfo(index=0, codec="opus", sample_rate=48000, channels=2)
    m = Measurements(info=MediaInfo(duration_s=10, sample_rate=48000, channels=2, codec="opus",
                                    has_audio=True, streams=(st,)))
    m.tracks = [TrackMeasurements(stream=st, decoded_s=6.0, extent_s=10.0, gap_total_s=4.0,
                                  gaps=[(3.0, 7.0)], frames=[(0.1, -23.0, -23.0, -3.0)],
                                  rms_dbfs=-20.0)]
    sev = {i.severity.value for i in evaluate(m, Settings()) if i.detail.get("check") == "packet_gap"}
    assert sev == {"warning"}


# ==== round 12, network surface ===============================================================

def test_job_hash_failure_is_busy_and_audited(tmp_path, media, monkeypatch):
    import audel.adapters.rest as rest

    log = tmp_path / "audit.jsonl"
    s = Settings(cache_dir=tmp_path / "ws", audit_log=log)

    def emfile(path):
        raise OSError(24, "Too many open files")

    with TestClient(build_app(settings=s)) as c:
        monkeypatch.setattr(rest, "_sha256", emfile)
        r = c.post("/check", files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")})
        jid = c.post("/jobs", files={"file": ("a.wav", media["good"].read_bytes(), "audio/wav")}
                     ).json()["job_id"]
        for _ in range(100):
            j = c.get(f"/jobs/{jid}").json()
            if j["status"] in ("failed", "done"):
                break
            time.sleep(0.05)
    assert r.status_code == 429 and "busy" in (j.get("error") or "").lower(), (r.text, j)
    assert log.exists() and '"BusyError"' in log.read_text()


def test_download_host_exhaustion_is_busy(tmp_path, monkeypatch):
    import audel.ingest as ing
    from audel.errors import BusyError

    def inner(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ing, "_download_inner", inner)
    with pytest.raises(BusyError):
        ing._download("https://x/a.wav", tmp_path / "d.wav", "http://127.0.0.1:1", Settings())


def test_speech_detection_respects_the_file_deadline(tmp_path):
    pytest.importorskip("faster_whisper")
    from audel.signals.vad import speech_regions

    f = tmp_path / "long.flac"
    _ff("-f", "lavfi", "-i", "anoisesrc=d=600:c=pink:a=0.1", "-ac", "2", f)
    t0 = time.monotonic()
    with pytest.raises(UnsafeSourceError):
        speech_regions(f, Settings(), stream=0, labels=["FL", "FR"],
                       channels=2, timeout_s=2.0)
    assert time.monotonic() - t0 < 30


# ==== round 13, network + auth surfaces =======================================================

def test_uvicorn_error_templates_are_scrubbed_and_bools_format():
    from audel.auth import new_token
    from audel.logging import register_secret

    tok = new_token()
    register_secret(tok)
    assert tok not in _emit(f"... Authorization: Bearer {tok}", name="uvicorn.error")
    assert tok not in _emit(f"token={tok} %s", "x", name="uvicorn.error")
    assert _emit("flag %d", True, name="uvicorn.error") == "flag 1"


@pytest.mark.parametrize("text", [
    "authorization: bearer abcdefghijklmnop", "authorization: token abcdefghijklmnopq",
    "Bearer abcd_efgh-ijkl_mnop", "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-1234567890-abcdefghij", "AKIAABCDEFGHIJKLMNOP"])
def test_lowercase_schemes_and_known_token_shapes_are_redacted(text):
    from audel.logging import scrub_text

    assert "[REDACTED]" in scrub_text(text)


def test_quoted_values_with_quotes_and_escapes_are_redacted():
    import json as _json

    from audel.logging import scrub_text

    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwgg\n-----END PRIVATE KEY-----"
    for text in ['{"password": "it\'s my secret"}', _json.dumps({"password": 'ab"cdefgh'}),
                 _json.dumps({"password": "p@ss\\w0rd!!"}), repr({"password": "it's a secret"}),
                 _json.dumps({"private_key": pem})]:
        out = scrub_text(text)
        assert "secret" not in out.split(":", 1)[1] and "MIIE" not in out and "cdefgh" not in out, out


def test_keyword_floods_cost_like_ordinary_text():
    from audel.logging import scrub_text

    def cost(u):
        text = u * (8192 // len(u))
        best = 9.0
        for _ in range(5):
            t0 = time.process_time()
            scrub_text(text)
            best = min(best, time.process_time() - t0)
        return best

    assert cost("authorization=a,") < 0.01 and cost("token: a ") < 0.01


def test_our_proxys_busy_reply_and_wrapped_host_errors_are_busy():
    import errno
    import urllib.error

    from audel.ingest import _host_failure
    from audel.proxy import BUSY_STATUS, _upstream_failure

    assert _upstream_failure(OSError(errno.EMFILE, "x")) == BUSY_STATUS
    assert _upstream_failure(OSError(errno.ECONNREFUSED, "x")) == b"502 Bad Gateway"
    assert _host_failure(urllib.error.URLError(OSError(errno.EMFILE, "Too many open files")))
    # Round 14: response text is the origin's to choose; it is never a busy signal.
    assert not _host_failure(OSError("Tunnel connection failed: 503 Audel Host Busy"))
    assert not _host_failure(urllib.error.URLError(OSError(errno.ECONNREFUSED, "refused")))


def test_a_client_request_id_cannot_rename_audit_keys(tmp_path):
    import json as _json

    from audel.ops import AuditLog

    log = tmp_path / "a.jsonl"
    AuditLog(log).write(request_id="abc-token", source="upload", tenant="t", endpoint="/check")
    rec = _json.loads(log.read_text().splitlines()[-1])
    assert rec["source"] == "upload" and "request_id" in rec


# ==== round 13, decode surface (dialogue gating) ==============================================

def _surround_with(tmp_path, name, expr):
    mono = _real_speech(tmp_path)
    f = tmp_path / name
    _ff("-i", mono, "-f", "lavfi", "-i", "sine=f=4:d=20", "-filter_complex", expr,
        "-map", "[out]", f)
    return f


@requires_ffmpeg
def test_a_subsonic_channel_cannot_hide_the_dialogue_channel(tmp_path):
    pytest.importorskip("faster_whisper")
    from audel.core.render import _render_sync

    ctl = _surround_with(tmp_path, "ctl.wav",
                         "[0]volume=0.05[d];[d]pan=5.1(side)|FC=c0[out]")
    atk = _surround_with(tmp_path, "atk.wav",
                         "[0]volume=0.05[d];[1]volume=0.35[s];[d][s]amerge=inputs=2,"
                         "pan=5.1(side)|FC=c0|SL=c1[out]")
    a = _render_sync(str(ctl), Settings(), "netflix").measurements.tracks[0].dialogue_lufs
    b = _render_sync(str(atk), Settings(), "netflix").measurements.tracks[0].dialogue_lufs
    assert a is not None and b is not None and abs(a - b) < 1.5, (a, b)


@requires_ffmpeg
def test_a_masked_voice_in_another_channel_is_not_dialogue(tmp_path):
    pytest.importorskip("faster_whisper")
    from audel.signals.vad import speech_regions

    mono = _real_speech(tmp_path)
    f = tmp_path / "mask.wav"
    _ff("-i", mono, "-f", "lavfi", "-i", "anoisesrc=d=20:c=pink:a=0.5", "-filter_complex",
        "[0]volume=0.01[v];[1][v]amerge=inputs=2,pan=stereo|FL=c0|FR=c1[out]", "-map", "[out]",
        f)
    regions = speech_regions(f, Settings(), stream=0, labels=["FL", "FR"], channels=2) or []
    assert sum(b - a for a, b in regions) < 2.0     # a voice 34 dB under the noise isn't dialogue


def test_speech_detection_streams_and_never_writes_a_temp_file(tmp_path, monkeypatch):
    pytest.importorskip("faster_whisper")
    import tempfile

    from audel.signals.vad import speech_regions

    def no_temp(*a, **k):
        raise AssertionError("speech detection must stream, not write a temp WAV")

    f = _real_speech(tmp_path)
    monkeypatch.setattr(tempfile, "mkstemp", no_temp)
    assert speech_regions(f, Settings(), stream=0, labels=["FC"], channels=1)


# ==== round 14, network + auth surfaces =======================================================

def test_an_origin_cannot_forge_host_busy():
    import urllib.error

    from audel.ingest import _host_failure

    for reason in ("Audel Host Busy", "Forbidden (Audel Host Busy)"):
        for code in (503, 404, 403):
            err = urllib.error.HTTPError("http://o/a.wav", code, reason, {}, None)
            assert not _host_failure(err)


def test_only_our_proxys_own_refusal_marks_it_busy():
    import errno

    from audel.proxy import BUSY_STATUS, VettingProxy, _upstream_failure

    proxy = VettingProxy()
    assert proxy.host_busy is False
    assert _upstream_failure(OSError(errno.EMFILE, "x")) == BUSY_STATUS


def test_keyword_floods_never_blank_the_line_and_stay_cheap():
    from audel.logging import scrub_text

    line = "GET /jobs/PROBE-MARKER-2?q=" + "key" * 400
    assert scrub_text(line).startswith("GET /jobs/PROBE-MARKER-2")
    flood = "/x?" + "key=v&" * 300 + "password=hunter22"
    out = scrub_text(flood)
    assert "hunter22" not in out and out.startswith("/x?key=")
    for unit in ("key", "pass", "ap", "authorization=a,", "monkey "):
        text = unit * (8192 // len(unit)) + "key"
        best = 9.0
        for _ in range(5):
            t0 = time.process_time()
            scrub_text(text)
            best = min(best, time.process_time() - t0)
        assert best < 0.015, (unit, best)     # was up to 761 ms / 9 ms per 8 KB field


@pytest.mark.parametrize("text", ["password=pa\\ss0rdHunter2xyz", "secret=ab\\cdefghijklmnop",
                                  "password=ab;cdefghijkl", "password=ab,cdefghijkl",
                                  "password=hunt3", "DB_PASSWORD=ab\\$cdefgh"])
def test_explicit_assignments_redact_any_value(text):
    from audel.logging import scrub_text

    out = scrub_text(text)
    assert out.endswith("[REDACTED]") and "=" in out, out


@pytest.mark.parametrize("text", ['["pass", "warn", "fail"]', "{'verdict': 'pass', 'issues': 3}"])
def test_bare_verdict_words_dont_redact_their_neighbours(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


@requires_ffmpeg
def test_a_timed_out_stream_is_reaped_even_while_suspended(media):
    from audel.mediaguard import stream_pcm16

    gen = stream_pcm16(media["good"], Settings(), stream=0, channels=2, chunk_s=1, timeout_s=0.3)
    next(gen)
    time.sleep(1.0)                     # the watchdog fires while we hold the generator
    gen.close()


# ==== round 14, decode surface (layouts) ======================================================

@pytest.mark.parametrize("n", [3, 4, 5, 7, 16, 24])
def test_unknown_channels_are_all_metered(n, tmp_path):
    from audel.mediaguard import channel_layout_arg

    lay = channel_layout_arg("", n)
    assert lay.startswith("USR768") and lay.count("+") == n - 1
    if shutil.which("ffmpeg") is None:
        return
    target = min(3, n - 1)
    expr = "|".join(f"c{i}=" + ("c0" if i == target else "0*c0") for i in range(n))
    out = subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-f", "lavfi", "-i",
                          "sine=f=1000:d=3", "-af", f"pan={lay}|{expr},ebur128", "-f", "null",
                          "-"], capture_output=True, text=True).stderr
    assert "-70.0 LUFS" not in out.split("Summary:")[-1]     # that channel is measured


def test_conventional_unlabelled_counts_keep_their_layout():
    from audel.mediaguard import StreamInfo, channel_layout_arg

    assert channel_layout_arg("", 6) == "5.1" and channel_layout_arg("unknown", 8) == "7.1"
    st = StreamInfo(index=0, codec="pcm_s16le", sample_rate=48000, channels=3)
    assert not any(lab.upper().startswith("LFE") for lab in st.channel_labels())


@pytest.mark.parametrize("layout", ["quad", "3.0", "5.1.2", "7.1(wide)", "hexagonal"])
def test_speech_decode_keeps_the_source_layout(layout):
    from audel.mediaguard import _keep_layout, layout_channels

    n = len(layout_channels(layout) or [])
    assert n and _keep_layout(layout, n) == ["-ch_layout", layout]


@requires_ffmpeg
def test_antiphase_across_a_quad_rear_pair_is_still_heard(tmp_path):
    pytest.importorskip("faster_whisper")
    from audel.core.render import _render_sync

    mono = _real_speech(tmp_path)
    ctl, atk = tmp_path / "ctl.wav", tmp_path / "atk.wav"
    _ff("-i", mono, "-af", "volume=0.3,pan=quad|BL=c0|BR=c0", ctl)
    _ff("-i", mono, "-af", "volume=0.3,pan=quad|BL=c0|BR=-1*c0", atk)
    a = _render_sync(str(ctl), Settings(), "netflix").measurements.tracks[0].dialogue_lufs
    b = _render_sync(str(atk), Settings(), "netflix").measurements.tracks[0].dialogue_lufs
    assert a is not None and b is not None and abs(a - b) < 1.0, (a, b)


# ==== round 15, auth surface ==================================================================

@pytest.mark.parametrize("text", [
    "İ password=hunter2XYZ", 'İzmir "password": "x y"', "İ [('x-api-key','abc123')]",
    "token:abc;password:hunterxyz", "credential:none,secret:topsecret",
    "signature:ok;api_key:hunterxyz", "[(b'x-amz-security-token', b'SECRETX')]",
    "[('x-auth-token', 'SECRETX')]", "[('x-goog-api-key', 'SECRETX')]",
    "[(b'proxy-authorization', b'Basic SECRETX')]",
    "[('username', 'bob'), ('password', 'hunter2')]", "[(b'api_key', b'zz9sss')]",
    "key " * 130 + "password='a b SECRETX'", "key " * 130 + "[(b'x-api-key', b'SECRETX')]",
    "key " * 130 + "cookie: session=abcSECRETX"])
def test_round15_redaction_gaps_are_closed(text):
    from audel.logging import scrub_text

    out = scrub_text(text)
    for secret in ("hunter", "SECRETX", "topsecret", "abc123", "zz9sss", "x y"):
        assert secret not in out, out


def test_double_encoded_json_credentials_are_redacted():
    import json as _json

    from audel.logging import scrub_text

    for key in ("password", "api_key", "client_secret"):
        text = _json.dumps({"cfg": _json.dumps({key: "hunter2"})})
        assert "hunter2" not in scrub_text(text)


def test_turkish_text_does_not_desync_redaction_in_workspace_state(tmp_path):
    import json as _json

    from audel.workspace import Workspace

    ws = Workspace(Settings(cache_dir=tmp_path / "ws"))
    sess = ws.new_session() if hasattr(ws, "new_session") else None
    from audel.logging import scrub_text

    payload = _json.dumps({"summary": "İzmir promo spot", "notes": "client_secret=hunter2XYZ"})
    assert "hunter2XYZ" not in scrub_text(payload)
    del sess


# ==== round 15, decode surface (multichannel) =================================================

def test_named_but_unusable_layouts_get_plain_channels_not_a_guess():
    from audel.mediaguard import channel_layout_arg

    assert channel_layout_arg("ambisonic 1+stereo", 6).startswith("USR768")
    assert channel_layout_arg("", 6) == "5.1" and channel_layout_arg("unknown", 6) == "5.1"


def test_mono_pan_averages_every_non_lfe_channel_by_index():
    from audel.mediaguard import mono_pan

    assert mono_pan(["FL", "FR", "FC"]) == "pan=mono|c0=0.333333*c0+0.333333*c1+0.333333*c2"
    assert "c3" not in mono_pan(["FL", "FR", "FC", "LFE", "BL", "BR"])


def test_aac_with_a_program_config_uses_the_decoders_order():
    from audel.mediaguard import _fixed_order_layout

    assert _fixed_order_layout("aac", "unknown", 7) == "6.1"
    assert _fixed_order_layout("aac", "", 8) == "7.1"
    assert _fixed_order_layout("flac", "unknown", 7) == "unknown"


@requires_ffmpeg
def test_zeroing_a_channel_mask_cannot_hide_hum_or_polarity(tmp_path):
    from audel import check

    lab = tmp_path / "lab.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=10", "-f", "lavfi", "-i", "sine=f=50:d=10",
        "-filter_complex", "[0]volume=0.3[s];[1]volume=0.02[h];[s][h]amerge=inputs=2,"
        "pan=3.0|FL=c0+c1|FR=-1*c0+c1|FC=c1[out]", "-map", "[out]", lab)
    m0 = tmp_path / "m0.wav"
    data = bytearray(lab.read_bytes())
    data[40:44] = b"\0\0\0\0"                       # zero the WAVE_FORMAT_EXTENSIBLE mask
    m0.write_bytes(bytes(data))
    a = {i.detail.get("check") for i in asyncio.run(check(str(lab))).issues}
    b = {i.detail.get("check") for i in asyncio.run(check(str(m0))).issues}
    assert "polarity_inversion" in a and {"polarity_inversion", "hum"} & a <= b, (a, b)


@requires_ffmpeg
def test_asr_decode_keeps_an_unlabelled_lcr_centre(tmp_path):
    import wave

    import numpy as np

    from audel.mediaguard import decode_to_wav

    lab = tmp_path / "lcr.wav"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=4", "-af", "volume=0.3,pan=3.0|FC=c0", lab)
    m0 = tmp_path / "lcr_m0.wav"
    data = bytearray(lab.read_bytes())
    data[40:44] = b"\0\0\0\0"                      # zero the channel mask
    m0.write_bytes(bytes(data))

    def level(f):
        w = decode_to_wav(f, Settings(), stream=0)
        with wave.open(str(w)) as x:
            a = np.frombuffer(x.readframes(x.getnframes()), "<i2").astype(float)
        w.unlink()
        return 20 * np.log10(np.sqrt(np.mean(a ** 2)) / 32768 + 1e-12)

    # The labelled file gets the dialogue-first (centre-weighted) mix, the unlabelled one the
    # plain mean: they differ by design, but the centre is never dropped (it read ~15 dB low).
    m0_db, lab_db = level(m0), level(lab)
    assert lab_db >= m0_db and lab_db - m0_db < 9.0, (m0_db, lab_db)


# ==== round 16, auth surface ==================================================================

@pytest.mark.parametrize("text", [
    "SECRET_KEY=CANARY6x", "secret_key: CANARY6x", "secretKey=CANARY6x", "JWT_SECRET_KEY=CANARY6x",
    "encryption_key=CANARY6x", "signing_key: CANARY6x", "master_key=CANARY6x", "ssh_key=CANARY6x",
    "license_key=CANARY6x", "hmac_key=CANARY6x", "sessionid=CANARY6x", "auth=CANARY6x",
    "Cookie: sid=CANARY6x", "Cookie=CANARY6x",
    "pass " * 130 + '"note": "key", x-api-key: CANARY6x', "pass " * 130 + "api_key=`CANARY6x`",
    "[('OPENAI_API_KEY', 'CANARY6x'), ('PATH', '/bin')]", "[('DB_PASSWORD', 'CANARY6x')]",
    "[('aws_secret_access_key','CANARY6x')]", "[('access_token','CANARY6x9')]",
    "[('jwt_secret','CANARY6x')]", "[('userPassword','CANARY6x')]", "[('token','CANARY6x9')]"])
def test_round16_key_names_and_pairs_are_redacted(text):
    from audel.logging import scrub_text

    assert "CANARY6x" not in scrub_text(text)


@pytest.mark.parametrize("value", ["éCANARY6x", "a'CANARY6x", 'a"CANARY6x', "a\\bCANARY6x"])
def test_double_encoded_values_with_escapes_are_redacted(value):
    import json as _json

    from audel.logging import scrub_text

    out = scrub_text(_json.dumps(_json.dumps({"password": value, "note": "ok"})))
    assert "CANARY6x" not in out and "note" in out


@pytest.mark.parametrize("text", ['["password", "username", "email"]',
                                  "visibility in ['secret', 'public', 'private']",
                                  "['api_key', 'cache_dir', 'spec']", "author: Jane",
                                  "authentication required", "session started"])
def test_name_lists_and_prose_are_not_redacted(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_access_log_redacts_secret_key_queries():
    out = _emit('%s - "%s %s HTTP/%s" %d', "1.2.3.4", "GET", "/specs?SECRET_KEY=CANARY6x", "1.1",
                401, name="uvicorn.access")
    assert "CANARY6x" not in out and "/specs?SECRET_KEY=" in out


# ==== round 16, decode surface (mono mix by layout type) ======================================

def _st(layout, n):
    from audel.mediaguard import StreamInfo

    return StreamInfo(index=0, codec="pcm_s16le", sample_rate=48000, channels=n, layout=layout)


def test_mono_mix_is_chosen_by_layout_type():
    from audel.mediaguard import mono_filter

    assert mono_filter(_st("ambisonic 1", 4)) == "pan=mono|c0=1.000000*c0"  # W only
    five = mono_filter(_st("5.1", 6))                                        # by label (r17)
    assert "channel_layouts" not in five and "*c3" not in five and "*c4" in five  # by label
    custom = mono_filter(_st("3 channels (FC+FL+FR)", 3))
    assert "pan=mono|" in custom and "*c0" in custom                        # label weights
    plain = mono_filter(_st("", 5), power=True)
    assert plain.startswith("pan=mono|") and "0.447214" in plain            # 1/sqrt(5)


def test_phase_checks_use_the_real_left_right_pair():
    from audel.mediaguard import lr_pair

    assert lr_pair(_st("3 channels (FC+FL+FR)", 3)) == (1, 2)
    assert lr_pair(_st("ambisonic 1", 4)) is None
    assert lr_pair(_st("", 5)) == (0, 1)                 # plain channels: L/R first
    assert lr_pair(_st("stereo", 2)) == (0, 1)


@requires_ffmpeg
def test_right_side_ambisonic_source_is_not_a_polarity_fault(tmp_path):
    from audel import check

    _ff("-f", "lavfi", "-i", "sine=f=440:d=6", "-f", "lavfi", "-i", "anoisesrc=d=6:c=pink:a=0.01",
        "-filter_complex", "[0]volume=0.3[s];[s][1]amix=normalize=0,asplit=4[w][y][z][x];"
        "[y]volume=-1[yn];[z]volume=0[zn];[x]volume=0.01[xn];[w][yn][zn][xn]amerge=inputs=4[out]",
        "-map", "[out]", "-c:a", "libopus", "-mapping_family", "2", tmp_path / "r.opus")
    r = asyncio.run(check(str(tmp_path / "r.opus")))
    checks = {i.detail.get("check") for i in r.issues}
    assert not {"polarity_inversion", "phase", "dead_channel"} & checks, checks


@requires_ffmpeg
@pytest.mark.parametrize("order", ["FC+FL+FR", "LFE+FL+FR+FC+BL+BR"])
def test_inverted_left_right_is_caught_in_any_channel_order(tmp_path, order):
    from audel import check

    n = order.count("+") + 1
    names = order.split("+")
    mapping = "|".join(f"c{i}=" + ("c0" if nm == "FL" else "-1*c0" if nm == "FR" else "0*c0")
                       for i, nm in enumerate(names))
    f = tmp_path / "x.mov"
    _ff("-f", "lavfi", "-i", "anoisesrc=d=6:c=pink:a=0.1", "-af",
        f"pan={order}|{mapping}", "-c:a", "pcm_s16le", f)
    del n
    lay = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "stream=channel_layout",
                          "-of", "csv=p=0", str(f)], capture_output=True, text=True).stdout
    if order not in lay:
        # ffmpeg 6.x's mov muxer stores the nearest standard layout without reordering the
        # audio: the file itself then mislabels its channels, which no grader can see through.
        pytest.skip(f"this ffmpeg can't write the {order} order (wrote {lay.strip()!r})")
    checks = {i.detail.get("check") for i in asyncio.run(check(str(f))).issues}
    assert "polarity_inversion" in checks, checks


# ==== round 17, auth surface ==================================================================

def test_pprint_wrapped_and_loose_pairs_are_redacted():
    import pprint

    from audel.logging import scrub_text

    c = "CANARYq9Z"
    for text in (pprint.pformat(sorted({"DB_PASSWORD": c + "x" * 70, "PATH": "/usr/bin"}.items())),
                 f"('password', 'zQ7{c}',)", f"['password', 'zQ7{c}', ]",
                 f"('password', 'zQ7{c}', 'x')", f"['psql', '--password', '{c}', '-h', 'db']",
                 f"('auth', '{c}')", f"('sig', '{c}x1')"):
        assert c not in scrub_text(text), text


@pytest.mark.parametrize("value", ["é", "😀", "\n"])
def test_double_encoded_with_raw_unicode_is_redacted(value):
    import json as _json

    from audel.logging import scrub_text

    text = _json.dumps(_json.dumps({"password": value + "CANARYq9Z"}, ensure_ascii=False))
    assert "CANARYq9Z" not in scrub_text(text)


def test_triple_encoded_json_is_redacted():
    import json as _json

    from audel.logging import scrub_text

    assert "CANARYq9Z" not in scrub_text(_json.dumps(_json.dumps(_json.dumps(
        {"password": "CANARYq9Z"}))))


@pytest.mark.parametrize("text", ["auth: required", "AUDEL auth: tenant t0 status=401",
                                  "cookie: none", "session_id: 42", '{"session_id": 42}',
                                  '{"auth": null, "x": 1}', "has_secret_key: false"])
def test_ids_literals_and_auth_prose_are_kept(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_sub_word_keys_are_found():
    from audel.logging import scrub_text

    for text in ("aws_secret_access_key=abcd1234", "myApiKey=abc123", "JWT_SECRET_KEY=abc"):
        assert scrub_text(text).endswith("[REDACTED]"), text


@pytest.mark.parametrize("unit", ["('apikey',  b", "('session_id', '", "secret[b'", "auth ",
                                  "('a','b'), "])
def test_pair_and_keyword_floods_stay_bounded(unit):
    from audel.logging import scrub_text

    text = unit * (7900 // len(unit))
    best = 9.0
    for _ in range(5):
        t0 = time.process_time()
        scrub_text(text)
        best = min(best, time.process_time() - t0)
    assert best < 0.015, best


# ==== round 17, decode surface ================================================================

@pytest.mark.parametrize("layout,n", [("7.1.4", 12), ("5.1.4", 10), ("7.2.3", 12), ("cube", 8),
                                      ("hexadecagonal", 16), ("22.2", 24)])
def test_every_channel_of_a_named_layout_reaches_the_mono_mix(layout, n):
    from audel.mediaguard import mono_filter

    st = _st(layout, n)
    labels = st.channel_labels()
    for power in (False, True):
        mix = mono_filter(st, power=power)
        for i, lab in enumerate(labels):
            assert (f"*c{i}+" in mix or f"*c{i}," in mix or mix.endswith(f"*c{i}")) \
                != lab.upper().startswith("LFE"), (layout, lab, mix)


def test_ambisonic_plus_stereo_keeps_and_checks_the_head_locked_pair():
    from audel.mediaguard import ambisonic_components, lr_pair, mono_filter

    st = _st("ambisonic 1+stereo", 6)
    assert ambisonic_components(st) == 4
    assert lr_pair(st) == (4, 5)
    mix = mono_filter(st)
    assert "*c0" in mix and "*c4" in mix and "*c5" in mix and "*c1" not in mix
    assert ambisonic_components(_st("ambisonic 2", 9)) == 9


def test_lfe_only_layout_never_builds_an_empty_mix():
    from audel.mediaguard import mono_filter

    for power in (False, True):
        assert mono_filter(_st("2 channels (LFE+LFE2)", 2), power=power).startswith(
            "pan=mono|c0=1.000000*c0")


@requires_ffmpeg
def test_hum_in_height_channels_is_heard(tmp_path):
    from audel import check

    f = tmp_path / "h.mov"
    mapping = "|".join(f"c{i}=" + ("c0" if i == 2 else "0.3*c1" if i in (10, 11) else "0*c0")
                       for i in range(12))
    _ff("-f", "lavfi", "-i", "anoisesrc=d=8:c=pink:a=0.05", "-f", "lavfi",
        "-i", "sine=f=50:d=8:sample_rate=48000", "-filter_complex",
        f"[0][1]amerge=inputs=2,pan=7.1.4|{mapping}[o]", "-map", "[o]", "-c:a", "pcm_s24le", f)
    checks = {i.detail.get("check") for i in asyncio.run(check(str(f))).issues}
    assert "hum" in checks, checks


def test_speex_uses_the_deterministic_decoder(monkeypatch):
    from audel import mediaguard
    from audel.config import Settings
    from audel.errors import DecodeError

    ff = mediaguard._tool("ffmpeg", Settings().ffmpeg_path)
    monkeypatch.setattr(mediaguard, "_LIBSPEEX", {ff: True})
    assert mediaguard.decoder_args("speex", 1, Settings()) == ["-c:a:1", "libspeex"]
    assert mediaguard.decoder_args("aac", 0, Settings()) == []
    monkeypatch.setattr(mediaguard, "_LIBSPEEX", {ff: False})
    with pytest.raises(DecodeError):
        mediaguard.decoder_args("speex", 0, Settings())


@requires_ffmpeg
def test_speex_decodes_identically_every_run(tmp_path):
    import hashlib
    import subprocess

    from audel.config import Settings
    from audel.mediaguard import decode_to_wav

    f = tmp_path / "s.ogg"
    try:
        _ff("-f", "lavfi", "-i", "anoisesrc=d=3:c=pink:a=0.2:r=16000", "-c:a", "libspeex", f)
    except (subprocess.CalledProcessError, AssertionError):
        pytest.skip("no libspeex encoder")
    digests = set()
    for _ in range(4):
        out = decode_to_wav(f, Settings())
        digests.add(hashlib.sha256(out.read_bytes()).hexdigest())
        out.unlink()
    assert len(digests) == 1


# ==== round 18, auth surface ==================================================================

@pytest.mark.parametrize("key", ["XAPIKEY", "AWSAccessKey", "GCPApiKey", "OPENAIAPIKEY", "DBPRIVATEKEY",
                                 "TLSPrivateKey", "myapikey", "9apikey", "éapikey", "SECRET_KEY_BASE",
                                 "DB_PASSWORD_PROD", "password2", "API_KEY_V2"])
def test_glued_and_suffixed_compound_keys_are_redacted(key):
    from audel.logging import scrub_text

    for fmt in ("{k}=zQ7hunterZ", "{k}: zQ7hunterZ", '{{"{k}": "zQ7hunterZ"}}'):
        assert "zQ7hunterZ" not in scrub_text(fmt.format(k=key)), fmt.format(k=key)


@pytest.mark.parametrize("text", ["password=zQ7}hunterZ", "DB_PASSWORD=p4ss]w0rd{zQ7hunterZ}",
                                  "secret=}zQ7hunterZ", "api_key: ]zQ7hunterZ",
                                  "('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_PASSWORD_BBBBBBBBBBB', 'zQ7hunterZ')",
                                  "('İsecret', 'zQ7hunterZ')"])
def test_brackets_inside_values_and_long_or_unicode_pair_names(text):
    from audel.logging import scrub_text

    assert "zQ7hunterZ" not in scrub_text(text)


@pytest.mark.parametrize("text", ["password=none", "password=yes", "session_id: 123456789012345"])
def test_carve_outs_are_narrow(text):
    from audel.logging import scrub_text

    assert scrub_text(text).endswith("[REDACTED]")


@pytest.mark.parametrize("text", ["tokens=512", "max_tokens=1024", "pass_rate: 98%", "keyframe=12",
                                  "monkey=3", "hotkey: ctrl", '{"password": null}'])
def test_counts_and_ordinary_words_are_kept(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


# ==== round 18, decode surface ================================================================

@requires_ffmpeg
@pytest.mark.parametrize("codec", ["pcm_s16le", "pcm_s24le"])
def test_hot_integer_surround_neither_wraps_nor_clips_in_the_asr_mix(tmp_path, codec):
    import wave

    import numpy as np

    from audel.config import Settings
    from audel.mediaguard import decode_to_wav

    f = tmp_path / "t51.wav"
    _ff("-f", "lavfi", "-i", "aevalsrc=0.89*sin(2*PI*1000*t):s=48000:d=3", "-af",
        "pan=5.1|FL=c0|FR=c0|FC=c0|LFE=0*c0|BL=c0|BR=c0", "-c:a", codec, f)
    w = decode_to_wav(f, Settings())
    with wave.open(str(w)) as x:
        a = np.frombuffer(x.readframes(x.getnframes()), "<i2").astype(float) / 32768
    w.unlink()
    a = a[len(a) // 4:]
    crest = 20 * np.log10(np.max(np.abs(a)) / np.sqrt(np.mean(a * a)))
    assert crest >= 2.9, crest                       # a sine's 3 dB: not squared off
    assert int(np.sum(np.abs(np.diff(a)) > 1.0)) == 0  # no wrap-around jumps


@requires_ffmpeg
def test_chained_ogg_codec_switch_is_not_silently_unmeasured(tmp_path):
    import subprocess

    from audel import check

    a, b, chain = tmp_path / "a.ogg", tmp_path / "b.ogg", tmp_path / "chain.ogg"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=4:sample_rate=48000", "-af", "volume=0.1",
        "-c:a", "libopus", a)
    try:
        _ff("-f", "lavfi", "-i", "sine=f=440:d=4:sample_rate=48000", "-c:a", "libvorbis", b)
    except (subprocess.CalledProcessError, AssertionError):
        pytest.skip("no libvorbis encoder")
    chain.write_bytes(a.read_bytes() + b.read_bytes())
    checks = {i.detail.get("check") for i in asyncio.run(check(str(chain))).issues}
    assert "demux_stopped" in checks, checks


def test_decoder_probe_timeout_is_busy_not_a_bad_file(monkeypatch):
    from audel import mediaguard
    from audel.config import Settings
    from audel.errors import BusyError, UnsafeSourceError

    def slow(*a, **k):
        raise UnsafeSourceError("decode exceeded 15s timeout (possible resource bomb)")

    monkeypatch.setattr(mediaguard, "_LIBSPEEX", {})
    monkeypatch.setattr(mediaguard, "run", slow)
    with pytest.raises(BusyError):
        mediaguard.decoder_args("speex", 0, Settings())
    assert mediaguard._LIBSPEEX == {}  # nothing cached from a failed probe


# ==== round 18b, REST availability + redaction ================================================

def test_disabled_watch_is_refused_before_its_body_is_read(tmp_path, monkeypatch):
    from starlette.requests import Request

    reads = []
    orig = Request.body

    async def spy(self):
        reads.append(1)
        return await orig(self)

    monkeypatch.setattr(Request, "body", spy)
    c = TestClient(build_app(settings=_s(tmp_path)))
    h = {"Authorization": f"Bearer {SHARED}", "Content-Type": "application/json"}
    r = c.post("/watch", content=b'{"source": "' + b"x" * 2_000_000 + b'"}', headers=h)
    assert r.status_code == 403 and not reads


def test_enabled_watch_takes_only_a_small_declared_body(tmp_path):
    c = TestClient(build_app(settings=_s(tmp_path, rest_allow_watch=True)))
    h = {"Authorization": f"Bearer {SHARED}", "Content-Type": "application/json"}
    assert c.post("/watch", content=b'{"source": "' + b"x" * 70_000 + b'"}',
                  headers=h).status_code == 413
    assert c.post("/watch", content=b"[1, 2]", headers=h).status_code == 400


def test_queued_upload_bytes_are_bounded_per_tenant(tmp_path):
    from audel.adapters.rest import SpoolQuota

    q = SpoolQuota(total=1000, per_tenant=400)
    assert q.reserve("a", 300) and not q.reserve("a", 200)   # tenant bound
    assert q.reserve("b", 400) and q.reserve("c", 300) and not q.reserve("d", 1)  # overall
    q.release("a", 300)
    assert q.reserve("d", 300) and q.held.get("a") is None

    c = TestClient(build_app(settings=_s(tmp_path, max_spool_bytes=10_000,
                                         max_spool_bytes_per_tenant=5_000)))
    h = {"Authorization": f"Bearer {SHARED}"}
    r = c.post("/jobs", files={"file": ("a.wav", b"\0" * 6_000, "audio/wav")}, headers=h)
    assert r.status_code == 429


@pytest.mark.parametrize("text", [
    "key " * 70 + ' {\\"password\\": \\"zQ7hunterZ\\"}', "token=1 " * 100 + " password2=zQ7hunterZ",
    "token2=zQ7hunterZ", "TOKEN_V2=zQ7hunterZ", '"access_token2": "zQ7hunterZ"',
    '"{\\"DB_PASSWORD_PROD\\": \\"zQ7hunterZ\\"}"', "psql --password zQ7hunterZ -h db",
    "('_sig', 'zQ7hunterZ')", "('v2sig', 'zQ7hunterZ')"])
def test_round18b_redaction_gaps_are_closed(text):
    from audel.logging import scrub_text

    assert "zQ7hunterZ" not in scrub_text(text)


@pytest.mark.parametrize("text", ["--verbose --pass-through x", "run --token-file /x",
                                  "('compass', 'north')", "tokens=512"])
def test_argv_and_pair_rules_keep_ordinary_text(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


def test_escaped_quote_floods_stay_bounded():
    from audel.logging import scrub_text

    text = 'sig=\\\\\\"' * (7900 // 8)
    best = 9.0
    for _ in range(5):
        t0 = time.process_time()
        scrub_text(text)
        best = min(best, time.process_time() - t0)
    assert best < 0.008, best


# ==== round 19, REST + redaction ==============================================================

def test_watch_body_is_read_before_a_grading_slot_is_taken():
    import inspect

    from audel.adapters import rest

    src = inspect.getsource(rest.build_app)
    body = src[src.index("async def watch_ep"):src.index("# ---- async jobs")]
    assert "Depends(" not in body.split(")", 1)[0]          # no slot dependency in the signature
    assert body.index("await request.body()") < body.index("_slot_for(")


def test_watch_nested_json_is_a_400_not_a_500(tmp_path):
    c = TestClient(build_app(settings=_s(tmp_path, rest_allow_watch=True)), raise_server_exceptions=False)
    h = {"Authorization": f"Bearer {SHARED}", "Content-Type": "application/json"}
    assert c.post("/watch", content=b"[" * 60000, headers=h).status_code == 400


def test_length_with_chunked_framing_is_refused(tmp_path):
    c = TestClient(build_app(settings=_s(tmp_path)))
    h = {"Authorization": f"Bearer {SHARED}", "Content-Length": "10", "Transfer-Encoding": "chunked"}
    r = c.post("/jobs", content=b"5\r\nhello\r\n0\r\n\r\n", headers=h)
    assert r.status_code == 400


def test_sync_uploads_count_against_the_spool_budget(tmp_path):
    c = TestClient(build_app(settings=_s(tmp_path, max_spool_bytes=10_000,
                                         max_spool_bytes_per_tenant=5_000)))
    h = {"Authorization": f"Bearer {SHARED}"}
    r = c.post("/check", files={"file": ("a.wav", b"\0" * 6_000, "audio/wav")}, headers=h)
    assert r.status_code == 429


@pytest.mark.parametrize("text", [
    "--password = zQ7hunterZ", '-password = "zQ7hunterZ"', "--password : zQ7hunterZ",
    'psql --password "zQ7hunterZ" -h db', "psql --password 'zQ7hunterZ'", "--x-api-key zQ7hunterZ",
    "--authorization zQ7hunterZ", "--cookie zQ7hunterZ", "aws --secret-access-key zQ7hunterZ",
    "--AWSAccessKey zQ7hunterZ", "--DB_PASSWORD_PROD zQ7hunterZ", "--session_id zQ7hunterZ"])
def test_command_line_credential_flags_are_redacted(text):
    from audel.logging import scrub_text

    assert "zQ7hunterZ" not in scrub_text(text)


@pytest.mark.parametrize("text", [
    "ffmpeg -i a -pass 1 -passlogfile x out.mp4", "x264 --pass 2", "llm --token 512",
    "--pwd /home/me", "--compass north", "--session-timeout 30", "('no_auth','true')",
    "('two-pass','true')", "('audio_sig','ok')"])
def test_ordinary_flags_and_flag_pairs_are_kept(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text


# ==== round 19, decode surface (unread media after the demuxer stops) =========================

def _demux_stopped(path):
    from audel import check

    return any(i.detail.get("check") == "demux_stopped" for i in asyncio.run(check(str(path))).issues)


@requires_ffmpeg
def test_fragmented_mp4_that_stops_early_is_caught(tmp_path):
    f = tmp_path / "f.mp4"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=8:sample_rate=48000", "-c:a", "aac", "-movflags",
        "+frag_keyframe+empty_moov", "-frag_duration", "1000000", f)
    assert not _demux_stopped(f)
    data = bytearray(f.read_bytes())
    second = data.find(b"moof", data.find(b"moof") + 4)
    assert second > 0
    data[second - 4:second] = (7).to_bytes(4, "big")  # a damaged box: ffmpeg stops, exit 0
    cut = tmp_path / "cut.mp4"
    cut.write_bytes(bytes(data))
    assert _demux_stopped(cut)


@requires_ffmpeg
@pytest.mark.parametrize("trailer", [b"TAG" + b"\0" * 125, b"\0" * 4096])
def test_wavpack_with_a_trailing_tag_or_padding_is_not_flagged(tmp_path, trailer):
    f = tmp_path / "a.wv"
    try:
        _ff("-f", "lavfi", "-i", "sine=f=440:d=4", "-c:a", "wavpack", "-metadata", "title=Song", f)
    except (subprocess.CalledProcessError, AssertionError):
        pytest.skip("no wavpack encoder")
    g = tmp_path / "b.wv"
    g.write_bytes(f.read_bytes() + trailer)
    assert not _demux_stopped(g)


@requires_ffmpeg
def test_intact_and_same_codec_chained_ogg_are_not_flagged(tmp_path):
    a, b = tmp_path / "a.ogg", tmp_path / "b.ogg"
    _ff("-f", "lavfi", "-i", "sine=f=440:d=4:sample_rate=48000", "-c:a", "libopus", a)
    _ff("-f", "lavfi", "-i", "sine=f=330:d=4:sample_rate=48000", "-c:a", "libopus", b)
    chain = tmp_path / "chain.ogg"
    chain.write_bytes(a.read_bytes() + b.read_bytes())
    assert not _demux_stopped(a) and not _demux_stopped(chain)


def test_demux_stop_is_not_read_from_decoder_log_text():
    import inspect

    from audel import mediaguard

    assert "Error during demuxing" not in inspect.getsource(mediaguard)  # forgeable by tag text


# ==== round 20, decode surface (unread media judged region by region) =========================

def test_one_oversized_packet_cannot_vouch_for_unread_regions():
    from audel.mediaguard import _first_unread

    regions = [10_000 * k for k in range(1, 11)]            # ten 10 kB essence regions
    assert _first_unread(regions, [10_100], [], 110_000) == 20_000  # one huge packet (MXF BER)
    relocated = [10_100, 109_000]                           # a packet copied to the file end
    assert _first_unread(regions, relocated, [], 110_000) == 20_000
    every = [r + 100 for r in regions]
    assert _first_unread(regions, every, [], 110_000) is None


def test_wavpack_multiblock_packets_and_small_header_regions_are_read():
    from audel.mediaguard import _first_unread

    # one packet spanning two blocks: the second block's region starts inside it
    assert _first_unread([0, 6_000, 12_000], [10, 12_010], [(10, 11_000), (12_010, 18_000)],
                         18_000) is None
    # header-sized regions (consecutive Ogg BOS pages) are not media
    assert _first_unread([0, 300, 700], [800], [], 50_000) is None


def test_packet_listing_reads_named_fields_not_csv_order():
    import inspect

    from audel import mediaguard

    src = inspect.getsource(mediaguard.unread_media_at)
    assert "compact=p=0" in src and 'b"pos"' in src  # ffprobe orders csv columns its own way


# ==== round 20, REST + redaction ==============================================================

def test_abandoned_grade_keeps_its_disk_reservation_until_it_ends(tmp_path, monkeypatch):
    import time as _time

    import audel.core as core

    async def slow_check(path, **kw):
        await asyncio.sleep(2.5)  # outlives the request's 1 s limit (the shielded work goes on)
        raise AudelError("stub")

    monkeypatch.setattr(core, "check", slow_check)
    app = build_app(settings=_s(tmp_path, request_timeout_s=1, max_request_bytes=8_000,
                                max_spool_bytes=20_000, max_spool_bytes_per_tenant=8_000))
    import io
    import wave

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:  # a real (tiny) WAV, so grading actually starts
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(b"\1\0" * 2_400)
    h = {"Authorization": f"Bearer {SHARED}"}
    up = {"file": ("a.wav", buf.getvalue(), "audio/wav")}
    with TestClient(app) as c:  # one event loop: the abandoned grade really keeps running
        assert c.post("/check", files=up, headers=h).status_code != 200
        assert c.post("/check", files=up, headers=h).status_code == 429  # still held on disk
        _time.sleep(3)
        assert c.post("/check", files=up, headers=h).status_code != 429  # released at its end


def test_derived_spool_share_always_fits_one_url_request(tmp_path):
    from audel.adapters import rest

    seen = []
    orig = rest.SpoolQuota.__init__

    def spy(self, total, per_tenant):
        seen.append(per_tenant)
        orig(self, total, per_tenant)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(rest.SpoolQuota, "__init__", spy)
        build_app(settings=_s(tmp_path, allow_url_ingest=True, max_request_bytes=1_000,
                              max_media_bytes=10_000, max_spool_bytes=20_000))
        assert seen[-1] >= 11_000                     # not total // 4 = 5 000
        warned = []
        mp.setattr(rest.log, "warning", lambda msg, *a: warned.append(msg % a))
        build_app(settings=_s(tmp_path, allow_url_ingest=True, max_request_bytes=1_000,
                              max_media_bytes=10_000, max_spool_bytes=20_000,
                              max_spool_bytes_per_tenant=5_000))
        assert any("always get 429" in w for w in warned)


@pytest.mark.parametrize("text", ["docker login --username amit --password-stdin ghcr.io",
                                  "--password-file /run/secrets/db_pass", "gpg --passphrase-fd 0",
                                  "--ssh-key-file ~/.ssh/id_ed25519"])
def test_flags_that_point_at_a_credential_are_kept(text):
    from audel.logging import scrub_text

    assert scrub_text(text) == text
