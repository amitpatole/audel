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
    t0 = time.monotonic()
    align_script(" ".join(["the"] * 30_000), t, 9_000_000)
    cues = [Cue(i * 500, i * 500 + 2000, "the " * 60) for i in range(20_000)]
    issues, _ = caption_issues(cues, t, Settings(), 9_000_000)
    assert time.monotonic() - t0 < 30


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
    assert [f for f in (ws / "tmp").iterdir()] == []


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
    assert channel_layout_arg("unknown", 9).startswith("USR0+") and \
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
def test_unknown_duration_counts_as_the_maximum_for_budgets(tmp_path):
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
    with pytest.raises(UnsafeSourceError, match="budget"):
        probe(validate_source(mkv, s), s)


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
    s = Settings(cache_dir=tmp_path / "ws", allow_local_files=False, request_timeout_s=0.5,
                 max_concurrent_jobs=2, max_inflight_per_tenant=20)
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
        await asyncio.sleep(3.0)
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
    assert r.status_code == 200 and took < 2.0, (r.status_code, took)


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
