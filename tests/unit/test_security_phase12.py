"""Phase 12 security: multi-tenant auth, JWT, rate limits, egress policy, TLS/mTLS.

Every test is an attack that must fail."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from audel.auth import Authenticator, RateLimiter, load_tenants, token_hash
from audel.config import Settings
from audel.errors import ConfigError, EgressDeniedError

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from audel.adapters.rest import build_app  # noqa: E402

A_TOK, B_TOK = "tenant-a-token-xxxxxxxxxxxxxxxx", "tenant-b-token-yyyyyyyyyyyyyyyy"


@pytest.fixture
def tokens_file(tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tenants": {
        "newsroom": {"sha256": token_hash(A_TOK)},
        "promos": {"sha256": token_hash(B_TOK), "rate_per_min": 2}}}))
    return f


def _h(tok):
    return {"authorization": f"Bearer {tok}"}


# ---- per-tenant tokens ------------------------------------------------------------------------

def test_tokens_file_holds_hashes_only_and_resolves_tenants(tokens_file):
    assert A_TOK not in tokens_file.read_text()
    a = Authenticator(Settings(api_tokens_file=tokens_file))
    assert a.required
    assert a.authenticate(f"Bearer {A_TOK}").tenant == "newsroom"
    assert a.authenticate(f"Bearer {B_TOK}").tenant == "promos"
    for bad in (None, "", "Bearer", "Bearer ", f"Basic {A_TOK}", f"Bearer {A_TOK}x",
                f"bearer {A_TOK}", "Bearer éé", "Bearer " + "x" * 9000):
        assert a.authenticate(bad) is None, bad


@pytest.mark.parametrize("payload", [
    {"tenants": {"../etc": {"sha256": "0" * 64}}},
    {"tenants": {"ok": {"sha256": "nothex"}}},
    {"tenants": {"ok": {"sha256": "0" * 64, "rate_per_min": -1}}},
    {"tenants": {}}, {"nope": 1}, [],
])
def test_tokens_file_is_strict(tmp_path, payload):
    f = tmp_path / "t.json"
    f.write_text(json.dumps(payload))
    with pytest.raises(ConfigError):
        load_tenants(f)


def test_tenant_cannot_see_another_tenants_job(tmp_path, media):
    tokens_file = tmp_path / "iso.json"   # no low per-tenant rate here: this test is isolation
    tokens_file.write_text(json.dumps({"tenants": {"newsroom": {"sha256": token_hash(A_TOK)},
                                                   "promos": {"sha256": token_hash(B_TOK)}}}))
    s = Settings(cache_dir=tmp_path, allow_local_files=False, api_tokens_file=tokens_file)
    with TestClient(build_app(settings=s)) as c:
        with open(media["good"], "rb") as fh:
            jid = c.post("/jobs", headers=_h(A_TOK),
                         files={"file": ("a.wav", fh, "audio/wav")}).json()["job_id"]
        assert c.get(f"/jobs/{jid}", headers=_h(B_TOK)).status_code == 404
        assert c.delete(f"/jobs/{jid}", headers=_h(B_TOK)).status_code == 404
        assert c.get("/jobs", headers=_h(B_TOK)).json()["jobs"] == []
        assert c.get(f"/jobs/{jid}", headers=_h(A_TOK)).status_code == 200


def test_per_tenant_rate_limit(tmp_path, tokens_file):
    s = Settings(cache_dir=tmp_path, api_tokens_file=tokens_file, rate_limit_burst=2)
    c = TestClient(build_app(settings=s))
    codes = [c.get("/specs", headers=_h(B_TOK)).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and 429 in codes[2:]
    r = c.get("/specs", headers=_h(B_TOK))
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert c.get("/specs", headers=_h(A_TOK)).status_code == 200  # other tenant unaffected


def test_failed_auth_is_throttled_and_valid_credentials_still_pass(tmp_path, tokens_file):
    s = Settings(cache_dir=tmp_path, api_tokens_file=tokens_file, auth_fail_per_min=4)
    c = TestClient(build_app(settings=s))
    codes = [c.get("/specs", headers=_h(f"guess-{i}")).status_code for i in range(6)]
    assert codes[0] == 401 and codes[-1] == 429
    assert c.get("/specs", headers=_h(A_TOK)).status_code == 200


def test_rate_limiter_memory_is_bounded():
    rl = RateLimiter(60, max_keys=100)
    for i in range(1000):
        rl.allow(f"10.0.{i // 256}.{i % 256}")
    assert len(rl._b) == 100


# ---- JWT --------------------------------------------------------------------------------------

jwt = pytest.importorskip("jwt")


@pytest.fixture
def idp(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    pub.update(kid="k1", alg="RS256", use="sig")
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": [pub]}))
    s = Settings(jwt_jwks_file=jwks, jwt_issuer="https://idp.example", jwt_audience="audel")

    def mint(**over):
        now = int(time.time())
        claims = {"iss": "https://idp.example", "aud": "audel", "iat": now, "exp": now + 300,
                  "tenant": "newsroom", **over}
        headers = {"kid": over.pop("_kid", "k1")} if "_kid" not in claims else {}
        claims.pop("_kid", None)
        return jwt.encode(claims, key, algorithm="RS256", headers=headers)

    return Authenticator(s), mint, key, pub


def test_valid_jwt_resolves_tenant(idp):
    a, mint, *_ = idp
    p = a.authenticate(f"Bearer {mint()}")
    assert p is not None and p.tenant == "jwt:newsroom" and p.method == "jwt"  # namespaced


@pytest.mark.parametrize("over", [
    {"iss": "https://evil.example"}, {"aud": "someone-else"},
    {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200},
    {"exp": int(time.time()) + 10 * 24 * 3600},           # lifetime over the cap
    {"tenant": "../admin"}, {"tenant": 7}, {"tenant": None},
])
def test_jwt_claim_attacks(idp, over):
    a, mint, *_ = idp
    assert a.authenticate(f"Bearer {mint(**over)}") is None


def test_jwt_alg_none_and_hs256_key_confusion_rejected(idp):
    a, _, _key, pub = idp
    now = int(time.time())
    claims = {"iss": "https://idp.example", "aud": "audel", "iat": now, "exp": now + 300,
              "tenant": "newsroom"}
    unsigned = jwt.encode(claims, key=None, algorithm="none")
    assert a.authenticate(f"Bearer {unsigned}") is None
    # Classic confusion: sign HS256 using the PUBLIC key as the shared secret.
    import base64
    import hashlib
    import hmac as _hmac

    def b64(x):
        return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(_hmac.new(json.dumps(pub).encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    assert a.authenticate(f"Bearer {head}.{body}.{sig}") is None


def test_jwt_from_an_unknown_key_rejected(idp):
    from cryptography.hazmat.primitives.asymmetric import rsa

    a, *_ = idp
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    tok = jwt.encode({"iss": "https://idp.example", "aud": "audel", "iat": now, "exp": now + 60,
                      "tenant": "newsroom"}, other, algorithm="RS256", headers={"kid": "k1"})
    assert a.authenticate(f"Bearer {tok}") is None


def test_symmetric_jwt_algorithms_refused_in_config(tmp_path):
    jwks = tmp_path / "j.json"
    jwks.write_text(json.dumps({"keys": []}))
    with pytest.raises(ConfigError):
        Authenticator(Settings(jwt_jwks_file=jwks, jwt_issuer="i", jwt_audience="a",
                               jwt_algorithms=["HS256"]))


# ---- egress policy ----------------------------------------------------------------------------

def test_egress_deny_blocks_every_network_path(tmp_path):
    from audel.backends.anthropic_backend import AnthropicBackend
    from audel.backends.ollama import OllamaBackend
    from audel.backends.ollama_local import LocalLLMBackend
    from audel.core.capture import capture_sound
    from audel.ingest import validate_ingest_url

    s = Settings(egress="deny", allow_url_ingest=True, ollama_api_key="k", anthropic_api_key="k",
                 local_llm_url="http://10.0.0.100:11434", trusted_backend_hosts=["10.0.0.100"])
    with pytest.raises(EgressDeniedError):
        asyncio.run(OllamaBackend(s).complete_text("s", "u"))
    with pytest.raises(EgressDeniedError):
        asyncio.run(LocalLLMBackend(s).complete_text("s", "u"))
    with pytest.raises(EgressDeniedError):
        AnthropicBackend(s)._complete("k", "s", "u")
    with pytest.raises(EgressDeniedError):
        validate_ingest_url("https://example.com/a.wav", s)
    with pytest.raises(EgressDeniedError):
        asyncio.run(capture_sound("https://example.com", settings=s))


def test_egress_local_only_allows_only_trusted_on_prem(monkeypatch):
    from audel.backends.ollama import OllamaBackend
    from audel.netguard import assert_backend_url

    s = Settings(egress="local-only", ollama_api_key="k", trusted_backend_hosts=["10.0.0.100"])
    assert_backend_url("http://10.0.0.100:11434/api/chat", s.trusted_backend_hosts, s)
    with pytest.raises(EgressDeniedError):
        asyncio.run(OllamaBackend(s).complete_text("s", "u"))  # public cloud


def test_egress_restricted_means_no_model_downloads():
    from audel.egress import models_offline

    assert models_offline(Settings(egress="deny")) and models_offline(Settings(egress="local-only"))
    assert not models_offline(Settings())
    with pytest.raises(ConfigError):
        models_offline(Settings(egress="sometimes"))


def test_check_still_works_with_egress_denied(media):
    from audel import check

    r = asyncio.run(check(str(media["good"]), settings=Settings(egress="deny")))
    assert r.verdict.value in ("pass", "warn")


# ---- TLS / mutual TLS -------------------------------------------------------------------------

def _certs(tmp_path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def make(cn, issuer_key=None, issuer_name=None, ca=False, san=None):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.UTC)
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(minutes=1))
             .not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if san:
            import ipaddress

            b = b.add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(san))]), critical=False)
        cert = b.sign(issuer_key or key, hashes.SHA256())
        return key, cert

    ca_key, ca = make("audel-test-ca", ca=True)
    srv_key, srv = make("127.0.0.1", ca_key, ca.subject, san="127.0.0.1")
    cli_key, cli = make("pipeline", ca_key, ca.subject)

    def dump(path, key, cert):
        path.with_suffix(".key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    dump(tmp_path / "ca", ca_key, ca)
    dump(tmp_path / "srv", srv_key, srv)
    dump(tmp_path / "cli", cli_key, cli)
    return tmp_path


def test_mutual_tls_requires_a_client_certificate(tmp_path, monkeypatch):
    import socket
    import ssl
    import threading
    import urllib.request

    pytest.importorskip("uvicorn")
    d = _certs(tmp_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    for k, v in {"AUDEL_API_TOKEN": "4ff70d20d90b8a5d20f68be638b41178509c5aa2d11dff85dc8bff1771a037fb", "AUDEL_CACHE_DIR": str(tmp_path),
                 "AUDEL_TLS_CERTFILE": str(d / "srv.crt"), "AUDEL_TLS_KEYFILE": str(d / "srv.key"),
                 "AUDEL_TLS_CLIENT_CA": str(d / "ca.crt")}.items():
        monkeypatch.setenv(k, v)
    from audel.adapters.rest import serve

    threading.Thread(target=serve, kwargs={"host": "127.0.0.1", "port": port}, daemon=True).start()
    url = f"https://127.0.0.1:{port}/healthz"
    ctx = ssl.create_default_context(cafile=str(d / "ca.crt"))
    deadline = time.time() + 15
    with_cert = ssl.create_default_context(cafile=str(d / "ca.crt"))
    with_cert.load_cert_chain(str(d / "cli.crt"), str(d / "cli.key"))
    while True:
        try:
            body = urllib.request.urlopen(url, context=with_cert, timeout=3).read()
            break
        except Exception:
            if time.time() > deadline:
                raise
            time.sleep(0.3)
    assert b'"ok"' in body
    # No client certificate: the TLS handshake is refused (surfaces as SSLError / URLError /
    # connection reset depending on timing).
    import urllib.error

    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError, OSError)):
        urllib.request.urlopen(url, context=ctx, timeout=3).read()


def test_serve_refuses_half_configured_tls(monkeypatch, tmp_path):
    from audel.adapters.rest import serve

    monkeypatch.setenv("AUDEL_API_TOKEN", "4ff70d20d90b8a5d20f68be638b41178509c5aa2d11dff85dc8bff1771a037fb")
    monkeypatch.setenv("AUDEL_TLS_CERTFILE", str(tmp_path / "a.crt"))
    with pytest.raises(SystemExit):
        serve("127.0.0.1", 0)
