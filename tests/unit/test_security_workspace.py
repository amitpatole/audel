"""Phase 5 security: the workspace never persists secrets and reaps stale/mismatched sessions."""

from __future__ import annotations

import pytest

from audel.config import Settings
from audel.errors import UnsafeSourceError
from audel.logging import register_secret, scrub_text
from audel.workspace import Workspace


def _ws(tmp_path) -> Workspace:
    return Workspace(Settings(cache_dir=tmp_path))


def test_secret_is_scrubbed_from_persisted_iteration(tmp_path):
    secret = "sk-supersecrettoken1234567890"
    register_secret(secret)
    ws = _ws(tmp_path)
    sid = ws.new_session_id()
    p = ws.write_iter_json(sid, 0, "report.json", f'{{"leak": "{secret}"}}')
    text = p.read_text()
    assert secret not in text and "[REDACTED]" in text


def test_secret_scrubbed_from_session_meta(tmp_path):
    secret = "AIzaSyDEADBEEFdeadbeef1234567890xyz"
    register_secret(secret)
    ws = _ws(tmp_path)
    sid = ws.new_session_id()
    ws.write_session_meta(sid, {"note": f"key={secret}"})
    text = (ws.session_dir(sid) / "session.json").read_text()
    assert secret not in text


def test_shape_based_token_scrubbed_even_if_unregistered(tmp_path):
    # A bearer token that was never register_secret'd is still caught by the shape regex backstop.
    ws = _ws(tmp_path)
    sid = ws.new_session_id()
    p = ws.write_iter_json(sid, 0, "h.json", "Authorization: Bearer abcDEF1234567890token")
    assert "abcDEF1234567890token" not in p.read_text()


def test_artifact_key_is_inputs_addressed_and_stable(tmp_path):
    ws = _ws(tmp_path)
    k1 = ws.artifact_key(source_bytes=b"AAAA", params={"sr": 16000, "ch": 1})
    k2 = ws.artifact_key(source_bytes=b"AAAA", params={"ch": 1, "sr": 16000})  # order-independent
    k3 = ws.artifact_key(source_bytes=b"BBBB", params={"sr": 16000, "ch": 1})
    assert k1 == k2 and k1 != k3 and len(k1) == 32


def test_gc_reaps_schema_mismatch_keeps_current(tmp_path):
    ws = _ws(tmp_path)
    good = ws.new_session_id()
    ws.write_session_meta(good, {"iterations": 1})
    stale = ws.new_session_id()
    (ws.session_dir(stale) / "session.json").write_text('{"schema_version": "0.0-OLD"}')
    removed = ws.gc()
    assert removed >= 1
    assert ws.read_session_meta(good) is not None
    assert not (ws.sessions / stale).exists()


def test_scrub_text_noop_on_clean_text():
    assert scrub_text("nothing to hide here") == "nothing to hide here"


# ---- path traversal (Round 1) -------------------------------------------------

@pytest.mark.parametrize("evil", ["../../etc", "..", "a/b", "a\\b", "/abs", "", "."])
def test_session_id_traversal_refused(tmp_path, evil):
    ws = _ws(tmp_path)
    with pytest.raises(UnsafeSourceError):
        ws.session_dir(evil)
    with pytest.raises(UnsafeSourceError):
        ws.write_session_meta(evil, {"x": 1})


@pytest.mark.parametrize("evil", ["../escape.json", "..", "a/b.json", "sub/dir"])
def test_iter_filename_traversal_refused(tmp_path, evil):
    ws = _ws(tmp_path)
    sid = ws.new_session_id()
    with pytest.raises(UnsafeSourceError):
        ws.write_iter_json(sid, 0, evil, "{}")


def test_no_file_is_written_outside_cache_dir(tmp_path):
    # Prove the escape is blocked: nothing lands above the sessions root.
    outside = tmp_path.parent / "PWNED"
    ws = _ws(tmp_path)
    with pytest.raises(UnsafeSourceError):
        ws.write_iter_json("../../PWNED", 0, "x.json", "owned")
    assert not outside.exists()


def test_generated_session_id_is_accepted(tmp_path):
    ws = _ws(tmp_path)
    sid = ws.new_session_id()  # our own ids must always pass the validator
    p = ws.write_iter_json(sid, 0, "report.json", "{}")
    assert p.exists()
