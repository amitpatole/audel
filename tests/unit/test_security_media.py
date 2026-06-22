"""Phase 1 security: prove the decode guards block each exploit, and pin them as regressions.

Surfaces: untrusted media decode (DoS / decompression bomb), path/option injection, and the
no-egress guarantee of the deterministic ``check`` path.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from audel import IssueKind, Verdict
from audel.config import Settings
from audel.core import check
from audel.errors import UnsafeSourceError
from audel.mediaguard import probe, validate_source

# --- path / option-injection guards -------------------------------------------------------

def test_leading_dash_source_rejected(tmp_path):
    # Even though we always pass `-i <path>`, a '-'-leading name is refused (option-injection).
    with pytest.raises(UnsafeSourceError):
        validate_source("-i/etc/passwd", Settings())


def test_control_chars_rejected():
    with pytest.raises(UnsafeSourceError):
        validate_source("evil\nname.wav", Settings())


def test_url_source_rejected_no_ssrf_via_check_path():
    # A URL must never reach ffmpeg's network protocols on the check path — it's not a local file.
    for url in ("http://169.254.169.254/latest/meta-data/",
                "https://example.com/a.wav", "file:///etc/passwd"):
        with pytest.raises(UnsafeSourceError):
            validate_source(url, Settings())


def test_empty_source_rejected():
    with pytest.raises(UnsafeSourceError):
        validate_source("", Settings())


def test_nonexistent_source_rejected(tmp_path):
    with pytest.raises(UnsafeSourceError):
        validate_source(str(tmp_path / "nope.wav"), Settings())


def test_directory_source_rejected(tmp_path):
    with pytest.raises(UnsafeSourceError):
        validate_source(str(tmp_path), Settings())


def test_empty_file_rejected(tmp_path):
    p = tmp_path / "empty.wav"
    p.write_bytes(b"")
    with pytest.raises(UnsafeSourceError):
        validate_source(str(p), Settings())


def test_local_files_disabled_rejected(tmp_path):
    p = tmp_path / "x.wav"
    p.write_bytes(b"RIFF....WAVE")
    with pytest.raises(UnsafeSourceError):
        validate_source(str(p), Settings(allow_local_files=False))


# --- DoS / decompression-bomb caps (enforced BEFORE decode) -------------------------------

def test_oversized_file_rejected_before_decode(media):
    # A real clip, but a tiny byte cap → refused up front (no decode attempted).
    with pytest.raises(UnsafeSourceError, match="over the"):
        validate_source(str(media["good"]), Settings(max_media_bytes=64))


def test_declared_duration_bomb_rejected(media):
    # The clip is ~3s; a 0.5s duration cap means a longer (or duration-lying) file is refused.
    path = validate_source(str(media["good"]), Settings())
    with pytest.raises(UnsafeSourceError, match="duration"):
        probe(path, Settings(max_duration_s=0.5))


def test_sample_rate_cap_rejected(media):
    path = validate_source(str(media["good"]), Settings())
    with pytest.raises(UnsafeSourceError, match="sample rate"):
        probe(path, Settings(max_sample_rate=8000))  # clip is 16 kHz


def test_channel_count_cap_rejected(media):
    path = validate_source(str(media["good"]), Settings())
    with pytest.raises(UnsafeSourceError, match="channel count"):
        probe(path, Settings(max_channels=0))  # any real file has >=1 channel


# --- corrupt input degrades to a graded FAIL, never a crash --------------------------------

def test_corrupt_file_grades_decode_error_not_crash(tmp_path):
    p = tmp_path / "garbage.wav"
    p.write_bytes(b"\x00\x01\x02not-a-real-wav" * 64)
    r = asyncio.run(check(str(p)))
    assert r.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.DECODE_ERROR for i in r.issues)


# --- the deterministic check path makes NO network calls -----------------------------------

def test_check_path_makes_no_python_network_calls(media, monkeypatch):
    calls = []

    def _boom(*a, **k):
        calls.append(a)
        raise AssertionError("network call attempted on the no-egress check path")

    monkeypatch.setattr(socket.socket, "connect", _boom, raising=True)
    monkeypatch.setattr(socket, "create_connection", _boom, raising=True)
    r = asyncio.run(check(str(media["good"])))
    assert r.verdict == Verdict.PASS
    assert calls == []
