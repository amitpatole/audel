"""Phase 9 security: new attack surface from multi-track probing, container tags, the HTML QC
report, and spec selection over REST/MCP. Each test is an exploit attempt that must be blocked."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from audel.config import Settings
from audel.errors import ConfigError, UnsafeSourceError
from audel.mediaguard import _tag, probe, validate_source
from audel.models import Issue, IssueKind, Report, Severity, Span, TrackSummary, Verdict
from audel.qc_report import render_html

requires_ffmpeg = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")


def _mux(tmp_path, n_streams: int, title: str = "x"):
    src = tmp_path / "a.wav"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "sine=f=440:d=1",
                    str(src)], check=True)
    out = tmp_path / f"m{n_streams}.mkv"
    argv = ["ffmpeg", "-v", "error", "-y"]
    for _ in range(n_streams):
        argv += ["-i", str(src)]
    for i in range(n_streams):
        argv += ["-map", f"{i}:a"]
    argv += ["-c:a", "pcm_s16le", "-metadata:s:a:0", f"title={title}", str(out)]
    subprocess.run(argv, check=True)
    return out


@requires_ffmpeg
def test_stream_count_bomb_refused_before_per_track_decode(tmp_path):
    f = _mux(tmp_path, 6)
    s = Settings(max_audio_streams=4)
    with pytest.raises(UnsafeSourceError, match="stream"):
        probe(validate_source(f, s), s)


@requires_ffmpeg
def test_hostile_container_tags_are_neutralized(tmp_path):
    f = _mux(tmp_path, 1, title="<script>alert(1)</script>\x1b[31m")
    s = Settings()
    info = probe(validate_source(f, s), s)
    title = info.streams[0].title or ""
    assert "<" not in title and ">" not in title and "\x1b" not in title


def test_tag_sanitizer_bounds_length_and_charset():
    assert len(_tag("a" * 10_000)) == 64
    assert _tag("eng\n\r\t<>\"'`") == "eng"


def test_qc_report_escapes_every_untrusted_field():
    evil = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    r = Report(verdict=Verdict.FAIL, summary=evil, backend=evil, duration_ms=1000, spec=evil,
               issues=[Issue.make(IssueKind.NOISE, Severity.WARNING, evil,
                                  span=Span(start_ms=0, end_ms=500), detail={"check": evil})],
               tracks=[TrackSummary(index=0, codec=evil, layout=evil, language=evil, title=evil)])
    page = render_html(r, source_name=evil)
    assert "<script>" not in page and "<img" not in page and "onerror=alert" not in page.replace(
        "onerror=alert(1)&gt;", "")
    assert "script-src 'none'" in page and "default-src 'none'" in page
    assert "&lt;script&gt;" in page


# ---- REST: spec selection is NAMES only ------------------------------------------------------

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from audel.adapters.rest import build_app  # noqa: E402


@requires_ffmpeg
def test_rest_refuses_spec_file_paths_and_unknown_names(tmp_path, media):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path, allow_local_files=False)))
    for bad in ("/etc/passwd", "../../secrets.json", "spec.json", "nope"):
        with open(media["good"], "rb") as fh:
            r = c.post("/check", files={"file": ("a.wav", fh, "audio/wav")}, data={"spec": bad})
        assert r.status_code == 400, bad
        assert "root:" not in r.text
    with open(media["good"], "rb") as fh:
        ok = c.post("/check", files={"file": ("a.wav", fh, "audio/wav")}, data={"spec": "ebu_r128"})
    assert ok.status_code == 200 and ok.json()["spec"] == "ebu_r128"
    assert {s["name"] for s in c.get("/specs").json()["specs"]} >= {"ebu_r128", "netflix"}


@requires_ffmpeg
def test_rest_rejects_unknown_content_type(tmp_path, media):
    c = TestClient(build_app(settings=Settings(cache_dir=tmp_path, allow_local_files=False)))
    with open(media["good"], "rb") as fh:
        r = c.post("/check", files={"file": ("a.wav", fh, "audio/wav")}, data={"content": "x"})
    assert r.status_code == 400


def test_mcp_spec_argument_is_names_only():
    pytest.importorskip("mcp")
    from audel.adapters.mcp import _builtin

    with pytest.raises(ConfigError):
        _builtin("/etc/audel/contract.json")
    assert _builtin("op59").name == "op59"
