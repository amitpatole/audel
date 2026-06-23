"""Phase 4 security: web-capture SSRF guard, sandbox-on-by-default, and DoS clamps."""

from __future__ import annotations

import asyncio
import inspect

import pytest

from audel.config import Settings
from audel.core import watch
from audel.core.capture import _launch_args, capture_sound, is_url
from audel.errors import UnsafeSourceError
from audel.models import Verdict


def test_is_url():
    assert is_url("http://x.com") and is_url("https://x.com/a")
    assert not is_url("/tmp/a.wav") and not is_url("file:///etc/passwd")


def test_capture_rejects_internal_url_before_launch():
    # SSRF: an internal URL is refused before Playwright is even imported.
    async def go():
        for url in ("http://169.254.169.254/", "http://127.0.0.1:3000/", "http://10.0.0.5/"):
            with pytest.raises(UnsafeSourceError):
                await capture_sound(url, settings=Settings())
    asyncio.run(go())


def test_capture_rejects_non_http_scheme():
    async def go():
        with pytest.raises(UnsafeSourceError):
            await capture_sound("ftp://example.com/a", settings=Settings())
    asyncio.run(go())


def test_watch_internal_url_grades_fail_not_crash():
    r = asyncio.run(watch("http://127.0.0.1:8080/"))
    assert r.verdict == Verdict.FAIL  # UnsafeSourceError -> graded decode_error, not an exception


def test_sandbox_on_by_default_no_silent_no_sandbox(monkeypatch):
    # The secure default is sandbox-ON. Isolate from any ambient AUDEL_CHROMIUM_SANDBOX
    # (CI sets it false so headless render tests can run on the runner) so this asserts
    # the genuine in-code default, not the environment.
    monkeypatch.delenv("AUDEL_CHROMIUM_SANDBOX", raising=False)
    on = _launch_args(Settings())
    assert on["chromium_sandbox"] is True and "--no-sandbox" not in on["args"]
    off = _launch_args(Settings(chromium_sandbox=False))  # explicit opt-out only
    assert off["chromium_sandbox"] is False and "--no-sandbox" in off["args"]


def test_loopback_forced_through_proxy():
    # Without <-loopback>, Chromium would bypass the proxy for 127.0.0.1 (SSRF side-channel).
    assert "--proxy-bypass-list=<-loopback>" in _launch_args(Settings())["args"]


def test_capture_uses_vetting_proxy_and_init_probe():
    src = inspect.getsource(capture_sound)
    assert "VettingProxy" in src and "assert_host_safe" in src and "add_init_script" in src
