"""Headless web-audio capture — play a URL and detect whether sounds actually fire.

The hard part of the ears (documented as such in the plan). Rather than capture a virtual audio
sink (brittle, headless), we instrument the page: hook ``AudioContext`` and ``HTMLMediaElement``
``play`` so we can tell whether ANY sound was produced — and, with a click target, whether a
*specific* interaction made a sound fire. Heavy + optional (``[render]`` / Chromium).

SECURITY (this is the highest-risk surface — a URL is attacker-controlled):
- the URL host is SSRF-vetted (:func:`audel.netguard.assert_host_safe`) before launch;
- the browser is launched through the DNS-rebinding-proof :class:`audel.proxy.VettingProxy`, so
  every subresource/redirect is re-vetted and pinned to a safe IP;
- the OS sandbox is ON by default and we FAIL CLOSED if it can't be enabled (never silently
  ``--no-sandbox``); downloads are disabled; frames/interval/observe-time are clamped (DoS).
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..config import Settings
from ..errors import MissingDependencyError, UnsafeSourceError
from ..netguard import assert_host_safe
from ..proxy import VettingProxy

# Injected before any page script: records whether sound was produced.
_PROBE_JS = r"""
(() => {
  window.__audel = { audioCtx: 0, played: 0, errors: 0 };
  const AC = window.AudioContext || window.webkitAudioContext;
  if (AC) {
    const orig = AC.prototype.start ? AC.prototype : null;
    window.AudioContext = function(...a){ window.__audel.audioCtx++; return new AC(...a); };
    try { window.AudioContext.prototype = AC.prototype; } catch(e){}
  }
  document.addEventListener('play', () => { window.__audel.played++; }, true);
  window.addEventListener('error', () => { window.__audel.errors++; }, true);
})();
"""


def is_url(source: str) -> bool:
    return urlparse(str(source)).scheme in ("http", "https")


def _launch_args(settings: Settings) -> dict:
    """Browser launch options: sandbox ON by default, downloads off, ALL traffic via the proxy.

    ``--proxy-bypass-list=<-loopback>`` removes loopback from Chromium's implicit proxy-bypass, so
    even a 127.0.0.1 / localhost subresource is forced through the vetting proxy (and refused) —
    without it the proxy could be side-stepped for loopback (SSRF).
    """
    args = ["--disable-dev-shm-usage", "--proxy-bypass-list=<-loopback>"]
    if not settings.chromium_sandbox:
        # Only a trusted/contained env should set this; we never flip it silently.
        args.append("--no-sandbox")
    return {"chromium_sandbox": settings.chromium_sandbox, "args": args}


async def capture_sound(url: str, *, settings: Settings, click_selector: str | None = None,
                        observe_ms: int = 3000) -> dict:
    """Load ``url`` in a sandboxed, proxied browser and report whether sound fired.

    Returns ``{"played": int, "audio_contexts": int, "errors": int, "clicked": bool}``. Raises
    ``UnsafeSourceError`` for an internal URL and ``MissingDependencyError`` without ``[render]``.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeSourceError("watch(url) requires an http(s) URL")
    assert_host_safe(parsed.hostname, parsed.port)  # resolve-time SSRF check

    try:
        from playwright.async_api import async_playwright
    except ImportError as e:  # pragma: no cover - only without the extra
        raise MissingDependencyError("web capture needs Playwright; pip install audel[render]") from e

    observe_ms = max(0, min(observe_ms, settings.watch_max_interval_ms * settings.watch_max_frames))
    proxy = VettingProxy("127.0.0.1", max_connections=settings.proxy_max_connections,
                         idle_timeout_s=settings.proxy_idle_timeout_s)
    await proxy.start()
    try:  # pragma: no cover - requires a real browser
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                proxy={"server": f"http://127.0.0.1:{proxy.port}"}, **_launch_args(settings))
            try:
                ctx = await browser.new_context(accept_downloads=False)
                page = await ctx.new_page()
                await page.add_init_script(_PROBE_JS)
                await page.goto(url, wait_until="load", timeout=settings.request_timeout_s * 1000)
                clicked = False
                if click_selector:
                    try:
                        await page.click(click_selector, timeout=2000)
                        clicked = True
                    except Exception:  # noqa: BLE001
                        clicked = False
                await page.wait_for_timeout(observe_ms)
                state = await page.evaluate("() => window.__audel")
                return {**state, "clicked": clicked}
            finally:
                await browser.close()
    finally:
        await proxy.stop()
