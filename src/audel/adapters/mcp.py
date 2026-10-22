"""MCP server — gives any MCP-capable host (Cursor, Claude, …) the audio feedback loop.

Tools return JSON Reports/Handoffs. Unlike the REST surface (remote, untrusted, upload-only), an
MCP host runs locally on the agent's own machine, so a tool ``source`` is a local path graded with
default settings. Loop sessions persist in-process so ``loop_iterate`` continues ``start_loop``.
Heavy/optional: install with ``audel[mcp]``.
"""

from __future__ import annotations

from typing import Any

from ..config import load_settings
from ..errors import MissingDependencyError
from ..models import Brief

FastMCP: Any
try:  # mcp >= 2: the high-level server is ``mcp.server.MCPServer``
    from mcp.server import MCPServer as FastMCP
except ImportError:  # pragma: no cover - mcp 1.x layout, or the extra is absent
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[attr-defined,no-redef]
    except ImportError:
        FastMCP = None

_MAX_SESSIONS = 64
_sessions: dict = {}


def _remember(session) -> None:
    """Track a loop session, bounding total memory in a long-lived server (FIFO eviction)."""
    _sessions[session.session_id] = session
    while len(_sessions) > _MAX_SESSIONS:
        del _sessions[next(iter(_sessions))]  # dict preserves insertion order → drop the oldest


def _brief(brief: str | None, expect: list[str] | None) -> Brief | None:
    if not (brief or expect):
        return None
    b = Brief.from_inputs(text=brief, expect=expect)
    return None if b.is_empty() else b


def _builtin(spec: str | None):
    """Tool arguments come from an agent (possibly prompt-injected): built-in spec NAMES only."""
    if not spec:
        return None
    from ..specs import builtin_spec

    return builtin_spec(spec)


def _settings(content: str | None):
    if content and content not in ("speech", "music", "mixed"):
        from ..errors import ConfigError

        raise ConfigError("content must be speech, music or mixed")
    return load_settings(content_type=content) if content else load_settings()


def _busy_safe(decorator):
    """Wrap an MCP tool so a busy host is reported as such (retry), not as a generic error."""
    import functools

    from ..errors import BusyError

    def wrap(fn):
        @functools.wraps(fn)
        async def inner(*a, **k):
            try:
                return await fn(*a, **k)
            except BusyError as e:
                return {"error": "busy", "retry": True, "detail": str(e)}

        return decorator(inner)

    return wrap


def build_server():
    if FastMCP is None:
        raise MissingDependencyError("MCP server needs the mcp package; pip install audel[mcp]")

    mcp = FastMCP("audel")

    @_busy_safe(mcp.tool())
    async def check_audio(source: str, brief: str | None = None,
                          expect: list[str] | None = None, spec: str | None = None,
                          content: str | None = None) -> dict:
        """Deterministically grade an audio/media file against a delivery spec.

        Checks loudness (integrated, short-term, momentary, LRA), true peak, clipping, silence,
        truncation, dead / inverted / out-of-phase channels, DC offset, hum and noise floor, on
        every audio track. ``spec`` is a built-in name (ebu_r128, ebu_r128_s1, atsc_a85, op59,
        arib_tr_b32, netflix, spotify, youtube, apple_music, apple_podcasts, podcast); ``content``
        is speech, music or mixed. No LLM, no network. With brief/expect, also grades transcript
        claims via OFFLINE local ASR.
        """
        from ..core import check

        report = await check(source, settings=_settings(content), brief=_brief(brief, expect),
                             spec=_builtin(spec))
        return report.model_dump(mode="json")

    @_busy_safe(mcp.tool())
    async def listen_audio(source: str, script: str | None = None, captions: str | None = None,
                           require: list[str] | None = None, forbid: list[str] | None = None,
                           key_messages: list[str] | None = None, tone: str | None = None,
                           understand: bool = False, backend: str | None = None,
                           spec: str | None = None, content: str | None = None) -> dict:
        """Hear AND listen to an audio/media file.

        Hearing: the full deterministic signal check (see check_audio). Listening (offline,
        local ASR): script adherence with time-grounded omissions/substitutions (pass the script
        TEXT), required/forbidden wording, speech rate, dead-air pauses, hard-to-make-out
        stretches, and caption conformance (pass SRT/WebVTT TEXT). With understand=True, a model
        also judges key messages, the listener takeaway and the delivery tone; ollama-local keeps
        that on the operator's network.
        """
        from ..core import listen

        report = await listen(source, settings=_settings(content), spec=_builtin(spec),
                              script=script, captions=captions, required=require,
                              forbidden=forbid, key_messages=key_messages, tone=tone,
                              understand=understand, backend=backend)
        return report.model_dump(mode="json")

    @mcp.tool()
    async def list_specs() -> list[dict]:
        """The built-in delivery specs (loudness target, tolerance, true-peak ceiling, gating)."""
        from ..specs import BUILTIN_SPECS

        return [s.model_dump(mode="json") for s in BUILTIN_SPECS.values()]

    @_busy_safe(mcp.tool())
    async def analyze_audio(source: str, brief: str | None = None,
                            expect: list[str] | None = None, backend: str | None = None) -> dict:
        """Full grade: deterministic signals + ASR + backend LLM/CLAP critique (may egress)."""
        from ..core import analyze

        report = await analyze(source, settings=load_settings(), brief=_brief(brief, expect),
                               backend=backend)
        return report.model_dump(mode="json")

    @_busy_safe(mcp.tool())
    async def perceive_handoff(source: str, brief: str | None = None,
                               expect: list[str] | None = None, backend: str | None = None) -> dict:
        """The ears→brain handoff: grade and return the distilled signal.

        Returns {perceived, next_action, matches_intent, summary, todo[], open_questions[]} — what
        the brain should do next: 'done', 'revise' (act on todo), or 'review'.
        """
        from ..core import analyze

        report = await analyze(source, settings=load_settings(), brief=_brief(brief, expect),
                               backend=backend)
        return report.to_handoff().model_dump(mode="json")

    @_busy_safe(mcp.tool())
    async def watch_audio(source: str, click_selector: str | None = None) -> dict:
        """Watch a file OR http(s) URL OVER TIME — does the audio play THROUGH (not a glance)?

        Flags silent-though-it-"plays", dropouts, and A/V desync. URL mode is SSRF-guarded.
        """
        from ..core import watch

        report = await watch(source, settings=load_settings(), click_selector=click_selector)
        return report.model_dump(mode="json")

    @_busy_safe(mcp.tool())
    async def render_audio(source: str) -> dict:
        """Decode to trustworthy signals (loudness/true-peak/RMS/silent spans); no LLM, no key."""
        from ..core import render

        rr = await render(source, settings=load_settings())
        return {"duration_ms": rr.duration_ms, "channels": rr.channels, "sample_rate": rr.sample_rate,
                "codec": rr.codec, "has_audio": rr.has_audio, "integrated_lufs": rr.integrated_lufs,
                "true_peak_dbtp": rr.true_peak_dbtp, "rms_dbfs": rr.rms_dbfs, "lra": rr.lra,
                "silences": len(rr.silences)}

    @_busy_safe(mcp.tool())
    async def diff_audio(baseline: str, candidate: str) -> dict:
        """Grade two clips and report what changed (resolved/introduced/persisted issues)."""
        from ..core import check, compute_diff

        settings = load_settings()
        before = await check(baseline, settings=settings)
        after = await check(candidate, settings=settings)
        return compute_diff(before, after).model_dump(mode="json")

    @_busy_safe(mcp.tool())
    async def start_loop(source: str, brief: str | None = None, expect: list[str] | None = None,
                         backend: str | None = None, offline: bool = False) -> dict:
        """Start an audio feedback loop session; returns session_id + first iteration."""
        from ..core.loop import LoopSession

        session = LoopSession(source, settings=load_settings(), backend=backend,
                              brief=_brief(brief, expect), offline=offline)
        _remember(session)
        result = await session.iterate()
        return {"session_id": session.session_id, "iteration": result.model_dump(mode="json")}

    @_busy_safe(mcp.tool())
    async def loop_iterate(session_id: str, source: str | None = None) -> dict:
        """Continue a loop session after the agent fixes the audio."""
        session = _sessions.get(session_id)
        if session is None:
            return {"error": f"unknown session_id {session_id!r}"}
        result = await session.iterate(source)
        return {"session_id": session_id, "iteration": result.model_dump(mode="json"),
                "stop_reason": session.stop_reason}

    @mcp.tool()
    def doctor() -> dict:
        """Report ffmpeg / ASR / CLAP / Chromium readiness and which backends have credentials."""
        from .doctor import run_checks

        return {"checks": [{"name": c.name, "ok": c.ok, "detail": c.detail}
                           for c in run_checks(load_settings())]}

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
