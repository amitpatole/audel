"""MCP server — gives any MCP-capable host (Cursor, Claude, …) the audio feedback loop.

Tools return JSON Reports/Handoffs. Unlike the REST surface (remote, untrusted, upload-only), an
MCP host runs locally on the agent's own machine, so a tool ``source`` is a local path graded with
default settings. Loop sessions persist in-process so ``loop_iterate`` continues ``start_loop``.
Heavy/optional: install with ``audel[mcp]``.
"""

from __future__ import annotations

from ..config import load_settings
from ..errors import MissingDependencyError
from ..models import Brief

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - only without the [mcp] extra
    FastMCP = None  # type: ignore

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


def build_server():
    if FastMCP is None:
        raise MissingDependencyError("MCP server needs the mcp package; pip install audel[mcp]")

    mcp = FastMCP("audel")

    @mcp.tool()
    async def check_audio(source: str, brief: str | None = None,
                          expect: list[str] | None = None) -> dict:
        """Deterministically grade an audio/media file (silence/clipping/loudness/truncation).

        No LLM, no network. With brief/expect, also grades transcript claims via OFFLINE local ASR.
        """
        from ..core import check

        report = await check(source, settings=load_settings(), brief=_brief(brief, expect))
        return report.model_dump(mode="json")

    @mcp.tool()
    async def analyze_audio(source: str, brief: str | None = None,
                            expect: list[str] | None = None, backend: str | None = None) -> dict:
        """Full grade: deterministic signals + ASR + backend LLM/CLAP critique (may egress)."""
        from ..core import analyze

        report = await analyze(source, settings=load_settings(), brief=_brief(brief, expect),
                               backend=backend)
        return report.model_dump(mode="json")

    @mcp.tool()
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

    @mcp.tool()
    async def watch_audio(source: str, click_selector: str | None = None) -> dict:
        """Watch a file OR http(s) URL OVER TIME — does the audio play THROUGH (not a glance)?

        Flags silent-though-it-"plays", dropouts, and A/V desync. URL mode is SSRF-guarded.
        """
        from ..core import watch

        report = await watch(source, settings=load_settings(), click_selector=click_selector)
        return report.model_dump(mode="json")

    @mcp.tool()
    async def render_audio(source: str) -> dict:
        """Decode to trustworthy signals (loudness/true-peak/RMS/silent spans); no LLM, no key."""
        from ..core import render

        rr = await render(source, settings=load_settings())
        return {"duration_ms": rr.duration_ms, "channels": rr.channels, "sample_rate": rr.sample_rate,
                "codec": rr.codec, "has_audio": rr.has_audio, "integrated_lufs": rr.integrated_lufs,
                "true_peak_dbtp": rr.true_peak_dbtp, "rms_dbfs": rr.rms_dbfs, "lra": rr.lra,
                "silences": len(rr.silences)}

    @mcp.tool()
    async def diff_audio(baseline: str, candidate: str) -> dict:
        """Grade two clips and report what changed (resolved/introduced/persisted issues)."""
        from ..core import check, compute_diff

        settings = load_settings()
        before = await check(baseline, settings=settings)
        after = await check(candidate, settings=settings)
        return compute_diff(before, after).model_dump(mode="json")

    @mcp.tool()
    async def start_loop(source: str, brief: str | None = None, expect: list[str] | None = None,
                         backend: str | None = None, offline: bool = False) -> dict:
        """Start an audio feedback loop session; returns session_id + first iteration."""
        from ..core.loop import LoopSession

        session = LoopSession(source, settings=load_settings(), backend=backend,
                              brief=_brief(brief, expect), offline=offline)
        _remember(session)
        result = await session.iterate()
        return {"session_id": session.session_id, "iteration": result.model_dump(mode="json")}

    @mcp.tool()
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
