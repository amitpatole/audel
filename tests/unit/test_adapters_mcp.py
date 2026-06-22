"""Phase 6: the MCP server registers the expected tools and a tool delegates to the core API."""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from audel.adapters.mcp import build_server  # noqa: E402

_EXPECTED = {"check_audio", "analyze_audio", "perceive_handoff", "watch_audio", "render_audio",
             "diff_audio", "start_loop", "loop_iterate", "doctor"}


def test_server_registers_expected_tools():
    tools = asyncio.run(build_server().list_tools())
    assert {t.name for t in tools} == _EXPECTED


def test_check_audio_tool_grades_a_fixture(media):
    # The tool is the offline check path: a good clip grades PASS, a silent clip FAILs.
    server = build_server()
    good = asyncio.run(server.call_tool("check_audio", {"source": str(media["good"])}))
    silent = asyncio.run(server.call_tool("check_audio", {"source": str(media["silent"])}))

    def _verdict(result):
        # FastMCP returns (content_blocks, raw) or content; normalize to the JSON payload.
        payload = result[1] if isinstance(result, tuple) else result
        if isinstance(payload, dict):
            return payload["verdict"]
        text = payload[0].text if isinstance(payload, list) else payload.content[0].text
        return json.loads(text)["verdict"]

    assert _verdict(good) == "pass"
    assert _verdict(silent) == "fail"


def test_session_store_is_bounded():
    # R3: a long-lived server must not grow loop sessions without bound (FIFO eviction at the cap).
    from types import SimpleNamespace

    from audel.adapters import mcp as mcp_mod

    mcp_mod._sessions.clear()
    for i in range(mcp_mod._MAX_SESSIONS + 25):
        mcp_mod._remember(SimpleNamespace(session_id=f"s{i}"))
    assert len(mcp_mod._sessions) == mcp_mod._MAX_SESSIONS
    assert "s0" not in mcp_mod._sessions and f"s{mcp_mod._MAX_SESSIONS + 24}" in mcp_mod._sessions
    mcp_mod._sessions.clear()
