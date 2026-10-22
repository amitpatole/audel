# Changelog

All notable changes to Audel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `SECURITY.md` with a private reporting path and supported-version table.
- `CITATION.cff` and a drift-guard test that pins it, `pyproject` and `__version__` together.
- CI now gates on strict type checking, the no-key demo, and a dependency vulnerability audit.

### Fixed
- MCP adapter works on `mcp` 2.x, where the high-level server moved to `mcp.server.MCPServer`.
  The 1.x import path is still supported.
- Anthropic backend works on `anthropic` 2.x. Sampling parameters were removed from the Messages
  API, so the request now uses `output_config.effort = "low"` and handles a `refusal` stop reason.

### Changed
- Default Anthropic critique model is now `claude-haiku-5-5` (was `claude-haiku-4-5`).

## [0.1.0] - 2026-06-22

First public release.

### Added
- Async `check`, `analyze`, `watch`, `render` and `compute_diff` over audio, video and URLs.
- Deterministic DSP grading: silence, clipping and true peak, integrated loudness against a preset
  target, truncation, dropouts, A/V desync, missing audio, decode errors.
- Local faster-whisper ASR with language, phrase and duration claim grading.
- `analyze` backends: Ollama Cloud text critique, Anthropic, Gemini audio, and CLAP zero-shot sounds.
- `LoopSession`, `GenerativeLoopSession` and an input-addressed workspace.
- `StreamMonitor` for bounded live-stream grading.
- CLI, REST (FastAPI) and MCP adapters, a no-key `audel demo`, and `audel doctor`.
- Security controls: bounded decode, SSRF guard with a DNS-rebind-proof vetting proxy, sandboxed
  headless capture, constant-time bearer auth, fail-closed non-loopback bind.
