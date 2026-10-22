# Changelog

All notable changes to Audel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Delivery specs as data.** Built-in EBU R128, R128 s1, ATSC A/85, OP-59, ARIB TR-B32,
  Netflix-style speech-gated, Spotify, YouTube, Apple Music, Apple Podcasts and podcast specs, plus
  operator JSON specs. Select with `--spec`, `spec=`, or `AUDEL_DELIVERY_SPEC`. `audel specs` and
  `GET /specs` list them.
- Spec grading of short-term and momentary loudness maxima and LRA ceilings, with time-grounded
  spans for every passage over the limit.
- Speech-gated loudness for dialogue-gated specs, using the Silero VAD in the `[asr]` extra.
- Every audio track is graded, with a per-track summary in `Report.tracks` and the spec name in
  `Report.spec`.
- Per-channel checks: dead channel, polarity inversion, phase, and DC offset.
- Mains hum detection at 50 and 60 Hz, and a noise-floor check for speech content.
- `detail.check` names the precise rule on every DSP finding.
- `audel qc` writes a self-contained HTML QC report for operators, with JSON alongside.
- **`listen()`: hearing plus listening.** It runs the full `check`, then grades what was said
  from a word-timed local transcript. That covers script adherence with time-grounded omissions,
  substitutions and ad-libs, required and forbidden wording, speech rate and rushed passages,
  dead-air pauses, hard-to-make-out stretches, and expected language per track.
- Caption conformance for SRT and WebVTT: text, consistent offset, per-cue timing, reading rate,
  uncaptioned speech, and malformed cues.
- Opt-in understanding (`understand=True`): key-message claims, a listener takeaway, and
  delivery and tone heard by an audio-capable model.
- `ollama-local` backend for on-prem inference. Audio-native listening was verified with
  `gemma4:12b-it-qat` on Ollama 0.34. An operator `AUDEL_TRUSTED_BACKEND_HOSTS` allowlist is the
  only way a backend URL may reach a private address.
- ASR word timestamps, `AUDEL_ASR_DEVICE` (`auto`, `cpu` or `cuda`) and `AUDEL_ASR_COMPUTE_TYPE`.
- `audel listen` CLI, `POST /listen` (understanding is operator opt-in via
  `AUDEL_REST_ALLOW_UNDERSTAND`), and the MCP tool `listen_audio`. `audel doctor` reports
  local-LLM reachability.
- `audel bench` measures precision and recall per check, on a synthetic labelled corpus or on your
  own labelled corpus.
- `SECURITY.md` with a private reporting path and supported-version table.
- `CITATION.cff` and a drift-guard test that pins it, `pyproject` and `__version__` together.
- CI now gates on strict type checking, the no-key demo, and a dependency vulnerability audit.

### Fixed
- Local ASR no longer depends on PyAV's file loader, which broke with PyAV 19. Audel feeds
  faster-whisper the samples it already decoded with ffmpeg.
- MCP adapter works on `mcp` 2.x, where the high-level server moved to `mcp.server.MCPServer`.
  The 1.x import path is still supported.
- Anthropic backend works on `anthropic` 2.x. Sampling parameters were removed from the Messages
  API, so the request now uses `output_config.effort = "low"` and handles a `refusal` stop reason.

### Security
- Backend HTTP calls refuse redirects and cap the response size before parsing.
- Backend URLs with embedded credentials are refused.

### Changed
- `audel doctor` no longer lists Deepgram, Groq or AssemblyAI. No backends for them exist.
- Truncation now requires the tail to sit near programme level, so a steady noise or hum tail no
  longer reads as a cut.
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
