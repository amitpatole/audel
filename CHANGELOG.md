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
- **Async jobs.** `POST /jobs` takes `check`, `listen` or `analyze` and returns 202 with a job id.
  `GET` and `DELETE /jobs/{id}` work on your tenant's jobs only. The queue is bounded and returns
  429 with `Retry-After` when full. Results expire after a TTL.
- **URL ingestion** for object-store and signed URLs (`AUDEL_ALLOW_URL_INGEST`, off by default).
  It is https-only, limited to ports 80 and 443, honours an optional host allowlist, routes
  through the vetting proxy, re-checks every redirect hop, and is byte- and time-capped.
- Prometheus `GET /metrics`, `X-Request-ID` on every response, and a JSON-lines audit log
  (`AUDEL_AUDIT_LOG`) that holds hashes and outcomes only.
- `audel purge` for crash leftovers and retention.
- Production Dockerfile: the model is baked in, the runtime is offline for models, it works with
  a read-only root filesystem, and it fails closed without a token. A hardened Helm chart lives in
  `deploy/helm/audel`.
- `AUDEL_ASR_MODEL_DIR` for pre-downloaded whisper models.
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
- Red-team round 1 fixes, each pinned by a regression test:
  - **High.** Uploaded HLS or ffconcat playlists could make ffmpeg read other media files on the
    host. Every decode now runs with `-protocol_whitelist file` and a demuxer allowlist, and temp
    files keep only known media extensions.
  - **Medium.** Tenants from different credential sources shared one namespace. JWT tenants are
    now `jwt:<claim>`, and `default` is reserved.
  - **Medium.** A JWT whose algorithm did not match the key type caused a 500 that the lockout
    did not count. Keys are now filtered by type, and the error is a 401.
  - **Medium.** The failed-auth lockout keyed on the client address and ran before credentials,
    so it could lock out every tenant behind a NAT or load balancer. Valid credentials now always
    pass, and only failures are throttled. IPv6 is grouped by /64.
  - **Medium.** A `.env` in the working directory could redirect the Ollama cloud key. No `.env`
    is read unless `AUDEL_ENV_FILE` names one, and the cloud key is sent only over https and never
    to an on-prem host.
  - **Medium.** Decode-failure reports echoed server temp paths. Messages are now sanitized.
  - **Medium.** `/healthz` read request bodies, and the middleware buffered whole bodies. The cap
    is now enforced on the stream, and `/healthz` reads nothing.
  - **Medium.** A cancelled or timed-out job freed its concurrency slot while the work kept
    running. Slots are now held until the work ends.
  - **Low.** `/doctor` and `/metrics` are admin-only, and `/doctor` honours the egress policy.
  - **Low.** `X-Forwarded-For` is trusted only from `AUDEL_FORWARDED_ALLOW_IPS`.
  - **Low.** Shared tokens shorter than 32 characters are refused, and a tenant rate of 0 is
    rejected.
  - **Low.** The workspace is 0700. Uploads and the audit log are 0600, created without following
    symlinks.
  - **Low.** `/watch` over REST is opt-in (`AUDEL_REST_ALLOW_WATCH`), WebRTC UDP is disabled in
    capture, and the vetting proxy allows ports 80 and 443 only.
  - **Low.** IPv6 NAT64, 6to4 and Teredo addresses are unwrapped before SSRF checks.
  - **Low.** Job error strings are sanitized.
  - **Deploy.** Helm ingress defaults to the same namespace, DNS egress goes to kube-dns only,
    token, JWKS and TLS mounts are supported, and the default is one replica. The Dockerfile base
    is pinned by digest, and GitHub Actions are pinned to commit SHAs.
- Red-team round 2 fixes (auth surface), each pinned by a regression test:
  - **Medium.** A throttled address still had every guess evaluated, so the right token got 200.
    A throttled address is now refused (429) before its credential is evaluated. Shared tokens
    also need about 128 bits of estimated entropy, not just 32 characters.
  - **Medium.** One tenant could fill the global job queue and evict other tenants' results. The
    queue and the result store now have per-tenant fair shares, and a tenant's own oldest result is
    evicted first.
  - **Medium.** Helm rendered a plaintext deployment for `tls.mutual` without a certificate. It now
    refuses that, and refuses LoadBalancer or NodePort without TLS unless explicitly allowed.
  - **Low.** Trusted-host comparison is canonical (IPv4-mapped, decimal or hex IPv4, trailing dot).
  - **Low.** JWKS keys whose `key_ops` exclude `verify` are no longer used.
  - **Low.** Duplicate token hashes across tenants are rejected.
  - **Low.** Logged tracebacks are scrubbed of secrets.
  - **Low.** The docs build excludes local-only files.
  - **Low.** The OG-image workflow no longer holds a write token while it installs third-party
    packages, and its docs and OG dependencies are pinned.
- **Per-tenant tokens.** `AUDEL_API_TOKENS_FILE` holds SHA-256 hashes only, and
  `audel token new` mints a token. All tenant hashes are compared in constant time on every
  request.
- **OIDC JWT authentication** (`[oidc]` extra) against a local JWKS. Only asymmetric algorithms
  are accepted. `iss`, `aud`, `exp` and `iat` are required, lifetime is capped, and the tenant is
  read from a claim.
- **Rate limits.** Token buckets apply per tenant (`AUDEL_RATE_LIMIT_PER_MIN`, with per-tenant
  overrides). After `AUDEL_AUTH_FAIL_PER_MIN` failed attempts, an address gets 429 before
  credentials are checked, so a correct guess stays hidden.
- **Egress policy.** `AUDEL_EGRESS` is `allow`, `local-only` (trusted on-prem hosts only) or
  `deny` (fully offline). It is enforced at every egress point, and also stops model downloads.
- **TLS and mutual TLS** on `audel serve` (`AUDEL_TLS_CERTFILE`, `AUDEL_TLS_KEYFILE`,
  `AUDEL_TLS_CLIENT_CA`).
- **Bounded CLAP input.** CLAP scoring now decodes at most two minutes through mediaguard.
  Before this it loaded the whole file into memory.
- Published threat model: `docs/security.md`.
- Backend HTTP calls refuse redirects and cap the response size before parsing.
- Backend URLs with embedded credentials are refused.

### Removed
- The unused `DEEPGRAM_API_KEY`, `GROQ_API_KEY` and `ASSEMBLYAI_API_KEY` settings. No backends
  for them existed.

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
