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
- Red-team round 5 fixes (auth surface): a character-variety floor on token bodies, so patterned
  bodies are refused even when wrapped in a valid checksum, and an honest description of what the
  format check proves. Minted tokens are redacted from logs wherever they appear, including when
  misplaced in a URL. `forwarded_allow_ips` refuses `*` in config and in Helm.
- Red-team round 4 fixes (decode and measurement surface), each pinned by a regression test:
  - **High.** A forward timestamp jump larger than the duration cap ended decoding early, because
    `-t` counts timestamps, so the audio after it was never measured and a clipping file could PASS.
    Decoding now restamps by sample count before the cap.
  - **Medium.** A truncated secondary track passed. Each track is now compared with the programme
    (`short_track`) and graded on its own decoded length.
  - **Medium.** Decoder errors were ignored when ffmpeg still exited 0, so corrupt or dropped
    packets could PASS. They are now counted and reported as `decode_errors`, and the
    duration-mismatch tolerance is tightened to 1 s or 2%.
  - **Medium.** Immersive and custom layouts (5.1.2, 5.1.4, 7.1.4, 22.2, `FL+FR+LFE+...`) lost their
    LFE label, giving false dead-channel FAILs. Channel names now come from FFmpeg's own layout
    table, and every LFE channel is recognised.
  - **Low.** Worker time per upload is tighter. The default channel-second budget is now 3 h of 7.1,
    and the per-file deadline is based on channel-seconds (`AUDEL_DECODE_TIMEOUT_PER_CHANNEL_S`).
  - **Info.** The frame-log cap follows the configured maximum duration.
- Red-team round 4 fixes (network and input surface), each pinned by a regression test:
  - **Medium.** A trickling upstream defeated the ingest deadline and leaked download threads from
    the shared executor, which stopped grading for every tenant. Each receive is now bounded by the
    time remaining, the vetting proxy has an absolute connection lifetime and cancels live
    connections on stop, and downloads run in their own small pool.
  - **Medium.** The global grading slot was taken before the per-tenant share, so one tenant could
    starve others. The tenant's share is now taken first, and each wait is bounded, returning 429
    (`AUDEL_QUEUE_WAIT_S`).
  - **Medium.** Requests waiting for a slot held their parsed uploads in temp storage without
    limit. Grading requests are now admitted before their bodies are read, with caps per tenant and
    overall (`AUDEL_MAX_INFLIGHT_PER_TENANT`, `AUDEL_MAX_INFLIGHT_TOTAL`).
  - **Low-Medium.** `/render` skipped the per-tenant work share. It now applies.
  - **Low-Medium.** The per-tenant intake check raced its semaphore. The share is now reserved
    before waiting.
  - **Low.** Per-tenant semaphore maps now clean themselves up when idle.
- Red-team round 4 fixes (auth surface), each pinned by a regression test:
  - **Medium.** The shape-based token check accepted chosen secrets, such as sentences or a hash of
    "password", and tenant-file hashes could not be checked at all, so guessing was bounded only by
    throughput. Tokens are now minted only by `audel token new`, in the form
    `audel_<256 random bits>_<checksum>`. Anything not in that format is refused before comparison,
    including a password whose hash is placed in the tokens file. The checksum is public, so the
    format catches typos and non-minted values but cannot prove randomness: always mint.
    **Breaking:** regenerate tokens with `audel token new`. Running it without `--tenant` prints a
    shared `AUDEL_API_TOKEN`.
  - **Low-Medium.** In Helm, a `tls.mutual` of `"True"` or `"yes"` silently disabled mTLS. Values are
    now normalised, and anything other than true or false fails.
  - **Low.** Log scrubbing collapsed record args and broke uvicorn's access-log lines. Arguments are
    now scrubbed in place, and the scrubber is installed through uvicorn's own log config so it
    survives startup.
- Red-team round 3 fixes (decode and measurement surface), each pinned by a regression test:
  - **High.** A stream that changed sample rate or channel count mid-file was silently resampled
    and downmixed to its first frame's format, which hid most of the audio, so a defective file
    could PASS. Decoding now refuses mid-stream format changes (`-reinit_filter 0`).
  - **Medium.** Round 2's `-ac N` remixed non-default channel layouts, causing false dead-channel
    findings and hiding the real dead channel. Channel layouts are now kept as-is. Unordered layouts
    pass through untouched, and more standard layouts are labelled.
  - **Medium.** Cheap uploads (high sample rate, many channels, no declared duration) could tie up a
    worker for about an hour. Analysis runs at no more than 48 kHz, an unknown duration counts as the
    maximum, there is a channel-second budget (`AUDEL_MAX_TOTAL_CHANNEL_S`), and one deadline covers
    the whole file.
  - **Low-Medium.** Audio beyond the duration cap went unmeasured when the container understated its
    length. Reaching the cap now fails closed, and a declared duration that disagrees with the
    decoded audio is reported, with grading done on the decoded audio.
  - **Low.** A duration lie could hide truncation. The tail is now read from the decoded end.
  - **Low.** Unordered many-channel audio aborted the grade. It is now graded.
  - **Fixed.** Silent loudness frames (`-nan`) were dropped by the frame parser.
- Red-team round 3 fixes (network and input surface), each pinned by a regression test:
  - **Medium.** An authenticated slow sender could hold every body-intake slot and block uploads
    for all tenants. The slot is now released as soon as the body is read. There is a body-read
    deadline that returns 408 (`AUDEL_BODY_READ_TIMEOUT_S`), and each tenant may hold at most half
    the intake slots.
  - **Medium.** The vetting proxy's per-direction idle timeout cut long downloads, and the
    truncated file was graded. Idleness is now judged on both directions together, and a download
    shorter than its `Content-Length` is refused.
  - **Low-Medium.** `/handoff` returned the server path of the upload. It now returns the input's
    SHA-256.
  - **Low.** A Unicode digit in a `language` index (`²=es`) caused a 500. It now returns 400.
  - **Low.** Deleting a running job freed the tenant's share while its work kept running. Running
    work now has a per-tenant share that is held until the work really ends.
- Red-team round 3 fixes (auth surface), each pinned by a regression test:
  - **Medium.** Round 2's pre-authentication lockout let one unauthenticated client lock out valid
    users sharing its address. Credentials must now be generated: a shared token must match
    `openssl rand -hex 32` or `audel token new` output, and patterned strings are refused. Valid
    credentials always pass, and only failures are throttled. The Helm chart gains a
    `forwardedAllowIps` value.
  - **Low.** The OG-image workflow is now split. Third-party code renders with a read-only token,
    and a separate job commits with hooks disabled.
  - **Low.** The scrubber redacts overlapping secrets longest-first, catches base64 bearer tokens,
    and covers uvicorn's loggers. Settings `repr` hides secrets.
  - **Info.** `canonical_host` normalizes short and hex IPv4 forms, IDNA names and IPv6 zone ids.
  - **Info.** Helm booleans passed as strings can't dodge the TLS rules.
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
- Red-team round 2 fixes (network and input surface), each pinned by a regression test:
  - **Medium.** Listening analysis ran on the event loop, so one large caption or script stalled
    every tenant. It now runs in a worker thread. Caption matching uses a bisect window with a
    comparison budget, and very large script alignments are windowed. All of it stays bounded.
  - **Medium.** Deleting a queued job leaked its spooled upload. Cleanup now runs on every job
    exit, including cancellation while queued.
  - **Low-Medium.** A cancelled URL fetch leaked its partial download and kept its thread running.
    The download now stops and is removed.
  - **Low-Medium.** In-flight form bodies were unbounded in aggregate. Body intake is
    concurrency-limited, with slots taken only after authentication
    (`AUDEL_MAX_CONCURRENT_UPLOADS`), and list fields are capped.
  - **Low.** The message sanitizer now redacts registered server roots exactly, plus Windows,
    percent-encoded and IPv6 forms, server temp names and ffmpeg pointer addresses.
  - **Low.** `/render` and `/handoff` now go through the grading timeout and the audit log.
- Red-team round 2 fixes (decode and resource surface), each pinned by a regression test:
  - **High.** ffmpeg printed container metadata into the same stderr the measurement parsers read,
    so two crafted tags could turn a FAIL into a PASS and a malformed tag could crash `check`.
    Every measurement pass is now a two-process pipeline. Untrusted decode goes to raw float PCM,
    and analysis runs on PCM that carries no metadata. Parsers tolerate malformed numbers.
  - **Medium.** Stream-count amplification. There is now a total-audio budget, streams times
    duration (`AUDEL_MAX_TOTAL_AUDIO_S`).
  - **Medium.** Tool stderr was buffered without a cap. Every subprocess now uses bounded readers.
  - **Medium.** Repetitive script and transcript pairs made alignment take minutes. Alignment now
    uses smaller windows under a wall-clock budget, and truncation is reported.
  - **Medium/Low.** ASR loaded the whole programme into memory (1.7 GB for 3 h). Transcription now
    runs in 10-minute chunks, peaking at about 160 MB for 3 h.
  - **Low.** Temp WAVs leaked on ffmpeg timeout. They are now removed on every exit and created
    inside the private workspace.
  - **Low.** Term search is indexed: at the caps it now takes 0.3 s instead of 17 s.
  - **Low.** Bench `labels.json` specs are built-in names only, and a NUL in a file name is a
    config error.
  - **Fixed.** Real 3-hour broadcast masters exceeded the fixed 120 s decode timeout. Timeouts now
    scale with declared duration (`AUDEL_DECODE_TIMEOUT_PER_AUDIO_S`).
  - **Fixed.** An empty audio stream was reported as 0 dBTP clipping. It is now reported as an
    empty stream.
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
