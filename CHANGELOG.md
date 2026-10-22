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
- Red-team round 5 fixes (decode and accuracy on real-world files), each pinned by a regression
  test. 21 legitimate professional formats (BWF, RF64, MXF OP1a, MOV pcm24 with timecode, TS, ALAC,
  E-AC-3, files with ID3 and odd chunks, and more) grade with no false integrity findings.
  - **Medium.** Decoder errors were counted from every stream ffmpeg probes, video included, and
    each was counted twice. A cut broadcast capture got a false FAIL, and a clean track was blamed
    for a damaged neighbour. The count now comes from ffmpeg's own per-stream summary for the graded
    stream only.
  - **Medium.** Custom channel masks (`N channels (A+B+...)`, such as surround or LFE stems) aborted
    the grade or were silently remixed. They are now decoded in place and labelled.
  - **Low-Medium.** Missing-packet gaps were closed up by the sample restamp. Packet-timeline gaps
    are now reported at their position (`packet_gap`).
  - **Low-Medium.** CRC-protected codecs (FLAC, AC-3, E-AC-3) hid corruption. CRCs are now checked.
  - **Low.** A delayed-start track was blamed at the wrong time and got a false truncation. Tracks
    are now placed on the programme timeline.
  - **Low.** An MPEG-TS timestamp splice was refused as a duration bomb. TS durations are treated
    as estimates, and the decode cap still fails closed.
  - **Low.** One undecodable track discarded the whole grade. It is now reported by name
    (`track_decode_error`) and the other tracks are graded.
- Red-team round 5 fixes (network surface), each pinned by a regression test:
  - **Medium.** Async jobs took the global grading slot before the tenant's share, and fetched URL
    inputs while holding it. Jobs now fetch first, before any slot, then take the tenant share,
    then a global slot.
  - **Low-Medium.** The download pool was shared without a per-tenant cap. Each tenant may now run
    at most 2 fetches, in a pool of 8.
  - **Low-Medium.** Work abandoned while waiting on its tenant share still ran later. Abandonment now
    propagates through both waits.
- Red-team round 12 fixes (network surface), each pinned by a regression test. A crafted-file
  corpus of 480 grades never produced a busy signal, and a cancellation fuzz of about 1,900
  requests left every slot and counter at baseline.
  - **Low.** Hashing an upload for a job, or writing a URL download, while the host is out of
    file descriptors, memory or disk was reported as a bad file (and the job wrote no audit row).
    Both are now a retry, and audited.
  - **Low.** Speech detection checks the file's deadline between chunks and channels, so it
    can't run past the budget. It reads 1-minute chunks, so memory stays bounded for 24 channels.
- Red-team round 12 fixes (dialogue gating), each pinned by a regression test. 227 files grade
  without new integrity findings under both the default and `netflix` specs.
  - **Medium.** Dialogue in channels a mono downmix drops (the top channels of 7.1.4, most of
    22.2) was never heard, and 5.1 dialogue in antiphase outside L/R cancelled in every pass, so
    a `netflix` grade could pass. Speech is now detected on each channel that matters.
  - **Low-Medium.** Dialogue loudness is now computed from the main pass's own 400 ms loudness
    blocks lying entirely inside speech, with BS.1770 gating. This removes the 200-region cap
    (which turned long programmes into programme loudness), stops speech regions spilling into
    adjacent music (a false FAIL), and drops a decode pass.
  - **Low.** Fewer than 0.4 s of dialogue is reported as `dialogue_unmeasured` instead of reading
    the meter's -70 LUFS floor.
  - **Info.** Opus packet gaps (silence suppression, as in WebRTC recordings) stay a warning.
- Red-team round 12 fixes (auth surface), each pinned by a regression test. No bypass,
  escalation, credential disclosure or log forgery was found.
  - **Low-Medium.** JWT-like floods still cost about 8x ordinary text to scrub. Header checks and
    percent-decoding now share bounded per-call budgets, and the key/value patterns run only when
    a keyword is present (an 8 KB field costs well under a millisecond in the common case).
  - **Low.** A JWT whose first header key was longer than 14 characters escaped; keys up to 32
    printable characters are covered.
  - **Low.** Credentials in Python repr shapes (`b'...'`, header tuples), quoted multi-word values
    and camelCase short keys (`dbPass=`) are redacted.
  - **Low.** Over-redaction that hurt audit and log use is gone: provider keys use their real
    case-sensitive shapes (so names like `aizawa-studios` survive), long legitimate percent-encoded
    URLs are kept, and prose such as `VERDICT PASS: loudness_ok`, `credential: missing` or
    `authorization: required` is not redacted. A client request id that looks like a credential is
    replaced instead of blanked, and uvicorn's own lines keep their arguments.
- Red-team round 11 fixes (network surface), each pinned by a regression test. A real-media leak
  stress (with `netflix` grades, disconnects, deletes and timeouts) returned processes, fds, temp
  files and counters to baseline.
  - **Medium.** On a dialogue-gated spec, a host failure or timeout in speech detection fell back
    to programme loudness silently, which could turn a FAIL into a PASS. Host failures are now a
    retry (429), the deadline refuses, and a track whose dialogue can't be measured is reported
    (`dialogue_unmeasured`).
  - **Medium.** Dialogue in antiphase (one channel inverted) cancelled in the mono mix the speech
    detector hears, so it found no speech and the file passed. Stereo tracks are also heard as
    their side signal, and the regions are united.
  - **Low-Medium.** Work another tenant abandoned could make a request fail as "grading exceeded"
    before it ran. Work slots are now acquired within the queue wait (429), before the request's
    time limit starts.
  - **Low.** File-descriptor, memory or thread exhaustion at the remaining sites (temp files,
    upload spooling, hashing, the header check, URL ingest) is a retry (429) instead of a 500 or a
    silently skipped check. The speech gate runs inside the file's deadline, and pipe handles are
    closed on every error path.
- Red-team round 11 fixes (auth and decode surfaces), each pinned by a regression test:
  - **Medium.** Round 10's narrower log filter skipped messages and arguments that weren't strings
    (an exception, a dict), registered secrets included. Every record except uvicorn's access
    lines is now rendered first and scrubbed as one line, which also covers a keyword in the
    template with its credential in an argument. A template that fails to format no longer prints
    its raw arguments.
  - **Medium.** Nested percent-encodings brought back a costly scrub (about 9x fewer requests per
    second). Runs shorter than any credential shape never reach Python, per-run checks are compiled
    patterns, decoding has a per-call budget past which encoded runs are redacted, and each access
    field is scrubbed once. Hostile text now costs about what ordinary text does.
  - **Low-Medium.** JSON and INI credentials (`"password": "..."`, `api_key = ...`), any
    `Authorization` scheme (`SSWS`, `Splunk`, `AWS4-HMAC-SHA256`), mixed-case bearer tokens,
    values with special characters, signed-URL signatures, JWTs behind glued text or with long,
    hyphenated or pretty-printed headers are redacted. Short keys like `pass` or `sig` match only
    as whole words, so `compass:` and `design:` stay readable.
  - **Low-Medium.** Listed missing-packet gaps totalling more than 10% of a track are now an
    error, matching the spread-loss rule.
- Red-team round 10 fixes (decode and accuracy), each pinned by a regression test. 212 legitimate
  and edge-case files grade with no new integrity findings.
  - **Medium.** Undoing a stray packet's gap also pulled the track's end back, so a sustained decoy
    pattern could erase a hole from the timeline. The track now runs to the latest packet end ever
    seen, which no revert lowers.
  - **Low-Medium.** MP4 files with multi-entry edit lists got a false shortfall (up to a FAIL):
    ffmpeg's preroll packets are flagged as discarded and never decode. Discarded packets are no
    longer on the timeline.
  - **Low-Medium.** Chained Ogg (concatenated links, as in radio dumps) got a false excess. A link
    that restarts at the stream's start continues the timeline.
  - **Low.** ADPCM in AVI got a false duration mismatch: AVI sizes compressed audio by a nominal
    byte rate, so that declared length is not trusted.
  - **Info.** The reason reported for a refused decode skips the decoder's metadata dump.
- Red-team round 10 fixes (network surface), each pinned by a regression test. An attacker can't
  make their own file look like a busy host; every busy signal is host-level.
  - **Medium.** A crafted MPEG-TS with more than 2,000 splices overflowed the splice list, which
    marked the scan incomplete and turned a FAIL (half the audio missing) into a WARN. Folding is
    still exact past the cap, so the scan stays complete and the timeline checks still run.
  - **Low-Medium.** A busy host during the packet scan is now retried (429), not graded as an
    incomplete scan.
  - **Low.** If a pipe-reader thread can't start, the child is killed and reaped and the request
    is retried, instead of a 500 and zombie processes.
  - **Low.** With a dialogue-gated spec (such as `netflix`), one undecodable track no longer
    discards the whole grade; it is reported by name and the others are graded. The speech gate
    uses the same per-stream cap, and decode refusals report the decoder's reason.
  - **Low.** Merging speech regions was quadratic; it is now O(n log n).
  - **Info.** A path made of one long run is no longer blanked from the access log.
- Red-team round 10 fixes (auth surface), each pinned by a regression test:
  - **Medium.** A flood of tiny runs (`%!%!...`) made each byte of an unauthenticated request line
    costly to scrub, cutting throughput about twelvefold. Only runs long enough to hold a
    credential are examined, and decoding happens only where a real `%XX` escape is present (an
    8 KB field now costs under a millisecond).
  - **Low.** Some request lines made the scrubber flatten the access record, which crashed
    uvicorn's access formatter and lost the line. Records are flattened only for a credential that
    spans the template and an argument, and `key=` no longer swallows the protocol after it.
  - **Low.** Names containing "eyJ" (`keyArchive2024.tar.gz`, `surveyAnalytics.s3...`) were
    redacted as JWTs, including audit hostnames. A JWT header must now decode to a JSON object
    key. Prose such as "Bearer authentication required" is no longer redacted; explicit
    assignments (`password=...`) always are.
- Red-team round 9 fixes (decode and network surfaces), each pinned by a regression test. 197
  legitimate and edge-case files grade with no new integrity findings.
  - **Medium.** Decoy packets could capture the stray-packet logic and switch off the round-8
    shortfall check. A jump can now only be undone back to an established clock. A gap can be
    undone only by a packet continuing exactly where the clock left off, which missing audio can
    never supply. Outside MPEG-TS the clock never restarts: a backward step lays audio over earlier
    audio, and the track runs from its earliest packet to its latest end.
  - **Medium.** One crafted upload with millions of timestamp jumps could grow the server's own
    memory by about 800 MB. The jump list is capped (the scan is then reported incomplete): 37 MB
    peak on the same file.
  - **Low-Medium.** Duplicate packets could cancel out missing ones. Audio laid over earlier audio
    is counted and subtracted, except for timestamp rounding (MKV rounds to 1 ms).
  - **Low-Medium.** Legacy AVI times compressed audio by byte position, which gave a false FAIL on
    VBR MP3. AVI's packet extent is no longer trusted for compressed audio.
  - **Low-Medium.** A multi-track file of unknown length (such as a spliced MPEG-TS) was refused by
    the duration budget. Each stream now decodes at most its share of the budget, which still fails
    closed.
  - **Low.** TS tracks are placed on the reference clock by timestamp, tolerating ordinary skew
    between PIDs around a splice.
  - **Low.** An impossible timestamp jump (longer than any file may run) is reported as a corrupt
    timeline (`timestamp_jump`), and more audio decoding than the timeline holds is reported
    (`timeline_excess`). Extents are clamped to the duration cap.
  - **Low.** A busy host no longer silently drops the truncation, spectral or speech-gated passes,
    and `/analyze`, `/handoff`, watch and jobs report it as busy (HTTP 429), never as a bad file. A
    failed thread start leaves no scans running. The CLI exits with 75 when the host is busy, and
    MCP tools return a `busy` result.
  - **Info.** A refused decode now reports the decoder's reason, not its closing statistics.
- Red-team round 9 fixes (auth surface), each pinned by a regression test:
  - **High.** The round-8 redaction patterns were still quadratic on runs such as `_eyJ_eyJ...`,
    so one unauthenticated request could stall the server. Redaction was redesigned to be
    linear by construction: the text is split once into runs, each run is tested with substring
    checks and fixed-length patterns, and a few keyword patterns can't backtrack. Each log field
    is also capped at 8 KB before scrubbing, cut at a run boundary so a credential is never left
    half-visible.
  - **Low.** The round-8 boundary rule let credentials glued to other text (`x=1audel_...`),
    camelCase keys (`accessToken=`), `Authorization: Token ...` and `Bearer` followed by a newline
    through. These are redacted again.
  - **Low.** A percent-encoded credential made the scrubber swap in the decoded line, which could
    forge access-log fields or break JSON. A run is now redacted in its original encoding, and the
    rest of the line is left as it was. Encodings up to five deep are recognised.
  - **Info.** NAT64 clients outside the /96 form are bucketed by /64, the Teredo prefix can't be a
    trusted proxy, and Helm refuses more spellings. Records from asyncio and the root logger, and
    stack traces, are scrubbed too.
- Red-team round 8 fixes (decode and timeline accuracy), each pinned by a regression test. 110
  legitimate and edge-case files grade with no new integrity findings.
  - **Medium.** A dropout of 60 s or more in MP4, MOV or MKV was treated as a timestamp splice and,
    with the header durations edited, graded PASS. Only MPEG-TS/PS splices are folded out now;
    elsewhere a jump is missing audio and is reported as a gap.
  - **Medium.** Missing audio spread through a track (many holes below the gap threshold, or
    packets whose durations are stretched) could grade PASS. A new header-independent check
    compares how long the packet timeline runs with the audio that decodes
    (`timeline_shortfall`).
  - **Low-Medium.** In MPEG-TS, one stray packet far ahead could hide a real gap. A jump that
    returns to the old clock within a few packets is treated as a stray, and the gap is measured
    against the old clock.
  - **Low-Medium.** A second TS audio track starting after a splice was placed a whole splice away
    (a false FAIL). All tracks now share the reference track's clock.
  - **Low.** A TS whose timestamps wrap (negative start time) got a false truncation warning; the
    tail is read from the right place again.
  - **Low.** Video running longer than the audio no longer counts as a duration mismatch in MKV,
    WebM, FLV or ASF, which don't declare per-stream durations (ASF copies the file's).
  - **Low.** Gaps past the first 50 still count toward a track's length (`packet_gap_total`).
  - **Low.** Truncation of compressed WAV (ADPCM, MP3) is no longer sized from a nominal byte
    rate, and A-law/mu-law AIFC truncation is caught.
- Red-team round 8 fixes (auth and network surfaces), each pinned by a regression test:
  - **High.** The JWT redaction pattern added in round 7 backtracked quadratically, so one
    unauthenticated request with a long URL could block the server for seconds while its access
    line was logged. Every redaction pattern is now anchored at a token boundary and can't
    backtrack (64 KB of hostile text scrubs in milliseconds), and each log record is scrubbed once.
  - **Low.** Provider-key and keyword patterns blanked ordinary words (such as `task-0123...`,
    `desk-reporting.example.com`, "token expired") in logs and audit records. They now need a word
    boundary or a `key=value` shape.
  - **Low.** NAT64 prefixes (`64:ff9b::/96`, `64:ff9b:1::/48`) are held to the IPv4 floor, and NAT64
    clients are rate-limited by their own IPv4 address.
  - **Low.** Double-encoded and fully percent-encoded tokens in a URL are redacted. When decoding
    reveals a credential, control characters are escaped so a log line can't be forged.
  - **Low.** A file refused partway now stops its packet scans at once, so they can't outlive the
    grading slot. A scan that prints nothing is still killed on time.
  - **Low.** A job deleted while running is audited as `cancelled`, not `ok`.
  - **Low.** A host that can't start another process returns 429 "retry later" instead of a 500.
  - **Info.** Secrets are excluded from settings dumps, and Helm refuses more spellings of the
    IPv4-mapped and NAT64 ranges.
- Red-team round 7 fixes (decode and timeline accuracy), each pinned by a regression test. The 69
  legitimate and edge-case files still grade with no false integrity findings.
  - **Medium.** Streamed WAVs from GStreamer and arecord use other "unknown length" placeholders
    and got a false truncation FAIL. Any placeholder size is now treated as unknown.
  - **Medium.** Audio starting more than about 5 s into an MKV or TS file got the wrong start
    time, which shifted every finding and hid or invented truncations. Each track now starts at its
    first packet.
  - **Low-Medium.** Truncated BW64, AIFF and CAF files are now caught (`container_truncated`).
  - **Low-Medium.** The missing-packet scan streams the packet list, so long files are read in full
    with flat memory. It handles packets without a duration (TrueHD in MKV) and timestamps that
    jump backwards, and it runs alongside the decode passes inside the per-file budget.
  - **Low-Medium.** Findings after a missing-packet gap were reported early by the gap's length.
    They are now mapped onto the programme timeline past the gap.
  - **Low.** Short clips with two packets no longer get a false gap. Lists of spans move with
    their track. Video running longer than the audio is no longer a duration mismatch, and for
    MPEG-TS the packets are the declaration. Whole-track spans stay inside the programme. The header
    walk is bounded by chunk count and the reported shortfall is clamped.
- Red-team round 7 fixes (network surface), each pinned by a regression test. A leak stress and
  a 20,000-task cancellation fuzz returned every counter to baseline.
  - **Low.** `/render` audited refused or failed requests as `ok` and left out the input digest.
    The audit now records the real outcome and the input's identity.
  - **Low.** An upload that failed mid-write (disk full, cancellation) left a partial file. The
    upload is now removed on any failure, and the service reaps temp files older than a day at
    startup.
  - **Info.** A job refused by the per-tenant download limit said the source couldn't be decoded.
    It now says the server is busy (HTTP 429 on synchronous routes).
- Red-team round 7 fixes (auth surface), each pinned by a regression test. No bypass or
  escalation was found.
  - **Low.** About one minted token in a million failed the structure check, so it would be refused
    at startup. Minting now re-checks its own output, and the run check counts only strictly
    ascending or descending runs.
  - **Low.** A JWT, or a percent-encoded token, misplaced in a URL reached the access log. Both are
    now redacted.
  - **Info.** IPv4-mapped IPv6 ranges are held to the IPv4 floor, so `::ffff:0:0/96` can't trust
    every client. Helm also refuses zero-padded prefixes and netmask forms.
- Red-team round 6 fixes (decode and accuracy), each pinned by a regression test. A fuzz of 350
  byte mutations across 14 codecs confirmed CRC enforcement never loses legitimate audio, and 69
  legitimate and edge-case files grade with no false integrity findings.
  - **Medium.** A dropout remuxed into MP4 or MOV was stored as one long sample and graded PASS.
    Packets far longer than the stream's normal packet are now reported as `packet_gap`.
  - **Low-Medium.** Findings were timed from the earliest audio, not the container start. Broadcast
    TS gaps were reported at their raw timestamps, audio starting after video got a false
    `duration_mismatch`, and the truncation tail was read from the wrong place. Everything is now on
    the programme timeline.
  - **Low-Medium.** A WAV or W64 file cut short in transfer graded PASS, because its length is
    estimated from the bytes present. The header's declared size is now compared with the bytes
    present (`container_truncated`). Streamed files that declare an unknown length are not judged.
  - **Low.** The missing-packet scan now runs inside the per-file time budget, and an incomplete
    scan is reported (`gap_scan_incomplete`) instead of being treated as clean.
- Red-team round 6 fixes (network surface), each pinned by a regression test:
  - **Medium.** Synchronous routes given a URL fetched it while holding a grading slot, and waited
    for the per-tenant fetch share without limit. All grading routes now acquire their input first
    and only then take a slot, and the fetch-share wait is bounded (429).
  - **Low-Medium.** Work abandoned before it started stayed queued with its whole request payload.
    It is now cancelled immediately.
  - **Low.** A download cancelled during proxy shutdown, or before its worker thread created the
    file, could leave a file behind. Both paths now clean up.
  - **Info.** Abandoned-task failures no longer print unscrubbed asyncio tracebacks.
- Red-team round 5 and 6 fixes (auth surface): obviously constructed token bodies (low character
  variety, short repeating periods, alphabet runs) are refused even when wrapped in a valid
  checksum. The format check can't detect a hash of a word, so tokens must be minted with
  `audel token new`. Minted tokens are redacted from logs wherever they appear, including when
  misplaced in a URL. `forwarded_allow_ips` refuses `*`, unparseable entries and networks broader
  than /8 (IPv4) or /32 (IPv6), in config and in Helm.
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
