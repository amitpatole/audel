# Security and threat model

Audel takes untrusted media, can fetch URLs, can drive a headless browser, and can send audio or
transcripts to a model provider. This page lists what it protects, where the trust boundaries
are, and the control for each threat. To report a vulnerability, see
[SECURITY.md](https://github.com/amitpatole/audel/blob/main/SECURITY.md).

## Assets

- **The media itself.** Unreleased programmes, embargoed news and client masters.
- **What the media says.** Transcripts, scripts and captions.
- **Credentials.** API tokens, provider keys, TLS keys.
- **The host.** Its filesystem, internal network, cloud metadata and compute.
- **Grading integrity.** A report must reflect the media actually graded.

## Trust boundaries

| Boundary | Untrusted side |
|---|---|
| Media decode | every byte of every file, including container metadata |
| REST and MCP callers | every request field; REST callers are remote |
| Transcripts and captions | text that can contain instructions aimed at a model |
| Outbound network | URLs supplied by callers, and DNS answers |
| Model output | anything a backend returns |

## Threats and controls

| Threat | Control |
|---|---|
| Decompression or resource bombs in media | Byte, duration, sample-rate, channel, stream-count, total-audio and channel-second caps run **before** decode. A missing duration counts as the maximum. Analysis runs at no more than 48 kHz, and one deadline covers the whole file. Timeouts scale with declared duration. Tool stderr is read through bounded buffers, and transcription runs in 10-minute chunks, so memory stays flat. ffmpeg runs in argv form with no shell, a wall-clock timeout and `RLIMIT_AS` / `RLIMIT_CPU` / `RLIMIT_FSIZE`. Decoding is capped with `-t` even when the container lies about its length. |
| Option or path injection through a source name | Sources are resolved, must be regular files, and may not start with `-` or contain control characters. The REST service never accepts a path. |
| Hostile container metadata (track titles, language tags) | Tags are truncated to 64 characters and filtered to a safe charset before reaching a report, log or HTML page. |
| Forging measurements through metadata or format tricks | The untrusted file is decoded in one ffmpeg process, quietly, into raw float PCM. That process keeps the stream's own channel layout and refuses a stream that changes format mid-file. Durations and the truncation tail come from the decoded audio, not the container's claims, and audio that reaches the duration cap fails closed. A second ffmpeg process measures that raw stream, so it never sees a container, a tag or any attacker text. Only the second process's output is parsed. Parsers also tolerate malformed numbers instead of crashing. |
| Script injection in the HTML QC report | Every value is HTML-escaped. A Content-Security-Policy forbids scripts and external loads. |
| SSRF through URLs (`watch`, URL ingestion, backends) | Private, loopback, link-local, CGNAT, multicast, reserved and cloud-metadata addresses are refused. Connections go through a vetting proxy that resolves once and pins the TCP connection to the vetted IP, which closes DNS rebinding. Ingestion is https-only on ports 80 and 443, honours an optional host allowlist, and re-validates every redirect hop. Backend calls refuse redirects. |
| Reaching an internal service through a misconfigured backend | A backend URL reaches a private address only when the operator lists that exact host in `AUDEL_TRUSTED_BACKEND_HOSTS`. Metadata and link-local addresses are refused even then. |
| Unwanted egress of sensitive media | `AUDEL_EGRESS=deny` makes Audel fully offline. `local-only` permits only operator-trusted on-prem hosts. Both stop model downloads too. `check` and offline `listen` never use the network under any setting. Understanding over REST is off unless the operator enables it. |
| Prompt injection from transcripts and captions | Transcripts are delimited, delimiter look-alikes are neutralised, and the model is told never to follow instructions inside them. Model output is parsed against closed vocabularies and kept advisory. It never overrides a deterministic finding. |
| Unauthenticated access | Every route except `/healthz` is authenticated in middleware **before** the body is read. A routable bind without credentials refuses to start, and so does the container. The Helm chart refuses to render without an auth secret. |
| Credential theft from the server | Per-tenant tokens are stored as SHA-256 hashes only. The workspace is 0700, and uploads and the audit log are 0600, opened without following symlinks. Provider keys come from the environment or `~/.config` and are scrubbed from logs. No default secrets exist. |
| Token brute force and timing attacks | Every comparison is constant time, and every tenant hash is compared on every request. Tokens must be minted by `audel token new`, in the form `audel_<256 random bits>_<checksum>`. Anything else is refused before comparison, so a chosen secret is unusable even when its hash is placed in the tokens file. JWTs are signatures. Online guessing is therefore infeasible. Failed attempts are throttled per client address, with IPv6 grouped by /64. A valid credential always passes, so one client can't lock out users who share its address. |
| Forged identity tokens | JWTs are verified against a local JWKS with asymmetric algorithms only, so `alg: none` and HS256 key confusion fail. A key is used only when its type matches the token's algorithm. `iss`, `aud`, `exp` and `iat` are required, lifetime is capped, and the tenant claim must be a plain identifier. |
| One tenant starving another | Each tenant gets a fair share of the job queue and of stored results (`AUDEL_MAX_QUEUED_JOBS_PER_TENANT`, `AUDEL_MAX_STORED_JOBS_PER_TENANT`). A tenant's churn evicts its own oldest results, never another tenant's. |
| Cross-tenant data access | Async jobs belong to the submitting tenant. Anyone else gets the same 404 as for a missing job. Tenants are namespaced by credential source: a JWT tenant `newsroom` is `jwt:newsroom` and can never equal a token tenant, and `default` is reserved for the shared token. |
| Spoofed client addresses | `X-Forwarded-For` is ignored unless the operator lists trusted proxies in `AUDEL_FORWARDED_ALLOW_IPS`. |
| Hostile working directory | No `.env` file is read implicitly. Set `AUDEL_ENV_FILE` to use one. The Ollama cloud key is only ever sent over https, and never to an on-prem host. |
| Diagnostics disclosure | `/doctor` and `/metrics` are admin-only when auth is on: the shared-token principal and `AUDEL_ADMIN_TENANTS`. Everyone else gets 404. |
| Media that references other files | ffmpeg and ffprobe run with `-protocol_whitelist file` and a demuxer allowlist, so playlists and concat lists such as HLS, DASH and ffconcat are refused and can't make ffmpeg read other files. Server temp files keep only known media extensions. |
| Headless browser escapes (`watch`) | Over REST it is off unless `AUDEL_REST_ALLOW_WATCH=true`. Chromium runs sandboxed with all traffic through the vetting proxy, which allows ports 80 and 443 only, and WebRTC UDP that would bypass the proxy is disabled. |
| Pathological text (scripts, captions, terms) | Alignment is windowed under a wall-clock budget. Caption matching uses bisect windows with a comparison budget, term search is indexed, and any truncation is reported. All of it runs off the event loop. |
| Denial of service | Body size is capped on the header and enforced on the stream as it arrives, without buffering the whole body. A body must arrive within a deadline (408). Body intake is concurrency-limited, with at most half the slots per tenant, and a slot is released as soon as its body is read. `/healthz` never reads a body. A concurrency limit applies to grading, with a per-tenant share. A slot stays held until the work really finishes, even after a timeout or cancel, and work abandoned before it started is skipped. The job queue is bounded with 429 backpressure, rate limits apply per tenant, and every in-memory map is bounded. |
| Leaking secrets or server internals in responses and logs | Errors and decode-failure reports are sanitized, and paths and addresses are replaced with `<path>`. The server-side `audio_path` is stripped from responses. Signed-URL query strings are never logged or audited. Audit records hold hashes and outcomes, never content. |
| Supply chain: arbitrary model loading | Whisper and CLAP model names come from closed allowlists. Containers bake models in at build time and run with `HF_HUB_OFFLINE=1`. CI runs `pip-audit`. |
| Network sniffing | `serve` supports TLS and mutual TLS (`AUDEL_TLS_CERTFILE`, `AUDEL_TLS_KEYFILE`, `AUDEL_TLS_CLIENT_CA`). |

## Hardening checklist for operators

1. Run the container, or the Helm chart, as shipped: non-root, read-only root filesystem, all
   capabilities dropped, seccomp, and no service-account token.
2. Use per-tenant tokens or JWT rather than one shared token, and rotate them.
3. Terminate TLS at Audel, or at a gateway on a private network segment. Use mutual TLS between
   pipeline services where you can.
4. Set `AUDEL_EGRESS=local-only` or `deny` for unreleased content. Keep URL ingestion off unless a
   pipeline needs it, and then set `AUDEL_INGEST_ALLOWED_HOSTS`.
5. Keep the default-deny egress NetworkPolicy. Open only the CIDRs you need.
6. Ship `AUDEL_AUDIT_LOG` to your log platform, and alert on 401 and 429 rates.
7. Run `audel purge` on a schedule.

## What no audit removes

These controls were each tested against a working exploit, and every fix is pinned by a
regression test. Independent adversarial review rounds were run until a full round found nothing
new. Even so, ffmpeg and its codecs, the Python runtime and its dependencies, the operating system
and kernel, and any model provider you enable remain inside your trust boundary. Treat Audel as one
layer of defence, not the only one.
