# Running Audel as a service

`audel serve` runs the REST API (FastAPI and uvicorn, from the `[serve]` extra). Loopback is
zero-config for local development. A routable bind refuses to start without authentication.

```bash
pip install "audel[serve,asr]"
export AUDEL_API_TOKEN="$(audel token new)"
audel serve --host 0.0.0.0 --port 8000
```

## Endpoints

| Method and path | What it does |
|---|---|
| `GET /healthz` | Liveness. The only unauthenticated route. |
| `GET /doctor` | Environment diagnostics: ffmpeg, ASR, backends, local LLM reachability. Admin only. |
| `GET /specs` | Built-in delivery specs. |
| `POST /check` | Deterministic grade: hearing. |
| `POST /listen` | Hearing plus listening. |
| `POST /analyze` | Signals, ASR and backend critique of brief claims. |
| `POST /render` | Signals only, per track. |
| `POST /handoff` | The distilled ears-to-brain handoff. |
| `POST /watch` | Temporal grade of an http(s) page. Off unless `AUDEL_REST_ALLOW_WATCH=true` (refused before the body is read when off). Takes a JSON body of at most 64 KB with a `Content-Length`. |
| `POST /jobs` | Queue `check`, `listen` or `analyze`. Returns `202` and a `job_id`. |
| `GET /jobs`, `GET /jobs/{id}`, `DELETE /jobs/{id}` | Your tenant's jobs. Another tenant's job is a 404. |
| `GET /metrics` | Prometheus metrics. Admin only. |

Every grading route takes **either** a multipart `file` upload **or** a `url`, never both. Every
response carries `X-Request-ID`. Send your own (64 characters at most, `[A-Za-z0-9._-]`) to
correlate with your pipeline, or let Audel generate one.

## Authentication

```bash
audel token new --tenant newsroom           # prints the token once, plus its hash entry
export AUDEL_API_TOKENS_FILE=/etc/audel/tokens.json
export AUDEL_ADMIN_TENANTS='["ops"]'         # who may read /doctor and /metrics
```

Every token, shared or per-tenant, must be minted by `audel token new`. A minted token has the
form `audel_<256 random bits>_<checksum>`. Anything else is refused before it is compared, so a
hand-chosen secret can't be used, even if its hash is put in the tokens file. For OIDC, set `AUDEL_JWT_JWKS_FILE`,
`AUDEL_JWT_ISSUER` and `AUDEL_JWT_AUDIENCE`, and keep the JWKS file synced from your identity
provider. JWT tenants appear as `jwt:<claim>`.

!!! note "Behind a reverse proxy or load balancer"
    List the proxy in `AUDEL_FORWARDED_ALLOW_IPS`, or in the Helm value `forwardedAllowIps`.
    Failed authentication is throttled per client address. Without the setting, every client
    shares the proxy's address and one failure budget. Valid credentials always pass either way.

## Async jobs

```bash
curl -H "Authorization: Bearer $AUDEL_API_TOKEN" \
     -F kind=listen -F spec=ebu_r128 -F file=@ep101.wav \
     -F script="$(cat ep101_script.txt)" http://audel:8000/jobs
# {"job_id": "5f0c…", "status": "queued", "status_url": "/jobs/5f0c…"}

curl -H "Authorization: Bearer $AUDEL_API_TOKEN" http://audel:8000/jobs/5f0c…
# {"status": "done", "result": { …the Report… }}
```

The queue is bounded overall (`AUDEL_MAX_QUEUED_JOBS`, default 64) and per tenant (a quarter of
that by default). The media held on disk is bounded too, overall (`AUDEL_MAX_SPOOL_BYTES`,
default 2 GB) and per tenant (a quarter of that by default): every upload in flight or queued
counts its declared request size (the full request cap when undeclared) from before the body is
read, and every fetched URL counts `AUDEL_MAX_MEDIA_BYTES` until its file is removed. A file stays
counted until the grading that uses it really ends, even when its request timed out or its job was
deleted. The derived per-tenant share always fits one maximum-size request (plus one URL fetch when
URL ingest is on); an explicit `AUDEL_MAX_SPOOL_BYTES_PER_TENANT` below that is logged at start-up. A request
that declares a length and also uses chunked framing is refused. Keep the overall bound below the cache
volume (the Helm chart sets 1.2 GB against its 2Gi `cacheSizeLimit`). Past any bound a
submission gets `429` with a `Retry-After` header. Finished results are kept for `AUDEL_JOB_RESULT_TTL_S` (default 1 hour) and
then purged.

!!! note "Scaling out"
    Job state lives in each process. Synchronous routes scale horizontally behind any load
    balancer. For `/jobs`, either run one replica per queue, or route each tenant's job calls to
    the same replica, or put your own queue in front and call the synchronous routes from workers.

## Grading from object storage

Pipelines usually hand over a signed URL rather than a file. URL ingestion is egress, so it is off
until the operator enables it:

```bash
export AUDEL_ALLOW_URL_INGEST=true
export AUDEL_INGEST_ALLOWED_HOSTS='[".s3.amazonaws.com", ".blob.core.windows.net"]'
curl -H "Authorization: Bearer $AUDEL_API_TOKEN" \
     -F spec=atsc_a85 -F url="https://media.s3.amazonaws.com/ep101.mxf?X-Amz-Signature=…" \
     http://audel:8000/check
```

The rules:

- **Scheme and port.** Only https on port 443 is allowed. Plain http on port 80 needs
  `AUDEL_INGEST_ALLOW_HTTP=true`. URLs with embedded credentials are refused.
- **Host allowlist.** When `AUDEL_INGEST_ALLOWED_HOSTS` is set, the host must match an entry
  exactly, or end with an entry that starts with a dot.
- **Network path.** Every connection goes through Audel's vetting proxy. It resolves the host
  once, refuses private, loopback, link-local and cloud-metadata addresses, and pins the
  connection to the vetted IP, which closes DNS rebinding.
- **Redirects.** At most 3, http(s) only, and every hop is checked against the same rules.
- **Limits.** Downloads stop at `AUDEL_MAX_MEDIA_BYTES` and `AUDEL_INGEST_TIMEOUT_S`.
- **Secrets.** The query string of a signed URL is a secret. Audel logs and audits the host only.

## Observability

`/metrics` sits behind the same auth as everything else:

```text
audel_requests_total{route="/check",status="200"} 1
audel_grades_total{kind="check",verdict="fail"} 1
audel_grade_seconds_bucket{kind="check",le="5"} 1
audel_jobs_inflight 0
audel_jobs_queued 0
```

Route labels come from a fixed set, so unknown paths count as `route="other"` and can't inflate
cardinality.

Set `AUDEL_AUDIT_LOG=/var/log/audel/audit.jsonl` for one JSON record per grade. The file is
created with mode 0600. Records go to the `audel.audit` logger as well.

```json
{"duration_ms": 412, "endpoint": "/check", "input_bytes": 96044,
 "input_sha256": "9c1e…", "issues": 2, "job_id": "5f0c…", "kind": "check",
 "request_id": "req-abc-1", "source": "upload", "spec": "ebu_r128", "status": "ok",
 "tenant": "default", "ts": "2026-10-21T23:40:02Z", "verdict": "fail"}
```

The audit log records hashes and outcomes. It never records media, transcripts, script or
caption text, tokens, or signed-URL query strings.

## Retention

Uploaded and fetched media is written to server-named temp files and deleted when the request or
job finishes, including when a request fails or is cancelled. The service also removes temp files
older than a day each time it starts. `audel purge --hours 24` does the same on demand and reaps
expired loop sessions. Run it from cron or a Kubernetes CronJob for long-lived processes.

## Container

```bash
docker build -t audel:1.0.0rc1 --build-arg EXTRAS=serve,asr --build-arg ASR_MODEL=small .
printf 'AUDEL_API_TOKEN=%s\n' "$AUDEL_API_TOKEN" > audel.env && chmod 600 audel.env
docker run --read-only --tmpfs /tmp -v audel-cache:/var/cache/audel \
  --env-file audel.env -p 8000:8000 audel:1.0.0rc1
```

The image runs as uid 10001 and works with a read-only root filesystem. The whisper model is
downloaded at build time and the runtime is offline for models (`HF_HUB_OFFLINE=1`), so a running
container never fetches code or weights. Without `AUDEL_API_TOKEN` the container exits instead of
serving.

## Kubernetes

A Helm chart lives in `deploy/helm/audel`.

```bash
kubectl create secret generic audel-auth --from-literal=AUDEL_API_TOKEN="$AUDEL_API_TOKEN"
helm install qc deploy/helm/audel --set auth.existingSecret=audel-auth \
  --set env.AUDEL_DELIVERY_SPEC=ebu_r128
```

The chart refuses to render without an auth source. It also refuses `tls.mutual` without
`tls.secretName`, and a `LoadBalancer` or `NodePort` service without TLS unless
`service.allowPlaintext=true`. That can be `auth.existingSecret`, the shared
token; `auth.tokensSecret`, a Secret holding `tokens.json`; or `auth.jwt.jwksConfigMap` with
`issuer` and `audience`. `tls.secretName` serves TLS, and `tls.mutual: true` adds mutual TLS.
`replicaCount` defaults to 1 because async jobs live in each pod's memory. Ingress defaults to
pods in the same namespace, and DNS egress is limited to kube-dns. Pods run non-root with a read-only
root filesystem, all capabilities dropped, the RuntimeDefault seccomp profile, and no
service-account token. A NetworkPolicy denies egress except DNS by default. Add `egressCIDRs`
for an on-prem LLM or an object store.

## Throughput

These figures were measured for 1.0.0rc1 on a shared 4-core host under heavy load (load average
about 14), grading eight 2-minute stereo programmes against `ebu_r128` through `/jobs`:

| `AUDEL_MAX_CONCURRENT_JOBS` | Wall time | Realtime factor | Files per hour |
|---|---|---|---|
| 1 | 22.6 s | 43x | about 1,280 |
| 4 | 16.6 s | 58x | about 1,730 |

Each grade is single-threaded, so set `AUDEL_MAX_CONCURRENT_JOBS` to the number of cores you give
the pod. `listen` adds transcription time, which depends on the whisper model and on whether a
GPU is present.

### Time budget per file

Every file gets one deadline for all of its passes: `AUDEL_DECODE_TIMEOUT_S` plus
`AUDEL_DECODE_TIMEOUT_PER_CHANNEL_S` for each channel-second the file declares. With the defaults,
a 70-minute stereo programme gets 540 s. A file that needs longer is refused rather than graded
partially. Most codecs finish far inside that. Slow lossless formats such as Dolby TrueHD can
reach it on long programmes, especially on a busy host. If you grade long lossless masters, raise
`AUDEL_DECODE_TIMEOUT_PER_CHANNEL_S`, for example to `0.1`, and keep
`AUDEL_MAX_CONCURRENT_JOBS` at your core count.
