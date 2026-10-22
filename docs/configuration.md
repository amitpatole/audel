# Configuration

Every setting is an environment variable. Most take the `AUDEL_` prefix; provider keys use their
conventional names. Lists are JSON, for example `AUDEL_TRUSTED_BACKEND_HOSTS='["10.0.0.100"]'`.
No `.env` file is read unless `AUDEL_ENV_FILE` names one. Provider keys can also live in
`~/.config/<Provider>/key`.

This page is generated from the `Settings` model by `scripts/gen_config_docs.py`, so names
and defaults match the code. A test fails if it goes stale.

## Delivery and hearing

| Variable | Default |
|---|---|
| `AUDEL_DELIVERY_SPEC` | — |
| `AUDEL_CONTENT_TYPE` | — |
| `AUDEL_LOUDNESS_TARGET` | `podcast` |
| `AUDEL_SILENCE_DBFS` | `-50.0` |
| `AUDEL_CLIPPING_DBTP` | `-1.0` |
| `AUDEL_ANALYZE_ALL_TRACKS` | `True` |
| `AUDEL_HUM_DETECTION` | `True` |
| `AUDEL_NOISE_FLOOR_DBFS` | `-50.0` |

## Listening

| Variable | Default |
|---|---|
| `AUDEL_ASR_MODEL` | `base` |
| `AUDEL_ASR_LANGUAGE` | — |
| `AUDEL_ASR_DEVICE` | `auto` |
| `AUDEL_ASR_COMPUTE_TYPE` | `auto` |
| `AUDEL_ASR_MODEL_DIR` | — |
| `AUDEL_LISTEN_MIN_WPM` | `110.0` |
| `AUDEL_LISTEN_MAX_WPM` | `190.0` |
| `AUDEL_LISTEN_MAX_PAUSE_S` | `3.0` |
| `AUDEL_LISTEN_LOW_CONF` | `0.45` |
| `AUDEL_LISTEN_EXCERPT_S` | `30.0` |
| `AUDEL_LISTEN_MAX_EXCERPTS` | `3` |
| `AUDEL_CAPTION_MAX_CPS` | `20.0` |
| `AUDEL_CAPTION_MAX_DRIFT_MS` | `1000` |

## Model backends

| Variable | Default |
|---|---|
| `AUDEL_AUDIO_BACKEND` | — |
| `AUDEL_OLLAMA_MODEL` | `gemma4:31b` |
| `AUDEL_OLLAMA_BASE_URL` | `https://ollama.com/v1` |
| `AUDEL_ANTHROPIC_MODEL` | `claude-haiku-5-5` |
| `AUDEL_GEMINI_AUDIO_MODEL` | `gemini-2.0-flash` |
| `OLLAMA_API_KEY` | — |
| `ANTHROPIC_API_KEY` | — |
| `GOOGLE_API_KEY` | — |
| `AUDEL_LOCAL_LLM_URL` | — |
| `AUDEL_LOCAL_LLM_MODEL` | `gemma4:12b-it-qat` |
| `AUDEL_LOCAL_LLM_AUDIO` | `True` |
| `AUDEL_LOCAL_LLM_TIMEOUT_S` | `180.0` |
| `AUDEL_TRUSTED_BACKEND_HOSTS` | `[]` |

## Egress

| Variable | Default |
|---|---|
| `AUDEL_EGRESS` | `allow` |
| `AUDEL_ALLOW_URL_INGEST` | `False` |
| `AUDEL_INGEST_ALLOW_HTTP` | `False` |
| `AUDEL_INGEST_ALLOWED_HOSTS` | `[]` |
| `AUDEL_INGEST_TIMEOUT_S` | `300.0` |
| `AUDEL_BLOCK_PRIVATE_NETWORKS` | `True` |

## Service and auth

| Variable | Default |
|---|---|
| `AUDEL_API_TOKEN` | — |
| `AUDEL_API_TOKENS_FILE` | — |
| `AUDEL_JWT_JWKS_FILE` | — |
| `AUDEL_JWT_ISSUER` | — |
| `AUDEL_JWT_AUDIENCE` | — |
| `AUDEL_JWT_ALGORITHMS` | `['RS256', 'ES256']` |
| `AUDEL_JWT_TENANT_CLAIM` | `tenant` |
| `AUDEL_JWT_LEEWAY_S` | `30` |
| `AUDEL_JWT_MAX_LIFETIME_S` | `86400` |
| `AUDEL_ADMIN_TENANTS` | `[]` |
| `AUDEL_RATE_LIMIT_PER_MIN` | `120` |
| `AUDEL_RATE_LIMIT_BURST` | — |
| `AUDEL_AUTH_FAIL_PER_MIN` | `30` |
| `AUDEL_TLS_CERTFILE` | — |
| `AUDEL_TLS_KEYFILE` | — |
| `AUDEL_TLS_CLIENT_CA` | — |
| `AUDEL_FORWARDED_ALLOW_IPS` | `[]` |
| `AUDEL_REST_ENABLED_BACKENDS` | `[]` |
| `AUDEL_REST_ALLOW_UNDERSTAND` | `False` |
| `AUDEL_REST_ALLOW_WATCH` | `False` |

## Limits

| Variable | Default |
|---|---|
| `AUDEL_MAX_REQUEST_BYTES` | `50000000` |
| `AUDEL_MAX_MEDIA_BYTES` | `200000000` |
| `AUDEL_MAX_DURATION_S` | `10800` |
| `AUDEL_MAX_SAMPLE_RATE` | `192000` |
| `AUDEL_MAX_CHANNELS` | `64` |
| `AUDEL_MAX_AUDIO_STREAMS` | `32` |
| `AUDEL_MAX_TOTAL_AUDIO_S` | `14400` |
| `AUDEL_MAX_TOTAL_CHANNEL_S` | `172800` |
| `AUDEL_DECODE_TIMEOUT_S` | `120.0` |
| `AUDEL_DECODE_TIMEOUT_PER_AUDIO_S` | `0.5` |
| `AUDEL_REQUEST_TIMEOUT_S` | `180.0` |
| `AUDEL_MAX_CONCURRENT_JOBS` | `4` |
| `AUDEL_MAX_CONCURRENT_UPLOADS` | — |
| `AUDEL_BODY_READ_TIMEOUT_S` | `60.0` |
| `AUDEL_QUEUE_WAIT_S` | `120.0` |
| `AUDEL_MAX_INFLIGHT_PER_TENANT` | — |
| `AUDEL_MAX_INFLIGHT_TOTAL` | — |
| `AUDEL_MAX_QUEUED_JOBS` | `64` |
| `AUDEL_MAX_STORED_JOBS` | `1000` |
| `AUDEL_MAX_QUEUED_JOBS_PER_TENANT` | — |
| `AUDEL_MAX_STORED_JOBS_PER_TENANT` | — |
| `AUDEL_JOB_RESULT_TTL_S` | `3600.0` |

## Operations

| Variable | Default |
|---|---|
| `AUDEL_AUDIT_LOG` | — |
| `AUDEL_METRICS_ENABLED` | `True` |
| `AUDEL_CACHE_DIR` | `platform user cache dir` |
| `AUDEL_SESSION_TTL_S` | `604800` |
| `AUDEL_FFMPEG_PATH` | — |

## Streaming, watch and capture

| Variable | Default |
|---|---|
| `AUDEL_STREAM_WINDOW_S` | `3.0` |
| `AUDEL_MAX_STREAM_CHUNK_S` | `5.0` |
| `AUDEL_MAX_STREAM_SPANS` | `1000` |
| `AUDEL_STREAM_DROPOUT_MIN_S` | `0.2` |
| `AUDEL_WATCH_FRAMES` | `10` |
| `AUDEL_WATCH_INTERVAL_MS` | `500` |
| `AUDEL_WATCH_MAX_FRAMES` | `120` |
| `AUDEL_WATCH_MAX_INTERVAL_MS` | `10000` |
| `AUDEL_CHROMIUM_SANDBOX` | `True` |
| `AUDEL_ALLOW_LOCAL_FILES` | `True` |
| `AUDEL_PROXY_MAX_CONNECTIONS` | `64` |
| `AUDEL_PROXY_IDLE_TIMEOUT_S` | `30.0` |
