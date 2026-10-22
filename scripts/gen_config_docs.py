"""Regenerate docs/configuration.md from the Settings model (run after adding a setting).

    python scripts/gen_config_docs.py            # write
    python scripts/gen_config_docs.py --check    # exit 1 if the page is stale (used by a test)
"""

from __future__ import annotations

import sys
from pathlib import Path

from audel.config import Settings

GROUPS = [
    ("Delivery and hearing", ["delivery_spec", "content_type", "loudness_target", "silence_dbfs",
                              "clipping_dbtp", "analyze_all_tracks", "hum_detection",
                              "noise_floor_dbfs"]),
    ("Listening", ["asr_model", "asr_language", "asr_device", "asr_compute_type", "asr_model_dir",
                   "listen_min_wpm", "listen_max_wpm", "listen_max_pause_s", "listen_low_conf",
                   "listen_excerpt_s", "listen_max_excerpts", "caption_max_cps",
                   "caption_max_drift_ms"]),
    ("Model backends", ["audio_backend", "ollama_model", "ollama_base_url", "anthropic_model",
                        "gemini_audio_model", "ollama_api_key", "anthropic_api_key",
                        "google_api_key", "local_llm_url", "local_llm_model", "local_llm_audio",
                        "local_llm_timeout_s", "trusted_backend_hosts"]),
    ("Egress", ["egress", "allow_url_ingest", "ingest_allow_http", "ingest_allowed_hosts",
                "ingest_timeout_s", "block_private_networks"]),
    ("Service and auth", ["api_token", "api_tokens_file", "jwt_jwks_file", "jwt_issuer",
                          "jwt_audience", "jwt_algorithms", "jwt_tenant_claim", "jwt_leeway_s",
                          "jwt_max_lifetime_s", "admin_tenants", "rate_limit_per_min",
                          "rate_limit_burst", "auth_fail_per_min", "tls_certfile", "tls_keyfile",
                          "tls_client_ca", "forwarded_allow_ips", "rest_enabled_backends",
                          "rest_allow_understand", "rest_allow_watch"]),
    ("Limits", ["max_request_bytes", "max_media_bytes", "max_duration_s", "max_sample_rate",
                "max_channels", "max_audio_streams", "max_total_audio_s", "max_total_channel_s",
                "decode_timeout_s",
                "decode_timeout_per_audio_s", "decode_timeout_per_channel_s", "request_timeout_s",
                "max_concurrent_jobs", "max_concurrent_uploads", "body_read_timeout_s", "queue_wait_s",
                "max_inflight_per_tenant", "max_inflight_total", "max_queued_jobs",
                "max_stored_jobs",
                "max_queued_jobs_per_tenant",
                "max_stored_jobs_per_tenant", "job_result_ttl_s"]),
    ("Operations", ["audit_log", "metrics_enabled", "cache_dir", "session_ttl_s", "ffmpeg_path"]),
    ("Streaming, watch and capture", ["stream_window_s", "max_stream_chunk_s", "max_stream_spans",
                                      "stream_dropout_min_s", "watch_frames", "watch_interval_ms",
                                      "watch_max_frames", "watch_max_interval_ms",
                                      "chromium_sandbox", "allow_local_files",
                                      "proxy_max_connections", "proxy_idle_timeout_s"]),
]
PAGE = Path(__file__).resolve().parents[1] / "docs" / "configuration.md"


def _env(fields, n: str) -> str:
    a = fields[n].validation_alias
    return a if isinstance(a, str) else f"AUDEL_{n.upper()}"


def _default(fields, n: str) -> str:
    if n == "cache_dir":
        return "platform user cache dir"
    d = fields[n].get_default(call_default_factory=True)
    return "" if d is None else (str(d.value) if hasattr(d, "value") else str(d))


def render() -> str:
    fields = Settings.model_fields
    out = ["# Configuration", "",
           "Every setting is an environment variable. Most take the `AUDEL_` prefix; provider keys "
           "use their",
           "conventional names. Lists are JSON, for example "
           "`AUDEL_TRUSTED_BACKEND_HOSTS='[\"10.0.0.100\"]'`.",
           "No `.env` file is read unless `AUDEL_ENV_FILE` names one. Provider keys can also live in",
           "`~/.config/<Provider>/key`.", "",
           "This page is generated from the `Settings` model by `scripts/gen_config_docs.py`, so names",
           "and defaults match the code. A test fails if it goes stale.", ""]
    used: set[str] = set()
    for title, names in GROUPS:
        out += [f"## {title}", "", "| Variable | Default |", "|---|---|"]
        for n in names:
            used.add(n)
            d = _default(fields, n).replace("|", "\\|")
            out.append(f"| `{_env(fields, n)}` | {'`' + d + '`' if d else '—'} |")
        out.append("")
    missing = [n for n in fields if n not in used]
    if missing:
        raise SystemExit(f"settings not placed in a group: {missing}")
    return "\n".join(out)


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        sys.exit(0 if PAGE.read_text() == text else 1)
    PAGE.write_text(text)
