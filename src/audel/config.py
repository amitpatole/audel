"""Configuration for Audel.

Settings resolve from (in order) explicit kwargs → environment (``AUDEL_*`` plus provider keys
under their conventional names) → a per-provider key file → defaults. Credentials are read here
and nowhere else, and are never persisted or logged (every resolved key is registered with the
scrubber). Mirrors AgentVision's config discipline with the ``AUDEL_`` prefix.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import platformdirs
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "audel"

# Default model per text/critique provider. Ollama is the default `analyze` text backend (the
# user's flat-rate cloud Max plan); Anthropic-Haiku is the cheap fallback; Gemini-audio is the
# opt-in audio-native critique model.
DEFAULT_MODELS = {
    "ollama": "gemma4:31b",
    "anthropic": "claude-haiku-4-5",
    "gemini_audio": "gemini-2.0-flash",
}

# Conventional key-file fallbacks (used only if the env var is unset). Match the user's layout
# under ~/.config; provider casing follows each provider's directory convention.
KEY_FILES = {
    "ollama": Path.home() / ".config" / "ollama" / "key",
    "anthropic": Path.home() / ".config" / "Anthropic" / "key",
    "gemini": Path.home() / ".config" / "Google" / "key",
    "deepgram": Path.home() / ".config" / "Deepgram" / "key",
    "groq": Path.home() / ".config" / "Groq" / "key",
    "assemblyai": Path.home() / ".config" / "AssemblyAI" / "key",
}


class LoudnessTarget(str, Enum):
    """Integrated-loudness targets (LUFS). ``podcast`` (−16) is the default."""

    STREAMING = "streaming"      # -14 LUFS (Spotify/YouTube/Apple)
    PODCAST = "podcast"          # -16 LUFS (default)
    BROADCAST_EBU = "broadcast_ebu"  # -23 LUFS (EBU R128)
    BROADCAST_US = "broadcast_us"    # -24 LKFS (ATSC A/85)

    @property
    def lufs(self) -> float:
        return {
            "streaming": -14.0, "podcast": -16.0,
            "broadcast_ebu": -23.0, "broadcast_us": -24.0,
        }[self.value]


def default_cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir(APP_NAME))


class Settings(BaseSettings):
    """Runtime settings. Environment prefix: ``AUDEL_``.

    Provider API keys use their conventional env names (not the prefix) so they match what the
    provider SDKs already expect.
    """

    model_config = SettingsConfigDict(
        env_prefix="AUDEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,  # aliased fields (api_token, provider keys) settable by name too,
        #                         so programmatic callers/tests can set them, not only via env.
    )

    # Backend selection
    audio_backend: str | None = Field(default=None, description="ollama|anthropic|gemini-audio|local")
    ollama_model: str = DEFAULT_MODELS["ollama"]
    ollama_base_url: str = "https://ollama.com/v1"
    anthropic_model: str = DEFAULT_MODELS["anthropic"]
    gemini_audio_model: str = DEFAULT_MODELS["gemini_audio"]

    # Provider credentials (conventional names; never logged/persisted)
    ollama_api_key: str | None = Field(default=None, validation_alias="OLLAMA_API_KEY")
    anthropic_api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    google_api_key: str | None = Field(default=None, validation_alias="GOOGLE_API_KEY")
    deepgram_api_key: str | None = Field(default=None, validation_alias="DEEPGRAM_API_KEY")
    groq_api_key: str | None = Field(default=None, validation_alias="GROQ_API_KEY")
    assemblyai_api_key: str | None = Field(default=None, validation_alias="ASSEMBLYAI_API_KEY")

    # ASR (local faster-whisper)
    asr_model: str = "base"            # whisper size; pinned name only (no arbitrary download path)
    asr_language: str | None = None    # None = autodetect

    # Loudness / DSP grading
    loudness_target: LoudnessTarget = LoudnessTarget.PODCAST
    silence_dbfs: float = -50.0        # below this RMS = silence
    clipping_dbtp: float = -1.0        # true-peak ceiling (dBTP) above which we flag clipping

    # Realtime streaming (Phase 7) — bounded buffers + backpressure for live grading.
    stream_window_s: float = 3.0       # rolling window the "current" RMS/peak is measured over
    max_stream_chunk_s: float = 5.0    # a single feed() longer than this is refused (backpressure)
    max_stream_spans: int = 1000       # cap recorded dropout spans (bound memory on a long stream)
    stream_dropout_min_s: float = 0.2  # interior silence ≥ this = a dropout (mid-stream gap)

    # Decode resource caps (untrusted media → ffmpeg). Enforced BEFORE decode (Phase 1).
    max_media_bytes: int = 200_000_000      # 200 MB byte cap before handing a file to ffmpeg
    max_duration_s: float = 3 * 60 * 60      # 3h duration cap (decompression-bomb bound)
    max_sample_rate: int = 192_000           # reject absurd sample rates
    max_channels: int = 64                    # reject channel-count bombs (broadcast tops out ~16)
    decode_timeout_s: float = 120.0          # hard timeout on the ffmpeg subprocess
    ffmpeg_path: str | None = None           # explicit ffmpeg binary; else auto-detected

    # watch() temporal bounds (Phase 4)
    watch_frames: int = 10
    watch_interval_ms: int = 500
    watch_max_frames: int = 120
    watch_max_interval_ms: int = 10_000

    # Web capture isolation (Phase 4)
    chromium_sandbox: bool = True
    block_private_networks: bool = True
    allow_local_files: bool = True           # REST sets False (no host-file reads from remote)
    proxy_max_connections: int = 64
    proxy_idle_timeout_s: float = 30.0

    # HTTP service (REST): bind + auth + DoS bounds (Phase 6)
    api_token: str | None = Field(default=None, validation_alias="AUDEL_API_TOKEN")
    max_request_bytes: int = 50_000_000      # cap request bodies before buffering/decoding
    max_concurrent_jobs: int = 4
    request_timeout_s: float = 180.0
    # Backends a REMOTE caller may name per-request. Empty = none selectable, so analyze() over REST
    # uses only the server's configured default (a remote caller can't redirect egress or pick a
    # paid model). Loopback/CLI is unaffected. Set e.g. ["local"] to permit explicit offline ASR.
    rest_enabled_backends: list[str] = Field(default_factory=list)

    # Workspace
    cache_dir: Path = Field(default_factory=default_cache_dir)
    session_ttl_s: float = 60 * 60 * 24 * 7  # 7 days

    def model_for(self, backend: str) -> str:
        return {
            "ollama": self.ollama_model,
            "anthropic": self.anthropic_model,
            "gemini-audio": self.gemini_audio_model,
        }.get(backend, "")

    def key_for(self, backend: str) -> str | None:
        """Resolve a provider credential: env → key file → None. Registers the value for scrubbing.

        Never silently downgrades: callers that require a backend should raise BackendAuthError
        when this returns None rather than falling back to a weaker grade.
        """
        key = {
            "ollama": self.ollama_api_key,
            "anthropic": self.anthropic_api_key,
            "gemini": self.google_api_key,
            "gemini-audio": self.google_api_key,
            "deepgram": self.deepgram_api_key,
            "groq": self.groq_api_key,
            "assemblyai": self.assemblyai_api_key,
        }.get(backend)
        if not key:
            f = KEY_FILES.get(backend if backend != "gemini-audio" else "gemini")
            if f and f.exists():
                try:
                    key = f.read_text().strip() or None
                except OSError:
                    key = None
        if key:
            from .logging import register_secret

            register_secret(key)
        return key


def load_settings(**overrides) -> Settings:
    """Build a Settings object, applying any explicit overrides last."""
    s = Settings(**{k: v for k, v in overrides.items() if v is not None})
    if s.api_token:
        from .logging import register_secret

        register_secret(s.api_token)
    return s
