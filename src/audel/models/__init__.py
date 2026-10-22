"""Audel data models.

Built on the shared :mod:`agentsensory` contract (re-exported here) plus the *audio* specialisation:
the closed ``IssueKind`` / ``IssueSource`` enums and the ``Issue`` / ``Report`` subclasses. Audio
issues are **time-grounded** via ``span`` (where the eyes use ``bbox``). Because both senses derive
from agentsensory, Audel's ``Handoff`` is schema-identical to AgentVision's.
"""

from __future__ import annotations

from enum import Enum

from agentsensory import (
    BBox,
    Brief,
    ClaimResult,
    ClaimStatus,
    Confidence,
    Conformance,
    Handoff,
    Importance,
    IntentClaim,
    IssueBase,
    NextAction,
    ReportBase,
    Sense,
    Severity,
    Span,
    Verdict,
    verdict_from_issues,
)
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    # shared contract (re-exported)
    "Verdict", "Severity", "Confidence", "Importance", "ClaimStatus",
    "BBox", "Span", "Brief", "IntentClaim", "ClaimResult", "Conformance",
    "Handoff", "NextAction", "Sense", "verdict_from_issues",
    # audio specialisation
    "IssueKind", "IssueSource", "Issue", "Report", "TrackSummary", "ListeningSummary",
    "DeliveryReading",
]


class IssueKind(str, Enum):
    """Time-grounded audio issue kinds."""

    SILENCE = "silence"
    CLIPPING = "clipping"
    LOUDNESS = "loudness"
    TRUNCATION = "truncation"
    DROPOUT = "dropout"
    DECODE_ERROR = "decode_error"
    MISSING_AUDIO = "missing_audio"
    DESYNC = "desync"
    TRANSCRIPT_MISMATCH = "transcript_mismatch"
    WRONG_LANGUAGE = "wrong_language"
    NOISE = "noise"
    CHANNEL_ISSUE = "channel_issue"
    DURATION = "duration"
    INTENT_MISMATCH = "intent_mismatch"
    OTHER = "other"


class IssueSource(str, Enum):
    """Who detected the issue (audio analog of AgentVision's IssueSource)."""

    DSP = "dsp"            # deterministic signal analysis (the trustworthy grounding)
    ASR = "asr"            # speech-to-text / language detection
    ACOUSTIC = "acoustic"  # CLAP / non-speech zero-shot
    AUDIO_LLM = "audio_llm"  # audio-native or transcript-fed LLM critique


class Issue(IssueBase):
    """An audio issue: ``kind``/``source`` narrowed to the audio enums; grounded in time (span)."""

    kind: IssueKind
    source: IssueSource = IssueSource.DSP


class TrackSummary(BaseModel):
    """Per-audio-stream measurements, flat and JSON-safe (non-finite levels become ``None``)."""

    model_config = ConfigDict(extra="forbid")

    index: int
    codec: str = ""
    channels: int = 0
    sample_rate: int = 0
    layout: str = ""
    language: str | None = None
    title: str | None = None
    integrated_lufs: float | None = None
    dialogue_lufs: float | None = None
    dialogue_coverage: float | None = None
    lra: float | None = None
    true_peak_dbtp: float | None = None
    max_momentary_lufs: float | None = None
    max_short_term_lufs: float | None = None
    rms_dbfs: float | None = None


class DeliveryReading(BaseModel):
    """What an audio-capable model heard in one excerpt (advisory)."""

    model_config = ConfigDict(extra="forbid")

    start_ms: int
    end_ms: int
    delivery: str = ""
    pace: str = ""
    intelligibility: str = ""
    note: str = ""


class ListeningSummary(BaseModel):
    """The listening layer: what was said and how well it can be followed."""

    model_config = ConfigDict(extra="forbid")

    language: str | None = None
    language_confidence: float | None = None
    words: int = 0
    speech_s: float = 0.0
    wpm: float | None = None
    longest_pause_s: float = 0.0
    mean_word_confidence: float | None = None
    low_confidence_ratio: float | None = None
    transcript: str = Field(default="", description="Transcript text (capped).")
    script_words: int | None = None
    script_adherence: float | None = None
    script_wer: float | None = None
    terms: dict[str, bool] = Field(default_factory=dict)
    caption_cues: int | None = None
    caption_matched_ratio: float | None = None
    caption_median_drift_ms: int | None = None
    caption_max_cps: float | None = None
    uncaptioned_speech_s: float | None = None
    track_languages: dict[str, str] = Field(default_factory=dict)
    takeaway: str | None = None
    delivery: list[DeliveryReading] = Field(default_factory=list)
    understood_by: str | None = None


class Report(ReportBase):
    """An audio report: shared fields + the decode/grading-specific surface."""

    issues: list[Issue] = Field(default_factory=list)  # type: ignore[assignment]
    conformance: Conformance | None = Field(
        default=None,
        description="Per-requirement grading vs the intended product, when a brief is given.",
    )
    capabilities: list[IssueKind] = Field(
        default_factory=list,
        description="Which IssueKinds the producing backend is able to emit.",
    )
    sample_rate: int | None = None
    channels: int | None = None
    duration_ms: int | None = None
    audio_path: str | None = Field(
        default=None, description="Server-relative artifact id/path; adapters project it."
    )
    spec: str | None = Field(default=None, description="Delivery spec the audio was graded against.")
    tracks: list[TrackSummary] = Field(default_factory=list,
                                       description="Per-audio-stream measurements.")
    listening: ListeningSummary | None = Field(
        default=None, description="What was said and how well it can be followed (listen()).")

    @property
    def artifact_path(self) -> str | None:
        """Generic artifact accessor the shared Handoff distiller reads."""
        return self.audio_path
