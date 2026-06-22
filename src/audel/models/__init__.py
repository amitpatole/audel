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
from pydantic import Field

__all__ = [
    # shared contract (re-exported)
    "Verdict", "Severity", "Confidence", "Importance", "ClaimStatus",
    "BBox", "Span", "Brief", "IntentClaim", "ClaimResult", "Conformance",
    "Handoff", "NextAction", "Sense", "verdict_from_issues",
    # audio specialisation
    "IssueKind", "IssueSource", "Issue", "Report",
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

    @property
    def artifact_path(self) -> str | None:
        """Generic artifact accessor the shared Handoff distiller reads."""
        return self.audio_path
