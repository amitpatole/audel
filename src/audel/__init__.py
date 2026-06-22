"""Audel — Ears for AI Agents 👂

A machine-graded audio feedback loop coding agents consume to self-correct before claiming an
audio/voice/media task done: play → hear → report → (fix) → re-play. The audio sibling of
AgentVision (eyes) and Verel (brain).

The top-level import is dependency-light. Heavy entry points (ffmpeg/DSP, ASR, CLAP, Playwright)
are exposed lazily via ``__getattr__`` so ``import audel`` always works, even on a bare server.
"""

from __future__ import annotations

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
    NextAction,
    Severity,
    Span,
    Verdict,
)

from .config import LoudnessTarget, Settings, load_settings
from .errors import (
    AudelError,
    BackendAuthError,
    BackendError,
    ConfigError,
    DecodeError,
    MissingDependencyError,
    UnsafeSourceError,
)
from .models import Issue, IssueKind, IssueSource, Report

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Settings", "load_settings", "LoudnessTarget",
    "AudelError", "UnsafeSourceError", "DecodeError", "MissingDependencyError",
    "BackendError", "BackendAuthError", "ConfigError",
    "BBox", "Span", "Issue", "IssueKind", "IssueSource", "Severity", "Confidence",
    "Verdict", "Report", "Brief", "IntentClaim", "Importance", "ClaimStatus", "ClaimResult",
    "Conformance", "Handoff", "NextAction",
    # lazy (built in later phases):
    "analyze", "check", "watch", "render", "compute_diff",
    "LoopSession", "GenerativeLoopSession", "StreamMonitor",
]

_LAZY_CORE = {"analyze", "check", "watch", "render", "compute_diff",
              "LoopSession", "GenerativeLoopSession", "StreamMonitor"}


def __getattr__(name: str):
    # Lazy high-level API — imported on demand to keep the base import light. Until a phase wires
    # the implementation, accessing it raises a clear, actionable error rather than ImportError.
    if name in _LAZY_CORE:
        try:
            from . import core
        except ImportError as e:  # pragma: no cover - until Phase 1
            raise NotImplementedError(
                f"audel.{name} lands in a later build; core is not wired yet."
            ) from e
        return getattr(core, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
