"""audel.core — high-level entry points (wired phase by phase)."""

from __future__ import annotations

from .analyze import analyze
from .check import check
from .diff import AudioDiff, compute_diff
from .generate import GenerationStep, GenerativeLoopSession
from .loop import IterationResult, LoopSession
from .render import RenderResult, render
from .stream import StreamMonitor, StreamUpdate
from .watch import watch

__all__ = [
    "check", "render", "analyze", "watch", "RenderResult",
    "compute_diff", "AudioDiff",
    "LoopSession", "IterationResult", "GenerativeLoopSession", "GenerationStep",
    "StreamMonitor", "StreamUpdate",
]
