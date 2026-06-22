"""audel.core — high-level entry points (wired phase by phase)."""

from __future__ import annotations

from .analyze import analyze
from .check import check
from .render import RenderResult, render

__all__ = ["check", "render", "analyze", "RenderResult"]
