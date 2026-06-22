"""audel.core — high-level entry points (wired phase by phase)."""

from __future__ import annotations

from .check import check
from .render import RenderResult, render

__all__ = ["check", "render", "RenderResult"]
