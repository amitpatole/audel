"""The audio feedback loop — the headline feature (ears edition).

A :class:`LoopSession` runs iterations of grade -> report -> diff-vs-previous with persisted
per-iteration state. Progress/stuck is decided by **issue-set stability** (``Report.issue_signature``),
not by raw signal deltas: a real fix can barely move the waveform and re-encoding noise can move it a
lot. Mirrors AgentVision's ``LoopSession`` so the eyes and ears drive identically.

Grading is ``analyze`` by default (DSP + ASR + optional LLM/CLAP, may egress on the LLM path); pass
``offline=True`` to grade with ``check`` instead — deterministic, ASR-only, **zero network**.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..config import Settings, load_settings
from ..models import Brief, Handoff, Report, Verdict
from ..workspace import Workspace
from .analyze import analyze
from .check import check
from .diff import AudioDiff, compute_diff


class IterationResult(BaseModel):
    index: int
    report: Report
    diff: AudioDiff | None = None
    verdict: Verdict
    handoff: Handoff | None = None
    progressed: bool = False
    stuck: bool = False
    artifacts: dict[str, str] = Field(default_factory=dict)


class LoopSession:
    """Drive the audio feedback loop for one artifact across iterations.

    Agents call :meth:`iterate` after each fix attempt (optionally passing an updated ``source``).
    State is persisted under the workspace so the session can be inspected or resumed.
    """

    def __init__(
        self,
        source: str,
        *,
        settings: Settings | None = None,
        backend: str | None = None,
        brief: Brief | None = None,
        offline: bool = False,
        session_id: str | None = None,
        stuck_threshold: int = 2,
    ):
        self.source = source
        self.settings = settings or load_settings()
        self.backend = backend
        self.brief = brief
        self.offline = offline
        self.stuck_threshold = stuck_threshold
        self.ws = Workspace(self.settings)
        self.session_id = session_id or self.ws.new_session_id()
        self.history: list[IterationResult] = []
        self._signatures: list[frozenset] = []
        self._repeat_count = 0
        self.stop_reason: str | None = None

    @property
    def last_report(self) -> Report | None:
        return self.history[-1].report if self.history else None

    async def _grade(self, src) -> Report:
        if self.offline:
            return await check(src, settings=self.settings, brief=self.brief)
        return await analyze(src, settings=self.settings, brief=self.brief, backend=self.backend)

    async def iterate(self, source: str | None = None) -> IterationResult:
        idx = len(self.history)
        src = source if source is not None else self.source
        if source is not None:
            self.source = source

        prev = self.last_report
        report = await self._grade(src)
        diff = compute_diff(prev, report) if prev is not None else None

        # Issue-set based progress / stuck detection.
        sig = report.issue_signature()
        progressed = bool(self._signatures and sig != self._signatures[-1])
        if self._signatures and sig == self._signatures[-1] and report.verdict != Verdict.PASS:
            self._repeat_count += 1
        else:
            self._repeat_count = 0
        self._signatures.append(sig)
        stuck = self._repeat_count >= (self.stuck_threshold - 1) and report.verdict != Verdict.PASS

        # Persist artifacts (report + the distilled ears->brain handoff signal), secret-scrubbed.
        handoff = report.to_handoff()
        rp = self.ws.write_iter_json(self.session_id, idx, "report.json",
                                     report.model_dump_json(indent=2))
        hp = self.ws.write_iter_json(self.session_id, idx, "handoff.json",
                                     handoff.model_dump_json(indent=2))
        artifacts = {"report": str(rp), "handoff": str(hp)}

        result = IterationResult(
            index=idx, report=report, diff=diff, verdict=report.verdict, handoff=handoff,
            progressed=progressed, stuck=stuck, artifacts=artifacts,
        )
        self.history.append(result)
        self.ws.write_session_meta(self.session_id, {
            "backend": ("offline" if self.offline else (self.backend or "auto")),
            "iterations": len(self.history),
            "last_verdict": report.verdict.value,
        })
        if report.verdict == Verdict.PASS:
            self.stop_reason = "pass"
        elif stuck:
            self.stop_reason = "stuck"
        return result

    async def run(self, max_iter: int = 5) -> list[IterationResult]:
        """Convenience: iterate the SAME source up to ``max_iter`` times.

        Useful for demonstrating stuck-detection on an unchanged artifact. Real agents drive
        :meth:`iterate` themselves, fixing the audio between calls.
        """
        for _ in range(max_iter):
            result = await self.iterate()
            if result.verdict == Verdict.PASS or result.stuck:
                break
        return self.history
