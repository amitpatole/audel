"""``compute_diff`` — what changed between two audio gradings.

AgentVision diffs *pixels* between iterations; for audio the meaningful, deterministic signal is
the **issue-set transition**: which problems a fix resolved, which it left, and which it introduced
(a regression). This is computed from two :class:`~audel.models.Report` objects — no re-decode, no
network — and drives the loop's progress/stuck reporting and the human-readable change log.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..models import Report, Verdict

_VERDICT_RANK = {Verdict.FAIL: 0, Verdict.WARN: 1, Verdict.PASS: 2}


def _sig_label(sig: tuple[str, str]) -> str:
    kind, message = sig
    return f"{kind}: {message}"


class AudioDiff(BaseModel):
    """Deterministic difference between a *before* and *after* audio report."""

    verdict_before: Verdict
    verdict_after: Verdict
    resolved: list[str] = Field(default_factory=list, description="Issues present before, gone after.")
    introduced: list[str] = Field(default_factory=list, description="New issues after (regressions).")
    persisted: list[str] = Field(default_factory=list, description="Issues present in both.")
    duration_delta_ms: int | None = None
    improved: bool = False
    regressed: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.resolved or self.introduced) or self.verdict_before != self.verdict_after


def compute_diff(before: Report, after: Report) -> AudioDiff:
    """Compare two reports of (presumably) the same artifact across a fix attempt.

    ``improved`` means the verdict got better OR strictly more issues were resolved than introduced;
    ``regressed`` means the verdict got worse OR a new issue appeared. Both can be False (no change).
    """
    before_sig = before.issue_signature()
    after_sig = after.issue_signature()
    resolved = sorted(_sig_label(s) for s in (before_sig - after_sig))
    introduced = sorted(_sig_label(s) for s in (after_sig - before_sig))
    persisted = sorted(_sig_label(s) for s in (before_sig & after_sig))

    dur_delta = None
    if before.duration_ms is not None and after.duration_ms is not None:
        dur_delta = after.duration_ms - before.duration_ms

    rank_before = _VERDICT_RANK[before.verdict]
    rank_after = _VERDICT_RANK[after.verdict]
    improved = rank_after > rank_before or (len(resolved) > len(introduced) and rank_after >= rank_before)
    regressed = rank_after < rank_before or bool(introduced)

    return AudioDiff(
        verdict_before=before.verdict, verdict_after=after.verdict,
        resolved=resolved, introduced=introduced, persisted=persisted,
        duration_delta_ms=dur_delta, improved=improved, regressed=regressed,
    )
