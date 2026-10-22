"""Bounded in-process async job store for the REST service.

A submitted job is queued, run under the service's concurrency limit, and its result kept for
``job_result_ttl_s``. Every job belongs to the tenant that submitted it: another tenant asking for
it gets the same 404 as for a job that does not exist (no existence oracle). Job ids are 128-bit
random. The store is bounded: submissions beyond ``max_queued_jobs`` are refused (the caller
gets 429) and the oldest finished results are evicted beyond ``max_stored_jobs``.

State is per process. Run one replica per job store, or put a shared queue in front; the docs say
how to scale this out.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .errors import AudelError


@dataclass
class Job:
    id: str
    owner: str
    kind: str
    status: str = "queued"          # queued | running | done | failed | cancelled
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    result: dict | None = None
    error: str | None = None
    task: asyncio.Task | None = field(default=None, repr=False)

    def public(self) -> dict:
        return {"job_id": self.id, "kind": self.kind, "status": self.status,
                "created": self.created, "started": self.started, "finished": self.finished,
                "result": self.result, "error": self.error}


class QueueFull(AudelError):
    pass


class JobStore:
    def __init__(self, *, max_queued: int, max_stored: int, ttl_s: float,
                 semaphore: asyncio.Semaphore, max_queued_per_owner: int | None = None,
                 max_stored_per_owner: int | None = None, owner_gate=None) -> None:
        self._jobs: dict[str, Job] = {}
        self._max_queued, self._max_stored, self._ttl = max_queued, max_stored, ttl_s
        # Fair share: one tenant cannot fill the global queue or evict others' results.
        self._q_owner = max_queued_per_owner or max(1, max_queued // 4)
        self._s_owner = max_stored_per_owner or max(1, max_stored // 4)
        self._sem = semaphore
        # Optional per-owner gate (async context manager factory) taken BEFORE the global slot,
        # so one owner's queued jobs never hold global slots while waiting on their own share.
        self._owner_gate = owner_gate

    def _purge(self, owner: str | None = None) -> None:
        now = time.time()
        for jid in [j.id for j in self._jobs.values()
                    if j.finished is not None and now - j.finished > self._ttl]:
            del self._jobs[jid]
        # A tenant's own oldest finished results go first (never another tenant's)...
        if owner is not None:
            own = sorted((j for j in self._jobs.values() if j.owner == owner and j.finished),
                         key=lambda j: j.finished or 0)
            while len(own) >= self._s_owner:
                del self._jobs[own.pop(0).id]
        # ...then the global bound, taken from whoever holds the most finished results.
        while len(self._jobs) > self._max_stored:
            finished = [j for j in self._jobs.values() if j.finished is not None]
            if not finished:
                break
            counts: dict[str, int] = {}
            for j in finished:
                counts[j.owner] = counts.get(j.owner, 0) + 1
            heavy = max(counts, key=lambda o: counts[o])
            victim = min((j for j in finished if j.owner == heavy), key=lambda j: j.finished or 0)
            del self._jobs[victim.id]

    def pending(self, owner: str | None = None) -> int:
        return sum(1 for j in self._jobs.values() if j.status in ("queued", "running")
                   and (owner is None or j.owner == owner))

    def submit(self, owner: str, kind: str, work: Callable[[], Awaitable[dict]],
               on_done: Callable[[Job], None] | None = None,
               cleanup: Callable[[], None] | None = None,
               prepare: Callable[[], Awaitable[None]] | None = None) -> Job:
        """``cleanup`` ALWAYS runs exactly once when the job ends: done, failed, or cancelled
        (including cancelled while still queued), so spooled inputs never leak."""
        self._purge(owner)
        if self.pending(owner) >= self._q_owner:
            raise QueueFull("your job queue is full; retry later")
        if self.pending() >= self._max_queued:
            raise QueueFull("job queue is full; retry later")
        job = Job(id=uuid.uuid4().hex, owner=owner, kind=kind)
        self._jobs[job.id] = job

        async def run() -> None:
            try:
                await _body()
            finally:
                if cleanup is not None:
                    try:
                        cleanup()
                    except OSError:
                        pass

        async def _body() -> None:
            try:
                if prepare is not None:
                    # I/O-bound preparation (e.g. fetching a URL) happens BEFORE any grading slot
                    # is taken, so a slow source cannot hold slots that other tenants need.
                    await prepare()
                gate = self._owner_gate(owner) if self._owner_gate else _null_gate()
                async with gate:
                    async with self._sem:
                        if job.status == "cancelled":
                            return
                        job.status, job.started = "running", time.time()
                        job.result = await work()
                        job.status = "done"
            except asyncio.CancelledError:
                job.status, job.error = "cancelled", "cancelled"
                raise
            except Exception as e:  # noqa: BLE001 - recorded on the job, never raised
                job.status, job.error = "failed", _public_error(e)
            finally:
                job.finished = time.time()
                if on_done is not None:
                    on_done(job)

        job.task = asyncio.create_task(run())
        return job

    def get(self, owner: str, job_id: str) -> Job | None:
        self._purge()
        job = self._jobs.get(job_id)
        return job if job is not None and job.owner == owner else None

    def list(self, owner: str, limit: int = 100) -> list[Job]:
        self._purge()
        own = [j for j in self._jobs.values() if j.owner == owner]
        return sorted(own, key=lambda j: j.created, reverse=True)[:limit]

    def cancel(self, owner: str, job_id: str) -> bool:
        job = self.get(owner, job_id)
        if job is None:
            return False
        if job.status in ("queued", "running") and job.task is not None:
            job.status = "cancelled"
            job.task.cancel()
        del self._jobs[job.id]
        return True


def _public_error(e: Exception) -> str:
    from .errors import BusyError, ConfigError, UnsafeSourceError, sanitize_message

    if isinstance(e, (BusyError, OSError, MemoryError)) or (
            isinstance(e, RuntimeError) and "can't start new thread" in str(e)):
        return "Server busy; resubmit later."  # the host at its limits, as the REST handler says
    if isinstance(e, (UnsafeSourceError, ConfigError)):
        return sanitize_message(str(e))
    return "Could not decode or grade the source."


class _null_gate:  # noqa: N801 - tiny async context manager
    async def __aenter__(self):
        return None

    async def __aexit__(self, *exc):
        return False
