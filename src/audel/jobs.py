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
                 semaphore: asyncio.Semaphore) -> None:
        self._jobs: dict[str, Job] = {}
        self._max_queued, self._max_stored, self._ttl = max_queued, max_stored, ttl_s
        self._sem = semaphore

    def _purge(self) -> None:
        now = time.time()
        for jid in [j.id for j in self._jobs.values()
                    if j.finished is not None and now - j.finished > self._ttl]:
            del self._jobs[jid]
        finished = sorted((j for j in self._jobs.values() if j.finished is not None),
                          key=lambda j: j.finished or 0)
        while len(self._jobs) > self._max_stored and finished:
            del self._jobs[finished.pop(0).id]

    def pending(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))

    def submit(self, owner: str, kind: str, work: Callable[[], Awaitable[dict]],
               on_done: Callable[[Job], None] | None = None) -> Job:
        self._purge()
        if self.pending() >= self._max_queued:
            raise QueueFull("job queue is full; retry later")
        job = Job(id=uuid.uuid4().hex, owner=owner, kind=kind)
        self._jobs[job.id] = job

        async def run() -> None:
            async with self._sem:
                if job.status == "cancelled":
                    return
                job.status, job.started = "running", time.time()
                try:
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
    from .errors import ConfigError, UnsafeSourceError, sanitize_message

    if isinstance(e, (UnsafeSourceError, ConfigError)):
        return sanitize_message(str(e))
    return "Could not decode or grade the source."
