"""Operations: Prometheus metrics and a structured audit log for the service.

Metrics are a tiny in-process registry rendered in the Prometheus text format (no extra
dependency). Label values come from a closed set (endpoint route templates, status codes,
verdicts, job kinds), so a caller cannot blow up cardinality.

The audit log is one JSON object per graded request: who (tenant), what (endpoint, job id, input
SHA-256 and byte count, source host for URL ingestion, spec), outcome (verdict, issue count,
status, duration). It NEVER records media content, transcripts, script or caption text, tokens,
or signed-URL query strings.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict
from pathlib import Path

from . import __version__
from .logging import get_logger, scrub_text

_audit_log = get_logger("audit")
_BUCKETS = (0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[tuple[str, str], int] = defaultdict(int)
        self.verdicts: dict[tuple[str, str], int] = defaultdict(int)
        self.hist: dict[str, list[int]] = defaultdict(lambda: [0] * (len(_BUCKETS) + 1))
        self.hist_sum: dict[str, float] = defaultdict(float)
        self.inflight = 0
        self.queued = 0

    def request(self, route: str, status: int) -> None:
        with self._lock:
            self.requests[(route, str(status))] += 1

    def graded(self, kind: str, verdict: str, seconds: float) -> None:
        with self._lock:
            self.verdicts[(kind, verdict)] += 1
            b = self.hist[kind]
            for i, edge in enumerate(_BUCKETS):
                if seconds <= edge:
                    b[i] += 1
                    break
            else:
                b[-1] += 1
            self.hist_sum[kind] += seconds

    def render(self) -> str:
        with self._lock:
            out = ["# HELP audel_build_info Audel version.", "# TYPE audel_build_info gauge",
                   f'audel_build_info{{version="{__version__}"}} 1',
                   "# HELP audel_requests_total HTTP requests by route and status.",
                   "# TYPE audel_requests_total counter"]
            for (route, status), n in sorted(self.requests.items()):
                out.append(f'audel_requests_total{{route="{route}",status="{status}"}} {n}')
            out += ["# HELP audel_grades_total Completed grades by kind and verdict.",
                    "# TYPE audel_grades_total counter"]
            for (kind, verdict), n in sorted(self.verdicts.items()):
                out.append(f'audel_grades_total{{kind="{kind}",verdict="{verdict}"}} {n}')
            out += ["# HELP audel_grade_seconds Grading wall time.",
                    "# TYPE audel_grade_seconds histogram"]
            for kind, b in sorted(self.hist.items()):
                acc = 0
                for edge, n in zip(_BUCKETS, b, strict=False):
                    acc += n
                    out.append(f'audel_grade_seconds_bucket{{kind="{kind}",le="{edge}"}} {acc}')
                acc += b[-1]
                out.append(f'audel_grade_seconds_bucket{{kind="{kind}",le="+Inf"}} {acc}')
                out.append(f'audel_grade_seconds_sum{{kind="{kind}"}} {self.hist_sum[kind]:.3f}')
                out.append(f'audel_grade_seconds_count{{kind="{kind}"}} {acc}')
            out += ["# HELP audel_jobs_inflight Grades running now.", "# TYPE audel_jobs_inflight gauge",
                    f"audel_jobs_inflight {self.inflight}",
                    "# HELP audel_jobs_queued Async jobs waiting.", "# TYPE audel_jobs_queued gauge",
                    f"audel_jobs_queued {self.queued}"]
        return "\n".join(out) + "\n"


class AuditLog:
    """Append-only JSON lines (file mode 0600) plus the ``audel.audit`` logger."""

    _ALLOWED = {"ts", "request_id", "tenant", "endpoint", "job_id", "kind", "input_sha256",
                "input_bytes", "source", "source_host", "spec", "verdict", "issues", "status",
                "duration_ms", "error"}

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()

    def write(self, **event) -> None:
        rec = {k: v for k, v in event.items() if k in self._ALLOWED and v is not None}
        rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        line = scrub_text(json.dumps(rec, sort_keys=True, default=str))
        _audit_log.info(line)
        if self._path is None:
            return
        with self._lock:
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchmod(fd, 0o600)  # also tighten a pre-existing file
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
