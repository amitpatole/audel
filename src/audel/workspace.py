"""Artifact store and loop session state (mirrors AgentVision's ``workspace.py``).

Two areas under the cache dir:

* ``artifacts/`` — content-addressed by INPUTS (source bytes + the decode params that determine
  the output), never by report content. A ``Report`` is grading output (the LLM path is
  non-deterministic and even the DSP path is provenance-bearing), so reports are written into the
  per-iteration session dir, never used as a cache key.
* ``sessions/<id>/iter_<n>/`` — per-loop-iteration state (report + handoff JSON). Filesystem
  mutation is guarded by a short-held sync ``filelock`` (acquired only around the write, never held
  across an ``await``).

SECURITY: **secrets are never persisted.** Every byte written to a session goes through
:func:`audel.logging.scrub_text`, so a credential that somehow reached a summary/message is redacted
before it touches disk. A TTL garbage collector reaps stale or schema-mismatched sessions.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
import uuid
from pathlib import Path

from filelock import FileLock, Timeout

from .config import Settings
from .errors import UnsafeSourceError
from .logging import get_logger, scrub_text

log = get_logger("workspace")

# Bump when the on-disk session layout / Report schema changes incompatibly.
SCHEMA_VERSION = "1.0"
DECODER_VERSION = "1"  # part of the artifact cache key; bump on decode-behavior changes

# A session id / filename must be a single benign path component — no separators, no traversal.
# Both can originate from a caller (LoopSession(session_id=...), write_iter_json(name=...)), so we
# charset-validate before either reaches a filesystem join (path-traversal defense).
_SAFE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _safe_component(value: str, *, what: str) -> str:
    v = str(value)
    if not _SAFE_ID.match(v) or v in (".", "..") or "/" in v or "\\" in v:
        raise UnsafeSourceError(f"unsafe {what}: {value!r} (must be a single [A-Za-z0-9._-] component)")
    return v


class Workspace:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = Path(settings.cache_dir)
        self.artifacts = self.root / "artifacts"
        self.sessions = self.root / "sessions"
        self.tmp = self.root / "tmp"
        for d in (self.artifacts, self.sessions, self.tmp):
            d.mkdir(parents=True, exist_ok=True)

    # ---- artifact cache (inputs-addressed) -------------------------------------

    @staticmethod
    def artifact_key(*, source_bytes: bytes, params: dict) -> str:
        """Stable key from the decode INPUTS only (source bytes + the params that shape the output).

        Never keyed on report bytes — grading output is non-deterministic / provenance-bearing.
        ``params`` is canonicalised (sorted keys) so equal inputs always collide."""
        h = hashlib.sha256()
        h.update(DECODER_VERSION.encode())
        h.update(source_bytes)
        h.update(json.dumps(params, sort_keys=True, default=str).encode())
        return h.hexdigest()[:32]

    def artifact_path(self, key: str, suffix: str = ".wav") -> Path:
        return self.artifacts / f"{key}{suffix}"

    # ---- sessions --------------------------------------------------------------

    def new_session_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def session_dir(self, session_id: str) -> Path:
        d = self.sessions / _safe_component(session_id, what="session id")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def iter_dir(self, session_id: str, index: int) -> Path:
        d = self.session_dir(session_id) / f"iter_{int(index)}"  # int() rejects a crafted index
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _lock(self, session_id: str) -> FileLock:
        sid = _safe_component(session_id, what="session id")
        return FileLock(str(self.sessions / f"{sid}.lock"))

    def write_iter_json(self, session_id: str, index: int, name: str, payload: str) -> Path:
        """Write per-iteration JSON, secret-scrubbed, under a short-held sync lock."""
        out = self.iter_dir(session_id, index) / _safe_component(name, what="filename")
        lock = self._lock(session_id)
        with lock:  # acquire -> write -> release; never held across an await
            out.write_text(scrub_text(payload))
        return out

    def write_session_meta(self, session_id: str, meta: dict) -> None:
        """Write session metadata (scrubbed) under a short-held sync lock."""
        meta = {**meta, "schema_version": SCHEMA_VERSION}
        lock = self._lock(session_id)
        with lock:
            (self.session_dir(session_id) / "session.json").write_text(
                scrub_text(json.dumps(meta, indent=2))
            )

    def read_session_meta(self, session_id: str) -> dict | None:
        f = self.session_dir(session_id) / "session.json"
        if not f.exists():
            return None
        try:
            meta = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        if meta.get("schema_version") != SCHEMA_VERSION:
            log.warning("session %s has stale schema_version; ignoring", session_id)
            return None
        return meta

    # ---- garbage collection ----------------------------------------------------

    def gc(self) -> int:
        """Reap stale or schema-mismatched sessions whose lock is unheld. Returns count removed."""
        removed = 0
        now = time.time()
        if not self.sessions.exists():
            return 0
        for d in self.sessions.iterdir():
            if not d.is_dir():
                continue
            session_id = d.name
            if not _SAFE_ID.match(session_id):
                continue  # never created by us; don't act on a name we can't vouch for
            lock = self._lock(session_id)
            try:
                lock.acquire(timeout=0)  # skip sessions a live process still holds
            except Timeout:
                continue
            try:
                stale_ttl = (now - d.stat().st_mtime) > self.settings.session_ttl_s
                meta = self.read_session_meta(session_id)  # None if schema mismatch
                if stale_ttl or meta is None:
                    shutil.rmtree(d, ignore_errors=True)
                    removed += 1
            finally:
                lock.release()
                (self.sessions / f"{session_id}.lock").unlink(missing_ok=True)
        return removed
