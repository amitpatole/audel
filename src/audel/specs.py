"""Delivery specs as data — the loudness/peak rules a deliverable must meet.

A :class:`DeliverySpec` is a plain, serializable rule set (integrated target and tolerance, true-peak
ceiling, optional short-term/momentary maxima, optional LRA ceiling, program or dialogue gating).
Audel ships the common broadcast and streaming specs as built-ins; an operator can load their own
contract spec from a JSON file. Grading reads ONLY this object, so swapping a spec never changes
code.

Values follow the published recommendations (EBU R128 / R128 s1, ATSC A/85, OP-59, ARIB TR-B32,
the streaming platforms' loudness guidance). Contracts often tighten these; when they do, ship a
custom JSON spec rather than editing a built-in.

Security: a spec FILE is operator configuration (``AUDEL_DELIVERY_SPEC`` / ``--spec-file``), never a
remote-caller input. The REST surface accepts built-in NAMES only (see :func:`builtin_spec`).
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .errors import ConfigError

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_MAX_SPEC_BYTES = 64 * 1024


class Gating(str, Enum):
    PROGRAM = "program"    # ITU-R BS.1770 gated loudness over the whole programme
    DIALOGUE = "dialogue"  # loudness over speech regions only (VAD approximation, see docs)


class ContentType(str, Enum):
    SPEECH = "speech"
    MUSIC = "music"
    MIXED = "mixed"


class Strictness(str, Enum):
    """How a loudness miss is graded. Broadcast deliveries are rejected (ERROR); streaming
    platforms normalize playback, so a miss there is a WARNING."""

    REJECT = "reject"
    ADVISE = "advise"


class DeliverySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    description: str = ""
    integrated_lufs: float = Field(ge=-70, le=0)
    tolerance_lu: float = Field(gt=0, le=10)
    max_true_peak_dbtp: float = Field(ge=-20, le=3)
    max_short_term_lufs: float | None = Field(default=None, ge=-70, le=0)
    max_momentary_lufs: float | None = Field(default=None, ge=-70, le=0)
    max_lra_lu: float | None = Field(default=None, gt=0, le=40)
    gating: Gating = Gating.PROGRAM
    strictness: Strictness = Strictness.REJECT
    content: ContentType | None = None   # informs content-aware checks (noise floor on speech)
    reference: str = ""                  # the published document the values come from

    @field_validator("name")
    @classmethod
    def _name_shape(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError("spec name must be 1-64 chars of [a-z0-9_.-]")
        return v


def _spec(**kw) -> DeliverySpec:
    return DeliverySpec(**kw)


BUILTIN_SPECS: dict[str, DeliverySpec] = {s.name: s for s in [
    _spec(name="ebu_r128", description="EBU R128 broadcast programme",
          integrated_lufs=-23.0, tolerance_lu=0.5, max_true_peak_dbtp=-1.0,
          reference="EBU R 128 (2023)"),
    _spec(name="ebu_r128_s1", description="EBU R128 s1 short-form (adverts, promos, trailers)",
          integrated_lufs=-23.0, tolerance_lu=0.5, max_true_peak_dbtp=-1.0,
          max_short_term_lufs=-18.0, reference="EBU R 128 s1"),
    _spec(name="atsc_a85", description="ATSC A/85 (US broadcast)",
          integrated_lufs=-24.0, tolerance_lu=2.0, max_true_peak_dbtp=-2.0,
          reference="ATSC A/85:2013"),
    _spec(name="op59", description="Free TV Australia OP-59",
          integrated_lufs=-24.0, tolerance_lu=1.0, max_true_peak_dbtp=-2.0,
          reference="Free TV OP-59"),
    _spec(name="arib_tr_b32", description="ARIB TR-B32 (Japan broadcast)",
          integrated_lufs=-24.0, tolerance_lu=1.0, max_true_peak_dbtp=-1.0,
          reference="ARIB TR-B32"),
    _spec(name="netflix", description="Netflix-style dialogue-gated programme loudness",
          integrated_lufs=-27.0, tolerance_lu=2.0, max_true_peak_dbtp=-2.0,
          gating=Gating.DIALOGUE, reference="Netflix sound mix specifications"),
    _spec(name="spotify", description="Spotify loudness normalization target",
          integrated_lufs=-14.0, tolerance_lu=2.0, max_true_peak_dbtp=-1.0,
          strictness=Strictness.ADVISE, content=ContentType.MUSIC,
          reference="Spotify for Artists loudness guidance"),
    _spec(name="youtube", description="YouTube playback normalization",
          integrated_lufs=-14.0, tolerance_lu=2.0, max_true_peak_dbtp=-1.0,
          strictness=Strictness.ADVISE, reference="YouTube loudness normalization"),
    _spec(name="apple_music", description="Apple Music Sound Check",
          integrated_lufs=-16.0, tolerance_lu=2.0, max_true_peak_dbtp=-1.0,
          strictness=Strictness.ADVISE, content=ContentType.MUSIC,
          reference="Apple Digital Masters guidance"),
    _spec(name="apple_podcasts", description="Apple Podcasts",
          integrated_lufs=-16.0, tolerance_lu=1.0, max_true_peak_dbtp=-1.0,
          strictness=Strictness.ADVISE, content=ContentType.SPEECH,
          reference="Apple Podcasts audio requirements"),
    _spec(name="podcast", description="General podcast / spoken word",
          integrated_lufs=-16.0, tolerance_lu=2.0, max_true_peak_dbtp=-1.0,
          strictness=Strictness.ADVISE, content=ContentType.SPEECH),
]}


def builtin_spec(name: str) -> DeliverySpec:
    """A built-in spec by NAME only (the safe surface for remote callers)."""
    spec = BUILTIN_SPECS.get(str(name).strip().lower())
    if spec is None:
        raise ConfigError(f"unknown delivery spec {name!r}; built-ins: {', '.join(sorted(BUILTIN_SPECS))}")
    return spec


def load_spec_file(path: str | Path) -> DeliverySpec:
    """Load an operator-supplied JSON spec. Bounded read, strict schema (unknown keys rejected)."""
    p = Path(path).expanduser()
    try:
        if not p.is_file():
            raise ConfigError(f"spec file not found: {p}")
        if p.stat().st_size > _MAX_SPEC_BYTES:
            raise ConfigError(f"spec file over {_MAX_SPEC_BYTES} bytes")
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ConfigError(f"could not read spec file {p}: {type(e).__name__}") from e
    try:
        return DeliverySpec.model_validate(data)
    except ValidationError as e:
        # Report field locations and error types only — never echo input values (a mis-pointed
        # spec path must not turn error messages into a file-content oracle).
        where = "; ".join(f"{'.'.join(str(x) for x in err['loc']) or '<root>'}: {err['type']}"
                          for err in e.errors()[:10])
        raise ConfigError(f"invalid spec file {p.name}: {where}") from None


def resolve_spec(value: str | DeliverySpec | None) -> DeliverySpec | None:
    """Name → built-in; a path ending in .json → file; a DeliverySpec passes through."""
    if value is None or isinstance(value, DeliverySpec):
        return value
    v = str(value).strip()
    if not v:
        return None
    if v.lower().endswith(".json") or "/" in v or "\\" in v:
        return load_spec_file(v)
    return builtin_spec(v)


def legacy_spec(target, clipping_dbtp: float) -> DeliverySpec:
    """The pre-spec behaviour (a LoudnessTarget preset, ±2 LU advisory, TP from settings), kept so
    callers that never set a delivery spec grade exactly as in 0.1."""
    return DeliverySpec(name=f"preset.{target.value}", description=f"{target.value} loudness preset",
                        integrated_lufs=target.lufs, tolerance_lu=2.0,
                        max_true_peak_dbtp=clipping_dbtp, strictness=Strictness.ADVISE)
