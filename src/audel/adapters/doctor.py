"""``audel doctor`` — environment diagnostics.

Reports which optional capabilities are available (ffmpeg decode, faster-whisper ASR, CLAP,
Playwright/Chromium, cloud backends) without importing heavy deps unless present. Never prints
credential values — only whether a key is resolvable.
"""

from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass

from ..config import Settings


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def _has_module(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def run_checks(settings: Settings | None = None) -> list[Check]:
    s = settings or Settings()
    checks: list[Check] = []

    ffmpeg = s.ffmpeg_path or shutil.which("ffmpeg")
    checks.append(Check("ffmpeg", bool(ffmpeg), ffmpeg or "not found — install ffmpeg for decode"))
    checks.append(Check("ffprobe", bool(shutil.which("ffprobe")),
                        shutil.which("ffprobe") or "not found"))

    checks.append(Check("faster-whisper (asr)", _has_module("faster_whisper"),
                        "installed" if _has_module("faster_whisper") else "pip install audel[asr]"))
    checks.append(Check("CLAP (acoustic)", _has_module("laion_clap") or _has_module("transformers"),
                        "available" if _has_module("transformers") else "pip install audel[clap]"))
    chromium = _has_module("playwright")
    checks.append(Check("playwright (render)", chromium,
                        "installed" if chromium else "pip install audel[render]"))

    # Cloud/text backends: report only whether a credential resolves (never the value).
    for backend in ("ollama", "anthropic", "gemini-audio"):
        has_key = bool(s.key_for(backend))
        checks.append(Check(f"backend:{backend}", has_key,
                            "key resolved" if has_key else "no key (set env or ~/.config/.../key)"))
    checks.append(_local_llm(s))
    return checks


def _local_llm(s: Settings) -> Check:
    """Is the operator's on-prem Ollama reachable (vetted URL, no redirects, short timeout)?"""
    if not s.local_llm_url:
        return Check("backend:ollama-local", False, "not configured (set AUDEL_LOCAL_LLM_URL)")
    import json
    import urllib.request

    from ..errors import UnsafeSourceError
    from ..netguard import _NoRedirect, assert_backend_url

    url = s.local_llm_url.rstrip("/") + "/api/version"
    try:
        assert_backend_url(url, s.trusted_backend_hosts)
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(url, timeout=3) as resp:
            version = json.loads(resp.read(4096)).get("version", "?")
        return Check("backend:ollama-local", True, f"reachable (Ollama {str(version)[:20]}), "
                     f"model {s.local_llm_model}")
    except UnsafeSourceError as e:
        return Check("backend:ollama-local", False, f"refused: {e} (add it to trusted_backend_hosts)")
    except Exception as e:  # noqa: BLE001 - diagnostics only
        return Check("backend:ollama-local", False, f"unreachable ({type(e).__name__})")


def format_checks(checks: list[Check]) -> str:
    lines = []
    for c in checks:
        mark = "✓" if c.ok else "✗"
        lines.append(f"  {mark} {c.name:24} {c.detail}")
    return "\n".join(lines)
