"""Phase 10: listen() end to end on real synthesized speech (espeak-ng + faster-whisper)."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess

import pytest

from audel.config import Settings
from audel.errors import ConfigError

needs = pytest.mark.skipif(shutil.which("espeak-ng") is None or shutil.which("ffmpeg") is None,
                           reason="needs espeak-ng + ffmpeg")


@pytest.fixture(scope="module")
def read_wav(tmp_path_factory):
    pytest.importorskip("faster_whisper")
    d = tmp_path_factory.mktemp("listen")
    wav = d / "read.wav"
    subprocess.run(["espeak-ng", "-s", "150", "-w", str(wav),
                    "Good evening. Heavy rain will spread across the north tonight. "
                    "Drivers are urged to take care. Terms and conditions apply."], check=True)
    return wav


@needs
def test_listen_hears_then_listens(read_wav):
    from audel import listen

    script = ("Good evening. Heavy rain will spread across the north tonight, with flooding "
              "possible near the river. Drivers are urged to take care. Terms and conditions apply.")
    r = asyncio.run(listen(str(read_wav), script=script, required=["terms and conditions apply"],
                           forbidden=["drivers"]))
    checks = {i.detail.get("check") for i in r.issues}
    assert "script_omission" in checks and "forbidden_term" in checks
    assert r.listening is not None and r.listening.words > 10 and r.listening.language == "en"
    assert r.listening.terms["terms and conditions apply"] is True
    assert r.listening.script_adherence is not None and r.listening.script_adherence < 1
    assert r.tracks and r.backend.startswith("dsp")  # hearing ran too
    json.loads(r.model_dump_json())


@needs
def test_listen_understand_with_a_fake_local_model(read_wav, monkeypatch):
    import importlib

    listen_mod = importlib.import_module("audel.core.listen")  # the module, not the function

    class FakeLocal:
        name, hears_audio = "ollama-local", True

        def available(self):
            return True

        async def complete_text(self, system, user):
            return json.dumps({"takeaway": "Rain tonight.", "messages": [
                {"index": 0, "status": "conveyed", "evidence": "rain"}]})

        async def critique_audio(self, path, prompt):
            return json.dumps({"delivery": "urgent", "pace": "normal",
                               "intelligibility": "clear", "note": "x"})

    monkeypatch.setattr(listen_mod, "resolve_backend", lambda name, s: FakeLocal())
    r = asyncio.run(listen_mod.listen(str(read_wav), understand=True, tone="calm",
                                      key_messages=["rain is coming"],
                                      settings=Settings(local_llm_url="http://10.0.0.1:11434")))
    assert r.listening.takeaway == "Rain tonight." and r.listening.understood_by == "ollama-local"
    assert r.listening.delivery and r.listening.delivery[0].delivery == "urgent"
    assert any(i.detail.get("check") == "delivery_tone" for i in r.issues)
    assert r.conformance and r.conformance.claims[0].status.value == "satisfied"


@needs
def test_listen_validates_inputs(read_wav):
    from audel import listen

    with pytest.raises(ConfigError):
        asyncio.run(listen(str(read_wav), tone="sarcastic"))
    with pytest.raises(ConfigError):
        asyncio.run(listen(str(read_wav), languages={0: "english; rm -rf /"}))
    with pytest.raises(ConfigError):
        asyncio.run(listen(str(read_wav), languages={5: "es"}))
