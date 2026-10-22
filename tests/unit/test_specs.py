"""Phase 9: delivery specs are data — built-ins resolve, operator files are strict and bounded."""

from __future__ import annotations

import json

import pytest

from audel.errors import ConfigError
from audel.specs import (
    BUILTIN_SPECS,
    Gating,
    Strictness,
    builtin_spec,
    load_spec_file,
    resolve_spec,
)


def test_builtins_cover_broadcast_and_streaming():
    for name in ("ebu_r128", "ebu_r128_s1", "atsc_a85", "op59", "arib_tr_b32", "netflix",
                 "spotify", "youtube", "apple_music", "apple_podcasts", "podcast"):
        assert name in BUILTIN_SPECS
    r128 = builtin_spec("EBU_R128")  # case-insensitive
    assert (r128.integrated_lufs, r128.tolerance_lu, r128.max_true_peak_dbtp) == (-23.0, 0.5, -1.0)
    assert builtin_spec("ebu_r128_s1").max_short_term_lufs == -18.0
    assert builtin_spec("atsc_a85").max_true_peak_dbtp == -2.0
    assert builtin_spec("netflix").gating is Gating.DIALOGUE
    assert builtin_spec("spotify").strictness is Strictness.ADVISE


def test_unknown_spec_fails_closed():
    with pytest.raises(ConfigError):
        builtin_spec("not_a_spec")


def test_operator_json_spec_loads(tmp_path):
    f = tmp_path / "contract.json"
    f.write_text(json.dumps({"name": "acme_tv", "integrated_lufs": -24, "tolerance_lu": 1,
                             "max_true_peak_dbtp": -2, "max_short_term_lufs": -20}))
    s = resolve_spec(str(f))
    assert s is not None and s.name == "acme_tv" and s.max_short_term_lufs == -20


def test_spec_file_rejects_unknown_keys_and_out_of_range(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"name": "x", "integrated_lufs": -24, "tolerance_lu": 1,
                             "max_true_peak_dbtp": -2, "surprise": 1}))
    with pytest.raises(ConfigError):
        load_spec_file(f)
    f.write_text(json.dumps({"name": "x", "integrated_lufs": 12, "tolerance_lu": 1,
                             "max_true_peak_dbtp": -2}))
    with pytest.raises(ConfigError):
        load_spec_file(f)


def test_spec_file_errors_never_echo_file_contents(tmp_path):
    # A mis-pointed spec path must not become a file-content oracle via validation messages.
    f = tmp_path / "secret.json"
    f.write_text(json.dumps({"name": "TOPSECRET-VALUE-9f2c", "password": "hunter2-ZZZ"}))
    with pytest.raises(ConfigError) as e:
        load_spec_file(f)
    assert "TOPSECRET" not in str(e.value) and "hunter2" not in str(e.value)


def test_spec_file_size_capped(tmp_path):
    f = tmp_path / "huge.json"
    f.write_text("[" + "1," * 100_000 + "1]")
    with pytest.raises(ConfigError):
        load_spec_file(f)
