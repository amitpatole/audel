"""Phase 9: the golden-corpus benchmark — every deterministic detector fires on its defect and
stays quiet on clean material (the synthetic corpus must grade 100% exact)."""

from __future__ import annotations

import json
import shutil

import pytest

from audel.bench import load_corpus, synthetic_bench
from audel.errors import ConfigError

requires_ffmpeg = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")


@requires_ffmpeg
def test_synthetic_corpus_grades_exactly(tmp_path):
    res = synthetic_bench(tmp_path)
    assert res.cases >= 20
    assert res.exact == res.cases, res.misses
    for name in ("integrated_loudness", "true_peak_ceiling", "clipping", "max_short_term",
                 "dead_channel", "polarity_inversion", "phase", "dc_offset", "hum", "noise_floor",
                 "silence_gap", "silent_track", "truncation"):
        sc = res.per_check[name]
        assert sc.recall == 1.0 and sc.precision == 1.0, (name, sc)


def test_corpus_labels_cannot_escape_the_directory(tmp_path):
    (tmp_path / "labels.json").write_text(json.dumps([{"file": "../../etc/passwd", "expect": []}]))
    with pytest.raises(ConfigError):
        load_corpus(tmp_path)


def test_corpus_labels_shape_validated(tmp_path):
    (tmp_path / "labels.json").write_text(json.dumps([{"file": "a.wav", "expect": "hum"}]))
    with pytest.raises(ConfigError):
        load_corpus(tmp_path)
