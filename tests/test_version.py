"""Lock the single-source-of-truth version invariant.

Frozen binaries have no dist metadata, so the UIs read uf_core.__version__. If that
constant drifts from pyproject.toml, shipped builds report a stale version. This test
fails on any such drift.
"""

from __future__ import annotations

import os

import pytest

import uf_core

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_matches_pyproject():
    tomllib = pytest.importorskip("tomllib")  # stdlib on Python 3.11+
    with open(os.path.join(_ROOT, "pyproject.toml"), "rb") as f:
        pyproject_version = tomllib.load(f)["project"]["version"]
    assert uf_core.__version__ == pyproject_version
