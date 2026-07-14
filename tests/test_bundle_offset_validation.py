"""read_bundle_manifest must reject an UNPARSEABLE flash offset at parse time.

Regression for a validation gap: read_bundle_manifest documents "raises ValueError if malformed"
and checked that a flash offset was PRESENT, but not that it PARSED — so a manifest entry with an
unparseable offset (e.g. offset_hex "0xZZ", or a non-numeric "offset") slipped past the validator
and only blew up later in _bundle_offset at flash time (an unlabeled ValueError instead of the
clean per-entry "malformed manifest" error every other bad-bundle case raises at parse). This locks
the offset-parseability check into read_bundle_manifest so the contract holds and _bundle_offset can
never raise on a manifest the validator returned.
"""
from __future__ import annotations

import json

import pytest

from uf_core import flasher


def _write_bundle(tmp_path, files) -> str:
    (tmp_path / "bundle.json").write_text(json.dumps({"files": files}), encoding="utf-8")
    return str(tmp_path)


def test_unparseable_offset_hex_is_rejected_at_parse(tmp_path):
    bundle = _write_bundle(tmp_path, [{"file": "app.bin", "offset_hex": "0xZZ"}])
    with pytest.raises(ValueError, match="unparseable offset"):
        flasher.read_bundle_manifest(bundle)


def test_non_numeric_offset_is_rejected_at_parse(tmp_path):
    bundle = _write_bundle(tmp_path, [{"file": "app.bin", "offset": "not-a-number"}])
    with pytest.raises(ValueError, match="unparseable offset"):
        flasher.read_bundle_manifest(bundle)


def test_valid_offsets_still_parse(tmp_path):
    bundle = _write_bundle(tmp_path, [
        {"file": "boot.bin", "offset_hex": "0x1000"},
        {"file": "app.bin", "offset": 65536},
    ])
    manifest = flasher.read_bundle_manifest(bundle)
    assert len(manifest["files"]) == 2
    # A manifest that PASSED validation must resolve every offset without raising.
    assert flasher._bundle_offset(manifest["files"][0]) == 0x1000
    assert flasher._bundle_offset(manifest["files"][1]) == 65536
