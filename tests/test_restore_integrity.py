"""Regression: restore_flash must verify a backup against its .meta sha256 before flashing it.

Audit finding (portfolio-audit, 2026-07-13, HIGH): backup_flash records the dump's sha256 in the
.meta for integrity, but restore_flash never consulted it, and the post-write esptool verify_flash
compares the freshly-written flash against the SAME (possibly corrupt) file — so a bit-rotted or
truncated backup was flashed and reported as a *verified* success, bricking the board while claiming
OK. restore_flash now re-hashes the file and refuses to flash a backup whose bytes don't match.
"""
import hashlib

import uf_core.backup as backup


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _make_backup(tmp_path, data: bytes, meta_sha) -> str:
    binp = tmp_path / "esp32_COM4_20260101.bin"
    binp.write_bytes(data)
    if meta_sha is not None:
        (tmp_path / (binp.name + ".meta")).write_text(
            f"chip=esp32\nsha256={meta_sha}\n", encoding="utf-8")
    return str(binp)


def _recorder(monkeypatch):
    """Replace esptool invocation with a recorder that reports success without touching hardware."""
    calls = []

    def fake_run_stream(argv, on_line):
        calls.append(argv)
        return 0

    monkeypatch.setattr(backup, "_run_stream", fake_run_stream)
    return calls


def test_restore_aborts_on_sha256_mismatch(tmp_path, monkeypatch):
    calls = _recorder(monkeypatch)
    path = _make_backup(tmp_path, b"\xff" * 4096, meta_sha="0" * 64)  # .meta sha != file bytes
    lines = []
    rc = backup.restore_flash("COM4", path, lines.append, chip="esp32")
    assert rc == 1
    assert not calls, "esptool must NOT run when the backup fails its integrity check"
    assert any("integrity check FAILED" in ln for ln in lines)


def test_restore_proceeds_on_sha256_match(tmp_path, monkeypatch):
    calls = _recorder(monkeypatch)
    data = b"\xa5" * 8192
    path = _make_backup(tmp_path, data, meta_sha=_sha256_bytes(data))  # correct sha
    lines = []
    rc = backup.restore_flash("COM4", path, lines.append, chip="esp32")
    assert rc == 0
    assert calls, "a good backup should proceed to the esptool write"
    assert any("integrity OK" in ln for ln in lines)


def test_restore_warns_but_proceeds_without_meta(tmp_path, monkeypatch):
    calls = _recorder(monkeypatch)
    path = _make_backup(tmp_path, b"\x00" * 1024, meta_sha=None)  # no .meta at all
    lines = []
    rc = backup.restore_flash("COM4", path, lines.append, chip="esp32")
    assert rc == 0
    assert calls
    assert any("no sha256 in the backup .meta" in ln for ln in lines)
