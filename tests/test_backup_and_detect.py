"""Robustness tests for uf_core/backup.py (no silently-truncated backups) and uf_core/device_detect.py
(the serial probe can't hang forever on a continuously-chatty device).

Both guard against a class of bug where the tool proceeds on unverified/partial data: a backup written
at an assumed flash size is a false safety net, and an unbounded read wedges the whole scan thread.
"""

import time

import uf_core.backup as backup
import uf_core.device_detect as dd


# ── backup.py: refuse to guess a flash size (no truncated backup) ──────────
def test_backup_aborts_when_flash_id_fails(tmp_path, monkeypatch):
    """flash_id (size detection) exits non-zero → abort before read_flash, write nothing."""
    calls = []

    def fake_run_stream(argv, on_line):
        calls.append(argv)
        return 1  # flash_id failed

    monkeypatch.setattr(backup, "_run_stream", fake_run_stream)
    lines = []
    out = backup.backup_flash("COM9", lines.append, chip="esp32", output_dir=str(tmp_path))
    assert out is None
    assert len(calls) == 1  # never reached the read_flash call
    assert any("refusing to guess" in l for l in lines)


def test_backup_aborts_when_no_size_line(tmp_path, monkeypatch):
    """flash_id succeeds but its output carries no recognizable size line → abort (don't default to 4MB)."""
    def fake_run_stream(argv, on_line):
        on_line("Chip is ESP32-D0WD (revision v1.0)")  # no "Detected flash size:" line
        return 0

    monkeypatch.setattr(backup, "_run_stream", fake_run_stream)
    lines = []
    out = backup.backup_flash("COM9", lines.append, chip="esp32", output_dir=str(tmp_path))
    assert out is None
    assert any("could not read the flash size" in l for l in lines)


def test_backup_aborts_on_unrecognized_size(tmp_path, monkeypatch):
    """A size string esptool reports that isn't in the map → abort rather than fall back to 4MB."""
    def fake_run_stream(argv, on_line):
        on_line("Detected flash size: 64MB")  # not in size_map
        return 0

    monkeypatch.setattr(backup, "_run_stream", fake_run_stream)
    lines = []
    out = backup.backup_flash("COM9", lines.append, chip="esp32", output_dir=str(tmp_path))
    assert out is None
    assert any("unrecognized flash size" in l for l in lines)


def test_backup_uses_detected_size_not_default(tmp_path, monkeypatch):
    """A real detected size (16MB) is what read_flash + the .meta use — never the old 4MB default."""
    state = {"n": 0}

    def fake_run_stream(argv, on_line):
        state["n"] += 1
        if state["n"] == 1:
            on_line("Detected flash size: 16MB")
            return 0
        dest = argv[-1]  # read_flash writes to the last argv element
        with open(dest, "wb") as f:
            f.write(b"\x00" * 32)
        return 0

    monkeypatch.setattr(backup, "_run_stream", fake_run_stream)
    lines = []
    out = backup.backup_flash("COM9", lines.append, chip="esp32", output_dir=str(tmp_path))
    assert out is not None
    meta = open(out + ".meta", encoding="utf-8").read()
    assert "flash_size=0x1000000" in meta  # 16MB, the detected size — not 0x400000


# ── device_detect.py: the idle read has an absolute ceiling ────────────────
class _ChattyPort:
    """A fake serial port that ALWAYS has bytes waiting — simulates a device streaming continuously."""

    @property
    def in_waiting(self):
        return 4

    def read(self, n):
        return b"log "


def test_read_until_idle_has_hard_ceiling():
    """A never-idle device must not push the deadline forever — the max_total cap bounds total read time."""
    ser = _ChattyPort()
    start = time.monotonic()
    out = ser and dd._read_until_idle(ser, timeout=1.0, max_total=0.3)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0          # returned near max_total (0.3s), not after the 1.0s idle window or forever
    assert isinstance(out, str)
