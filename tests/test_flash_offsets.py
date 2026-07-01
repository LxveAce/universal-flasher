"""Regression tests for per-chip bootloader flash offsets.

The second-stage bootloader offset is baked into the flash plan; writing it to the wrong
address is a brick (the ROM can't find the bootloader on the next boot). The offsets MUST
match esptool's per-target BOOTLOADER_FLASH_OFFSET.

Regression target: ESP32-C5 was previously grouped with the 0x0 chips and had its bootloader
written to 0x0 — but the C5 (like the P4/H4) uses 0x2000. These are pure, deterministic
mapping checks; no hardware, network, or serial device is touched (the one support-file path
that fetches over the network is monkeypatched to a local stub).
"""

from __future__ import annotations

import pytest

from uf_core import flasher


def _silent(_):
    pass


class TestBootloaderOffset:
    @pytest.mark.parametrize("chip,offset", [
        ("esp32", "0x1000"),      # classic ESP32
        ("esp32s2", "0x1000"),
        ("esp32s3", "0x0"),
        ("esp32c2", "0x0"),
        ("esp32c3", "0x0"),
        ("esp32c6", "0x0"),
        ("esp32c61", "0x0"),
        ("esp32h2", "0x0"),
        ("esp32c5", "0x2000"),    # <-- the bug: C5 is 0x2000, NOT 0x0
        ("esp32p4", "0x2000"),
        ("esp32h4", "0x2000"),
    ])
    def test_offset_matches_esptool(self, chip, offset):
        assert flasher._bootloader_offset(chip) == offset

    def test_c5_is_not_in_the_zero_set(self):
        # C5 must never be treated as a 0x0-bootloader chip again.
        assert "esp32c5" not in flasher._BOOTLOADER_0
        assert flasher._bootloader_offset("esp32c5") != "0x0"


class TestSupportFilesUseCorrectOffset:
    """The offset the helper returns is the one that actually lands in the flash plan."""

    def test_div_support_files_place_c5_bootloader_at_0x2000(self, monkeypatch):
        # Stub the network fetch so support_files stays hardware/network-free; it returns the
        # local dest path it was asked to write to.
        monkeypatch.setattr(flasher, "_fetch_div_file",
                            lambda rel_path, dest, on_line: dest)
        support = flasher.Esp32DivProfile().support_files("esp32c5", "/tmp/cache", _silent)
        assert support is not None
        # bootloader offset key must be 0x2000 for the C5 (was 0x0 before the fix)
        assert "0x2000" in support
        assert "0x0" not in support
        # partitions / boot_app0 are unchanged
        assert "0x8000" in support and "0xe000" in support

    def test_div_support_files_place_esp32_bootloader_at_0x1000(self, monkeypatch):
        monkeypatch.setattr(flasher, "_fetch_div_file",
                            lambda rel_path, dest, on_line: dest)
        support = flasher.Esp32DivProfile().support_files("esp32", "/tmp/cache", _silent)
        assert "0x1000" in support and "0x8000" in support and "0xe000" in support

    def test_div_support_files_place_s3_bootloader_at_0x0(self, monkeypatch):
        monkeypatch.setattr(flasher, "_fetch_div_file",
                            lambda rel_path, dest, on_line: dest)
        support = flasher.Esp32DivProfile().support_files("esp32s3", "/tmp/cache", _silent)
        assert "0x0" in support and "0x8000" in support and "0xe000" in support
