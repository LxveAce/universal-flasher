"""Safety tests for uf_core/sd_backend.py — the raw block-device SD writer.

Covers the removable-drive write gate (_validate_write_target), the write_image capacity guard, and the
64-bit ctypes HANDLE marshalling of the raw-disk kernel32 calls. Pure logic + tmp-file dispatch — this
never performs a real SD write. These mirror the equivalent guards in the sister cyber-controller backend.
"""

import pytest

sd = pytest.importorskip("uf_core.sd_backend")


def _noline(_l):
    pass


# ── _validate_write_target (the removable-drive write gate) ────────────────
def test_validate_write_target_returns_matching_removable_card():
    card = {"device": "/dev/sdb", "name": "SD", "removable": True, "size": 16 * 10**9}
    assert sd._validate_write_target("/dev/sdb", [card], _noline) is card


def test_validate_write_target_refuses_non_removable():
    card = {"device": "/dev/sda", "name": "SysDisk", "removable": False, "size": 500 * 10**9}
    with pytest.raises(ValueError):
        sd._validate_write_target("/dev/sda", [card], _noline)


def test_validate_write_target_refuses_at_or_over_cap():
    card = {"device": "/dev/sdb", "name": "Huge", "removable": True, "size": sd._MAX_SD_BYTES}
    with pytest.raises(ValueError):
        sd._validate_write_target("/dev/sdb", [card], _noline)


def test_validate_write_target_device_not_found():
    cards = [{"device": "/dev/sdb", "name": "SD", "removable": True, "size": 0}]
    with pytest.raises(ValueError):
        sd._validate_write_target("/dev/sdz", cards, _noline)


# ── write_image capacity guard (refuse an image larger than the target card) ──
def test_write_image_refuses_image_larger_than_card(tmp_path, monkeypatch):
    img = tmp_path / "big.img"
    img.write_bytes(b"\x00" * 4096)
    dev = r"\\.\PhysicalDrive9"
    monkeypatch.setattr(sd, "detect_sd_cards",
                        lambda on_line: [{"device": dev, "name": "TestCard", "removable": True, "size": 1024}])
    with pytest.raises(ValueError, match="will not fit"):
        sd.write_image(str(img), dev, _noline, confirmed=True)


def test_write_image_allows_image_that_fits(tmp_path, monkeypatch):
    img = tmp_path / "ok.img"
    img.write_bytes(b"\x00" * 512)
    dev = "/dev/sdX"
    monkeypatch.setattr(sd, "detect_sd_cards",
                        lambda on_line: [{"device": dev, "name": "TestCard", "removable": True, "size": 4096}])
    monkeypatch.setattr(sd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sd, "_write_dd", lambda *a, **k: 0)
    assert sd.write_image(str(img), dev, _noline, confirmed=True) == 0


def test_write_image_requires_confirmed(tmp_path):
    img = tmp_path / "x.img"
    img.write_bytes(b"\x00" * 16)
    with pytest.raises(ValueError):
        sd.write_image(str(img), r"\\.\PhysicalDrive9", _noline)  # confirmed defaults to False


# ── ctypes raw-disk HANDLE marshalling (64-bit safety) ────────────────────────
def test_configure_kernel32_marshals_handle_without_overflow():
    import platform
    if platform.system() != "Windows":
        pytest.skip("kernel32 raw-disk marshalling is Windows-only")
    import ctypes
    k = ctypes.windll.kernel32
    sd._configure_kernel32(k)
    # Opening a non-existent physical drive must return INVALID_HANDLE_VALUE cleanly — no OverflowError
    # from a mis-marshalled pointer-sized handle (the exact bug the argtypes declaration prevents).
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    h = k.CreateFileW(r"\\.\PhysicalDrive999", GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    invalid = ctypes.c_void_p(-1).value
    assert h in (invalid, 0, None)
    if h not in (invalid, 0, None):
        k.CloseHandle(h)
