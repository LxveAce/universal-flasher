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


# ── _detect_sd_linux excludes the OS/boot disk (incl. a USB-attached root) ────
class _FakeRun:
    def __init__(self, stdout):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


def test_detect_sd_linux_skips_usb_root_disk(monkeypatch):
    import json as _json
    # sda: a USB-attached SSD hosting '/' and '/boot/firmware' (rm=0, tran=usb) — the classic Pi USB-boot
    #      / live-USB case that the bus+removable heuristics alone would wave through. MUST be refused.
    # sdb: a genuine USB SD-card reader, only an auto-mounted data partition — MUST still be offered.
    lsblk = {
        "blockdevices": [
            {"name": "sda", "size": 240 * 10**9, "rm": False, "type": "disk", "tran": "usb",
             "model": "USB-SSD", "mountpoint": None, "children": [
                 {"name": "sda1", "type": "part", "mountpoint": "/boot/firmware"},
                 {"name": "sda2", "type": "part", "mountpoint": "/"},
             ]},
            {"name": "sdb", "size": 16 * 10**9, "rm": True, "type": "disk", "tran": "usb",
             "model": "CardReader", "mountpoint": None, "children": [
                 {"name": "sdb1", "type": "part", "mountpoint": "/media/pi/DATA"},
             ]},
        ]
    }
    monkeypatch.setattr(sd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sd.subprocess, "run", lambda *a, **k: _FakeRun(_json.dumps(lsblk)))
    devs = [c["device"] for c in sd._detect_sd_linux(_noline)]
    assert "/dev/sda" not in devs   # the USB *root* disk is refused (before the fix it was offered)
    assert "/dev/sdb" in devs       # a real removable card reader (only /media mount) is still offered


# ── _detect_sd_macos excludes an external boot/system disk ────────────────────
def test_detect_sd_macos_skips_external_boot_disk(monkeypatch):
    import plistlib

    def _pl(d):
        return plistlib.dumps(d).decode()

    # '/' is on an APFS volume whose container's physical store is disk2 → disk2 is the boot disk.
    root_info = {"ParentWholeDisk": "disk9", "APFSPhysicalStores": [{"DeviceIdentifier": "disk2s2"}]}
    list_ext = {"WholeDisks": ["disk2", "disk4"]}
    disk2 = {"TotalSize": 240 * 10**9, "Removable": False, "Internal": False,
             "MediaName": "External Boot SSD", "BusProtocol": "USB"}       # external BUT is the boot disk
    disk4 = {"TotalSize": 32 * 10**9, "Removable": True, "Internal": False,
             "MediaName": "SD Card", "BusProtocol": "USB"}                 # a genuine external SD card

    def fake_run(cmd, **k):
        if cmd[:3] == ["diskutil", "list", "-plist"]:
            return _FakeRun(_pl(list_ext))
        if cmd[:3] == ["diskutil", "info", "-plist"]:
            info = {"/": root_info, "disk2": disk2, "disk4": disk4}.get(cmd[3], {})
            return _FakeRun(_pl(info))
        return _FakeRun("")

    monkeypatch.setattr(sd.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(sd.subprocess, "run", fake_run)
    devs = [c["device"] for c in sd._detect_sd_macos(_noline)]
    assert "/dev/disk2" not in devs   # the external *boot* disk is refused (before the fix it was offered)
    assert "/dev/disk4" in devs       # a genuine external SD card is still offered


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


# ── download_image atomic-download (a mid-stream failure must not clobber a cached image) ──────────

class _FakeResp:
    """Minimal streaming requests.Response stand-in for download_image."""
    def __init__(self, chunks, content_length, raise_after=None):
        self._chunks = chunks
        self.headers = {"content-length": str(content_length)} if content_length is not None else {}
        self.is_redirect = False
        self.is_permanent_redirect = False
        self._raise_after = raise_after

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=None):
        for i, c in enumerate(self._chunks):
            if self._raise_after is not None and i == self._raise_after:
                raise OSError("simulated dropped connection mid-download")
            yield c


_IMG_URL = "https://github.com/o/r/releases/download/v1/test.img"


def _no_temp_left(dest_dir):
    import os
    return not any(n.endswith(".part") or n.startswith(".uf-img-") for n in os.listdir(dest_dir))


def test_download_image_mid_stream_failure_keeps_cached_file(tmp_path, monkeypatch):
    # A prior GOOD cached image must survive a dropped-connection re-download — never truncated to a
    # partial that a later flash could then write to an SD card.
    dest = tmp_path / "test.img"
    dest.write_bytes(b"GOOD-CACHED-IMAGE")
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: _FakeResp([b"AAAA", b"BBBB"], 8, raise_after=1))
    with pytest.raises(OSError):
        sd.download_image(_IMG_URL, str(tmp_path), _noline)
    assert dest.read_bytes() == b"GOOD-CACHED-IMAGE"   # untouched
    assert _no_temp_left(str(tmp_path))                 # no partial temp left behind


def test_download_image_short_read_rejected(tmp_path, monkeypatch):
    # Content-Length claims 100 but only 8 bytes arrive (silent truncation) -> reject, cache nothing.
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: _FakeResp([b"AAAA", b"BBBB"], 100))
    with pytest.raises(ValueError, match="truncated"):
        sd.download_image(_IMG_URL, str(tmp_path), _noline)
    assert not (tmp_path / "test.img").exists()
    assert _no_temp_left(str(tmp_path))


def test_download_image_happy_path_writes_complete_file(tmp_path, monkeypatch):
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: _FakeResp([b"AAAA", b"BBBB"], 8))
    out = sd.download_image(_IMG_URL, str(tmp_path), _noline)
    assert out == str(tmp_path / "test.img")
    assert (tmp_path / "test.img").read_bytes() == b"AAAABBBB"
    assert _no_temp_left(str(tmp_path))
