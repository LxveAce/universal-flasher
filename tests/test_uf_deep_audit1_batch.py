"""Regression guards for the uf-deep-audit-1 survivors shipped 2026-07-14 (ledger uf-pass1).

Five fixes across the flash-verify-integrity + self-wipe-safety surface, each re-confirmed against
the real code before fixing (verify-never-fake):

#2 (HIGH) suicide/__init__.py::build_bundle — the package-level API every UI calls hashed the
   password WITHOUT provision.validate_password(), so an ARMED board could bake a pwhash the firmware
   can never reproduce (>63 bytes / leading-trailing whitespace / `unlock ` prefix), and the owner's
   OWN correct password would be counted as a failed attempt and, after max_att, self-wipe the board.
   Fix: call prov.validate_password(pw_buf) before hashing (parity with provision.build_bundle).

#6 (MED) sd_backend.verify_write — the Unix read-back used a plain unprivileged open(); when the
   write ran via `sudo dd` (non-root) that open() is denied -> a GOOD write was reported as a verify
   FAILURE. Fix: fall back to a `sudo dd` read-back at the same privilege (drained SIGPIPE-safe).

#7 (MED) sd_backend.verify_write — Linux read the BUFFERED block device with no cache-drop (macOS
   already uses the unbuffered /dev/rdisk), so a corrupt write could pass verify from the page cache.
   Fix: posix_fadvise(DONTNEED) the range before the Linux read-back (_drop_block_cache).

#9 (LOW) os_catalog.download — opened the final dest with open(dest,"wb") (truncates before the new
   bytes exist) and never checked Content-Length, so a dropped connection on a re-run destroyed a
   previously-downloaded good cached image and a short read was returned as complete. Fix: stream to a
   temp sibling, reject a short read, os.replace onto dest (prior file untouched on any failure).

Pure logic + fakes: no hardware, no real device, no network is touched.
"""
import hashlib
import os

import pytest


# ── #2: build_bundle enforces the firmware-parity password guard ──

# _get_provisioner() exec's a fresh provision module per call, so ProvisionError has no stable class
# identity to import — match by type name + message (still fully discriminates the validation error
# from any incidental downstream error on the buggy path, which never carries these messages).

def test_build_bundle_rejects_overlong_password(tmp_path):
    import suicide

    # 64 UTF-8 bytes: the firmware secret buffer is char[64] (63 usable) and clamps before hashing,
    # so an armed board could NEVER match the owner's own correct password -> self-wipe. Must reject.
    with pytest.raises(Exception) as excinfo:
        suicide.build_bundle("x" * 64, out_dir=str(tmp_path))
    assert type(excinfo.value).__name__ == "ProvisionError"
    assert "UTF-8 bytes" in str(excinfo.value)


def test_build_bundle_rejects_unlock_prefixed_password(tmp_path):
    import suicide

    # The serial adapter strips a leading `unlock ` before hashing, so the host must reject it too.
    with pytest.raises(Exception) as excinfo:
        suicide.build_bundle("unlock hunter2", out_dir=str(tmp_path))
    assert type(excinfo.value).__name__ == "ProvisionError"
    assert "unlock" in str(excinfo.value).lower()


# ── #7: Linux verify drops the page cache so it reads the media, not RAM ──

def test_drop_block_cache_calls_fadvise_dontneed(monkeypatch):
    from uf_core import sd_backend as sd

    calls: list = []
    monkeypatch.setattr(sd.os, "posix_fadvise",
                        lambda fd, off, ln, adv: calls.append((fd, off, ln, adv)), raising=False)
    monkeypatch.setattr(sd.os, "POSIX_FADV_DONTNEED", 4, raising=False)
    sd._drop_block_cache(7, 4096)
    assert calls == [(7, 0, 4096, 4)]  # drops the whole image range -> read hits the media


def test_drop_block_cache_noop_without_fadvise(monkeypatch):
    from uf_core import sd_backend as sd

    monkeypatch.delattr(sd.os, "posix_fadvise", raising=False)
    sd._drop_block_cache(7, 4096)  # Windows/macOS lack it -> a silent no-op, not a crash


# ── #6: Unix non-root verify reads back at write-privilege (sudo dd), drained SIGPIPE-safe ──

class _FakePipeProc:
    """Models a `dd` child writing ``data`` into a pipe: if the reader closes stdout before draining
    all of it, the child's next write hits a broken pipe and dd is SIGPIPE-killed (rc 141) — exactly
    what a real subprocess does. A fully-drained pipe lets dd finish and exit 0."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self.returncode = None
        self.stdout = self

    def read(self, n: int = -1) -> bytes:
        chunk = self._data[self._pos:] if n < 0 else self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        pass

    def wait(self) -> None:
        self.returncode = 0 if self._pos >= len(self._data) else 141


def test_verify_read_via_sudo_dd_drains_tail_so_good_write_is_not_sigpipe_failed(monkeypatch):
    from uf_core import sd_backend as sd

    img_size = sd._CHUNK + 512  # NOT a whole block -> dd emits ceil()=2 blocks, a tail past img_size
    blocks = (img_size + sd._CHUNK - 1) // sd._CHUNK
    total = blocks * sd._CHUNK
    payload = b"Z" * img_size
    proc = _FakePipeProc(payload + b"\x00" * (total - img_size))
    monkeypatch.setattr(sd.subprocess, "Popen", lambda *a, **k: proc)

    h = hashlib.sha256()
    ok = sd._verify_read_via_sudo_dd("/dev/sdX", img_size, h, None, lambda ln: None, direct=True)
    assert ok is True                       # a GOOD non-root write must verify, not SIGPIPE-fail
    assert proc.returncode == 0             # dd fully drained -> clean exit (the bug left it 141)
    assert h.hexdigest() == hashlib.sha256(payload).hexdigest()  # hashes only img_size bytes


def test_verify_write_falls_back_to_sudo_dd_when_unprivileged_read_is_denied(monkeypatch, tmp_path):
    from uf_core import sd_backend as sd

    img = tmp_path / "img.bin"
    img.write_bytes(b"HELLO-IMAGE-BYTES")
    monkeypatch.setattr(sd.platform, "system", lambda: "Linux")

    real_open = open

    def selective_open(path, *a, **k):
        if str(path) == "/dev/sdX":
            raise PermissionError("raw device is root-only")  # write ran via sudo dd
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", selective_open)

    def fake_sudo_dd(dev, img_size, h, on_progress, on_line, direct):
        h.update(img.read_bytes())          # simulate reading the good bytes back at write-privilege
        return True

    monkeypatch.setattr(sd, "_verify_read_via_sudo_dd", fake_sudo_dd)
    assert sd.verify_write(str(img), "/dev/sdX", lambda s: None) is True  # good write verifies


# ── #9: a truncated re-download must not clobber a prior good cached image ──

def test_download_truncation_does_not_clobber_prior_cached_image(monkeypatch, tmp_path):
    from uf_core import os_catalog as oc

    class _FakeResp:
        is_redirect = False
        is_permanent_redirect = False
        headers = {"content-length": "100"}

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size=1):
            yield b"X" * 40  # only 40 of the promised 100 bytes -> a silently-truncated stream

        def close(self):
            pass

    monkeypatch.setattr(oc, "_require_os_url", lambda u: u)  # bypass the host allowlist for the test
    monkeypatch.setattr(oc.requests, "get", lambda *a, **k: _FakeResp())

    dest = tmp_path / "current.iso"
    dest.write_bytes(b"PRIOR GOOD IMAGE")  # a previously-downloaded, verified image
    with pytest.raises(ValueError):
        oc.download("https://x/current.iso", str(tmp_path), lambda s: None)

    assert dest.read_bytes() == b"PRIOR GOOD IMAGE"  # the prior cached image survived the truncation
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".uf-os-")]  # temp cleaned up
