"""Tests for the Universal Flasher Software-OS catalog (uf_core/os_catalog.py).

Network + the destructive device write are mocked (monkeypatch).
"""

from __future__ import annotations

import hashlib

import pytest

from uf_core import os_catalog as oc


def _silent(_):
    pass


@pytest.fixture()
def img(tmp_path):
    p = tmp_path / "os-image.iso"
    p.write_bytes(b"OS-IMAGE-CONTENT" * 2000)
    return str(p), hashlib.sha256(p.read_bytes()).hexdigest()


def test_load_catalog_has_three_oses():
    ids = {i.id for i in oc.load_catalog()}
    assert {"tails", "kali", "arch"} <= ids
    assert oc.get_image("kali").verify_model == "checksums_sig"
    assert oc.get_image("arch").image_type == "iso"


def test_host_allowlist():
    assert oc._host_allowed("cdimage.kali.org") is True
    assert oc._host_allowed("geo.mirror.pkgbuild.com") is True
    assert oc._host_allowed("evil.example.com") is False
    with pytest.raises(ValueError):
        oc._require_os_url("https://evil.example.com/x.iso")
    with pytest.raises(ValueError):
        oc._require_os_url("http://cdimage.kali.org/x.iso")


def test_parse_sha256sums():
    body = ("a" * 64 + "  kali-linux-2026.2-live-amd64.iso\n"
            + "b" * 64 + " *kali-linux-2026.2-installer-amd64.iso\n")
    assert oc.parse_sha256sums(body, "kali-linux-2026.2-live-amd64.iso") == "a" * 64
    assert oc.parse_sha256sums(body, "nope.iso") is None


def test_resolve_kali(monkeypatch):
    body = "c" * 64 + "  kali-linux-2026.2-live-amd64.iso\n"
    monkeypatch.setattr(oc, "_http_get_text", lambda url, timeout=30: body)
    r = oc.resolve(oc.get_image("kali"), _silent, online=True)
    assert r.version == "2026.2" and r.sha256 == "c" * 64
    assert r.image_url == "https://cdimage.kali.org/current/kali-linux-2026.2-live-amd64.iso"


def test_resolve_arch(monkeypatch):
    feed = {"latest_version": "2026.06.01", "releases": [
        {"version": "2026.06.01", "available": True, "iso_url": "/iso/2026.06.01/archlinux-2026.06.01-x86_64.iso",
         "sha256_sum": "f" * 64, "pgp_fingerprint": "ABCD1234", "release_date": "2026-06-01"},
    ]}
    monkeypatch.setattr(oc, "_http_get_json", lambda url, timeout=30: feed)
    r = oc.resolve(oc.get_image("arch"), _silent, online=True)
    assert r.version == "2026.06.01" and r.gpg_fingerprint == "ABCD1234"
    assert r.sig_url == r.image_url + ".sig"


def test_resolve_tails(monkeypatch):
    feed = {"version": "7.9", "installations": [
        {"url": "https://download.tails.net/tails/stable/tails-amd64-7.9/tails-amd64-7.9.img",
         "sha256": "1" * 64}]}
    monkeypatch.setattr(oc, "_http_get_json", lambda url, timeout=30: feed)
    r = oc.resolve(oc.get_image("tails"), _silent, online=True)
    assert r.version == "7.9" and r.sha256 == "1" * 64
    assert r.sig_url == "https://tails.net/torrents/files/tails-amd64-7.9.img.sig"


def test_resolve_offline_uses_pinned():
    r = oc.resolve(oc.get_image("arch"), _silent, online=False)
    assert r.source == "pinned" and r.version == "2026.06.01"


def test_resolve_falls_back_on_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("down")
    monkeypatch.setattr(oc, "_http_get_text", boom)
    assert oc.resolve(oc.get_image("kali"), _silent, online=True).source == "pinned"


def _resolved_image_sig(sha):
    return oc.Resolved(image_id="arch", version="x", image_url="https://x", image_type="iso",
                       verify_model="image_sig", sha256=sha)


def test_flash_requires_confirmation(img):
    path, sha = img
    with pytest.raises(ValueError, match="confirmed=True"):
        oc.flash_os_image(oc.get_image("arch"), _resolved_image_sig(sha), path,
                          r"\\.\PhysicalDrive9", _silent, confirmed=False)


def test_flash_success_with_sha(img, monkeypatch):
    path, sha = img
    monkeypatch.setattr(oc.sd, "write_image", lambda *a, **k: 0)
    monkeypatch.setattr(oc.sd, "verify_write", lambda *a, **k: True)
    assert oc.flash_os_image(oc.get_image("arch"), _resolved_image_sig(sha), path,
                             r"\\.\PhysicalDrive9", _silent, confirmed=True) == 0


def test_flash_rejects_sha_mismatch(img, monkeypatch):
    path, _sha = img
    wrote = {"x": False}
    monkeypatch.setattr(oc.sd, "write_image", lambda *a, **k: wrote.__setitem__("x", True) or 0)
    with pytest.raises(ValueError, match="SHA-256"):
        oc.flash_os_image(oc.get_image("arch"), _resolved_image_sig("0" * 64), path,
                          r"\\.\PhysicalDrive9", _silent, confirmed=True)
    assert wrote["x"] is False


def test_flash_checksums_sig_bad_sig_refuses(img, monkeypatch):
    path, sha = img
    monkeypatch.setattr(oc, "verify_gpg_detached", lambda *a, **k: False)
    monkeypatch.setattr(oc.sd, "write_image", lambda *a, **k: 0)
    r = oc.Resolved(image_id="kali", version="2026.2", image_url="https://x", image_type="iso",
                    verify_model="checksums_sig", sha256=sha)
    with pytest.raises(ValueError, match="SHA256SUMS signature"):
        oc.flash_os_image(oc.get_image("kali"), r, path, r"\\.\PhysicalDrive9", _silent,
                          checksums_path=path, checksums_sig_path=path + ".gpg", confirmed=True)


# ── UF-4a: verify hardening (fail-closed + no GPG short-circuit + guarded redirects) ──────────

def test_flash_image_sig_enforces_sha_even_when_gpg_passes(img, monkeypatch):
    """Belt-and-suspenders: a GPG 'pass' must NOT short-circuit the pinned SHA-256 — this closes the
    'GPG accepted by ANY keyring key' fail-open (e.g. Arch pins no fingerprint)."""
    path, _sha = img
    monkeypatch.setattr(oc, "verify_gpg_detached", lambda *a, **k: True)   # pretend GPG verified
    wrote = {"x": False}
    monkeypatch.setattr(oc.sd, "write_image", lambda *a, **k: wrote.__setitem__("x", True) or 0)
    r = _resolved_image_sig("0" * 64)                                       # sha256 will NOT match
    with pytest.raises(ValueError, match="SHA-256"):
        oc.flash_os_image(oc.get_image("arch"), r, path, r"\.\PhysicalDrive9", _silent,
                          sig_path=path + ".sig", confirmed=True)
    assert wrote["x"] is False                                             # never wrote despite GPG 'pass'


def test_flash_fails_closed_when_unverified(img, monkeypatch):
    """No signature and no expected SHA-256 -> refuse to write (was warn-and-write, a fail-open)."""
    path, _sha = img
    wrote = {"x": False}
    monkeypatch.setattr(oc.sd, "write_image", lambda *a, **k: wrote.__setitem__("x", True) or 0)
    r = _resolved_image_sig("")                                            # no sha256, no sig passed
    with pytest.raises(ValueError, match="UNVERIFIED"):
        oc.flash_os_image(oc.get_image("arch"), r, path, r"\.\PhysicalDrive9", _silent, confirmed=True)
    assert wrote["x"] is False


class _FakeResp:
    def __init__(self, redirect=False, location=""):
        self.is_redirect = redirect
        self.is_permanent_redirect = False
        self.headers = {"Location": location}

    def close(self):
        pass


def test_guarded_get_rejects_redirect_off_allowlist(monkeypatch):
    """The metadata GET must re-validate each redirect hop against the allowlist (SSRF), like download()."""
    monkeypatch.setattr(oc.requests, "get",
                        lambda url, **k: _FakeResp(redirect=True, location="https://evil.example.com/x"))
    with pytest.raises(ValueError):
        oc._guarded_get("https://cdimage.kali.org/meta.json")


def test_guarded_get_returns_non_redirect_response(monkeypatch):
    resp = _FakeResp(redirect=False)
    monkeypatch.setattr(oc.requests, "get", lambda url, **k: resp)
    assert oc._guarded_get("https://cdimage.kali.org/meta.json") is resp
