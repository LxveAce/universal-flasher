"""Software-OS flashing catalog: write bootable PC/USB operating systems to a USB stick.

Universal Flasher's "Software" side (parallel to firmware): flash whole-disk OS images (Tails, Kali,
Arch, ...) to a removable USB. Self-contained (Universal Flasher has no tails.py): this module owns the
catalog, the latest-version resolvers, and the verification chain, and reuses the hardened removable-
only writer in :mod:`uf_core.sd_backend` for the destructive device write.

Each catalog entry resolves its LATEST version live from upstream so the tool never ships stale:
  * Tails -> the installer feed (latest.json) on tails.net
  * Kali  -> parse ``cdimage.kali.org/current/SHA256SUMS`` (``current`` always = latest)
  * Arch  -> the machine-readable feed ``archlinux.org/releng/releases/json/``
If there is no network, the bundled **pinned** version in ``os_catalog.json`` is used (full offline).

Verification models (per upstream):
  * ``image_sig``     (Tails, Arch): detached OpenPGP ``.sig`` over the IMAGE itself.
  * ``checksums_sig`` (Kali): OpenPGP ``.gpg`` over a ``SHA256SUMS`` file listing the image hash.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from shutil import which
from typing import Any, Callable, Dict, List, Optional

import requests

from uf_core import sd_backend as sd

log = logging.getLogger(__name__)
Line = Callable[[str], None]
Progress = Optional[Callable[[float], None]]

# SSRF allowlist for OS metadata + image downloads (scoped to this module; does not widen the
# firmware flasher's allowlist).
_OS_HOSTS = frozenset((
    "tails.net", "download.tails.net", "tails.boum.org", "dl.amnesia.boum.org",
    "cdimage.kali.org", "kali.download",
    "archlinux.org", "www.archlinux.org", "geo.mirror.pkgbuild.com",
))
_OS_HOST_SUFFIXES = (".tails.net", ".boum.org", ".kali.org", ".archlinux.org", ".mirror.pkgbuild.com")


def _host_allowed(host: Optional[str]) -> bool:
    if not host:
        return False
    h = host.lower().split("@")[-1].split(":")[0]
    return h in _OS_HOSTS or any(h.endswith(s) for s in _OS_HOST_SUFFIXES)


def _require_os_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "https":
        raise ValueError(f"refusing non-https OS URL: {url!r}")
    if not _host_allowed(parts.hostname):
        raise ValueError(f"refusing OS URL to non-allowlisted host {parts.hostname!r}")
    return url


def _catalog_path() -> str:
    mp = getattr(sys, "_MEIPASS", None)
    if mp:
        p = os.path.join(mp, "uf_core", "os_catalog.json")
        if os.path.isfile(p):
            return p
    return os.path.join(os.path.dirname(__file__), "os_catalog.json")


# ── catalog model ────────────────────────────────────────────────────

@dataclass
class OSImage:
    id: str
    name: str
    category: str
    description: str
    homepage: str
    image_type: str
    resolver: str
    verify_model: str
    gpg_fingerprint: Optional[str]
    pinned: Dict[str, Any]
    extra: Dict[str, Any]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "OSImage":
        known = {"id", "name", "category", "description", "homepage", "image_type",
                 "resolver", "verify_model", "gpg_fingerprint", "pinned"}
        return cls(
            id=d["id"], name=d["name"], category=d.get("category", ""),
            description=d.get("description", ""), homepage=d.get("homepage", ""),
            image_type=d.get("image_type", "img"), resolver=d["resolver"],
            verify_model=d.get("verify_model", "image_sig"),
            gpg_fingerprint=d.get("gpg_fingerprint"), pinned=d.get("pinned", {}),
            extra={k: v for k, v in d.items() if k not in known},
        )


@dataclass
class Resolved:
    image_id: str
    version: str
    image_url: str
    image_type: str
    verify_model: str
    sig_url: Optional[str] = None
    checksums_url: Optional[str] = None
    checksums_sig_url: Optional[str] = None
    sha256: Optional[str] = None
    gpg_fingerprint: Optional[str] = None
    source: str = "online"


def load_catalog(path: Optional[str] = None) -> List[OSImage]:
    with open(path or _catalog_path(), "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [OSImage.from_dict(d) for d in data.get("images", [])]


def get_image(image_id: str, path: Optional[str] = None) -> OSImage:
    for img in load_catalog(path):
        if img.id == image_id:
            return img
    raise KeyError(f"no such OS image in catalog: {image_id!r}")


def list_images(path: Optional[str] = None) -> List[Dict[str, str]]:
    return [{"id": i.id, "name": i.name, "category": i.category,
             "description": i.description, "image_type": i.image_type}
            for i in load_catalog(path)]


# ── HTTP helpers (allowlisted; monkeypatched in tests) ───────────────

def _http_get_text(url: str, timeout: int = 30) -> str:
    _require_os_url(url)
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def _http_get_json(url: str, timeout: int = 30) -> Any:
    _require_os_url(url)
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ── resolvers ────────────────────────────────────────────────────────

def parse_sha256sums(text: str, filename: str) -> Optional[str]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"([0-9a-fA-F]{64})[ \t*]+(.+)$", line)
        if m and os.path.basename(m.group(2).strip()) == filename:
            return m.group(1).lower()
    return None


def _resolve_tails(entry: OSImage, on_line: Line) -> Resolved:
    feed = entry.extra.get("tails_feed_url", "https://tails.net/install/v2/Tails/amd64/stable/latest.json")
    data = _http_get_json(feed)
    found: Dict[str, Any] = {}

    def walk(node):
        if isinstance(node, dict):
            url = node.get("url") or node.get("href")
            sha = node.get("sha256") or node.get("sha-256") or node.get("hash")
            if isinstance(url, str) and url.lower().endswith(".img") and isinstance(sha, str):
                found.setdefault("url", url)
                found.setdefault("sha256", sha)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    if "url" not in found:
        raise RuntimeError("tails feed had no recognizable .img + sha256")
    img_url = _require_os_url(found["url"])
    base = os.path.basename(urllib.parse.urlsplit(img_url).path)
    sig_url = _require_os_url(f"https://tails.net/torrents/files/{base}.sig")
    ver = str((data.get("version") if isinstance(data, dict) else None) or "").strip()
    if not ver or ver.lower() == "none":
        m = re.search(r"tails-amd64-([0-9][0-9.]*)\.img", base)
        ver = m.group(1) if m else "?"
    return Resolved(image_id=entry.id, version=ver, image_url=img_url,
                    image_type=entry.image_type, verify_model="image_sig", sig_url=sig_url,
                    sha256=found.get("sha256"), gpg_fingerprint=entry.gpg_fingerprint)


def _resolve_kali(entry: OSImage, on_line: Line) -> Resolved:
    sums_url = entry.pinned["checksums_url"]
    text = _http_get_text(sums_url)
    variant = entry.extra.get("kali_variant", "live-amd64")
    fname = ver = sha = None
    for line in text.splitlines():
        m = re.match(r"([0-9a-fA-F]{64})[ \t*]+(.+)$", line.strip())
        if not m:
            continue
        name = os.path.basename(m.group(2).strip())
        vm = re.match(rf"kali-linux-(.+?)-{re.escape(variant)}\.iso$", name)
        if vm:
            fname, ver, sha = name, vm.group(1), m.group(1).lower()
            break
    if not fname:
        raise RuntimeError(f"no kali {variant} image found in SHA256SUMS")
    base = sums_url.rsplit("/", 1)[0] + "/"
    img_url = _require_os_url(base + fname)
    return Resolved(image_id=entry.id, version=ver, image_url=img_url,
                    image_type=entry.image_type, verify_model="checksums_sig",
                    checksums_url=sums_url, checksums_sig_url=entry.pinned.get("checksums_sig_url"),
                    sha256=sha, gpg_fingerprint=entry.gpg_fingerprint)


def _resolve_arch(entry: OSImage, on_line: Line) -> Resolved:
    feed = entry.extra.get("arch_feed_url", "https://archlinux.org/releng/releases/json/")
    mirror = entry.extra.get("arch_mirror_base", "https://geo.mirror.pkgbuild.com").rstrip("/")
    data = _http_get_json(feed)
    releases = data.get("releases", []) if isinstance(data, dict) else []
    avail = [r for r in releases if r.get("available") and r.get("iso_url") and r.get("sha256_sum")]
    if not avail:
        raise RuntimeError("no available arch release in feed")
    latest_ver = data.get("latest_version")
    rel = next((r for r in avail if r.get("version") == latest_ver), None) or \
        sorted(avail, key=lambda r: str(r.get("release_date") or ""), reverse=True)[0]
    iso_path = rel["iso_url"]
    img_url = _require_os_url(mirror + iso_path if iso_path.startswith("/") else mirror + "/" + iso_path)
    return Resolved(image_id=entry.id, version=str(rel.get("version") or "?"),
                    image_url=img_url, image_type=entry.image_type, verify_model="image_sig",
                    sig_url=_require_os_url(img_url + ".sig"), sha256=str(rel.get("sha256_sum")).lower(),
                    gpg_fingerprint=rel.get("pgp_fingerprint") or entry.gpg_fingerprint)


_RESOLVERS: Dict[str, Callable[[OSImage, Line], Resolved]] = {
    "tails": _resolve_tails, "kali": _resolve_kali, "arch": _resolve_arch,
}


def _pinned(entry: OSImage) -> Resolved:
    p = entry.pinned
    return Resolved(image_id=entry.id, version=str(p.get("version") or "?"),
                    image_url=p["image_url"], image_type=entry.image_type,
                    verify_model=entry.verify_model, sig_url=p.get("sig_url"),
                    checksums_url=p.get("checksums_url"), checksums_sig_url=p.get("checksums_sig_url"),
                    sha256=(p.get("sha256") or None), gpg_fingerprint=entry.gpg_fingerprint,
                    source="pinned")


def resolve(entry: OSImage, on_line: Line, online: bool = True) -> Resolved:
    if online:
        fn = _RESOLVERS.get(entry.resolver)
        if fn is not None:
            try:
                r = fn(entry, on_line)
                on_line(f"[os] {entry.name}: latest is {r.version}")
                return r
            except Exception as exc:  # noqa: BLE001
                on_line(f"[os] {entry.name}: could not resolve latest ({exc}); using bundled "
                        f"version {entry.pinned.get('version','?')} (offline).")
    return _pinned(entry)


# ── verification ─────────────────────────────────────────────────────

def verify_sha256(img_path: str, expected_sha256: str, on_line: Line,
                  on_progress: Progress = None) -> bool:
    want = (expected_sha256 or "").strip().lower().replace(" ", "")
    if len(want) != 64 or not re.fullmatch(r"[0-9a-f]{64}", want):
        on_line(f"[os] invalid expected SHA-256: {expected_sha256!r}")
        return False
    actual = sd.sha256_file(img_path, on_line, on_progress).lower()
    ok = hmac.compare_digest(actual, want)
    on_line("[os] SHA-256 " + ("MATCH" if ok else f"MISMATCH (expected {want})"))
    return ok


def _gpg() -> Optional[str]:
    for cand in ("gpg", "gpg2"):
        if which(cand):
            return cand
    return None


def verify_gpg_detached(target_path: str, sig_path: str, fingerprint: Optional[str],
                        on_line: Line) -> Optional[bool]:
    gpg = _gpg()
    if not gpg:
        on_line("[os] gpg not found — skipping signature check (SHA-256 will be used instead).")
        return None
    try:
        proc = subprocess.run([gpg, "--status-fd", "1", "--verify", sig_path, target_path],
                              capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        on_line(f"[os] gpg verify error: {exc}")
        return None
    status = proc.stdout + proc.stderr
    flat = status.replace(" ", "")
    good = ("VALIDSIG" in status or "GOODSIG" in status)
    if fingerprint:
        good = good and fingerprint.replace(" ", "") in flat
    on_line("[os] GPG signature " + ("VALID" if good else "NOT valid for the expected key"))
    return good


# ── download (allowlisted, redirect-following) ───────────────────────

def download(url: str, dest_dir: str, on_line: Line, on_progress: Progress = None) -> str:
    _require_os_url(url)
    os.makedirs(dest_dir, exist_ok=True)
    name = sd._safe_filename(url.rsplit("/", 1)[-1].split("?")[0]) or "download.bin"
    dest = os.path.join(dest_dir, name)
    current = url
    for _ in range(8):
        resp = requests.get(current, stream=True, timeout=120, allow_redirects=False)
        if resp.is_redirect or resp.is_permanent_redirect:
            current = _require_os_url(resp.headers.get("Location", ""))
            resp.close()
            continue
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0) or 0)
        written = 0
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
                written += len(chunk)
                if on_progress and total:
                    on_progress(min(written / total, 1.0))
        on_line(f"[os] downloaded {written} bytes -> {dest}")
        return dest
    raise ValueError("too many redirects fetching the OS file")


# ── flash pipeline ───────────────────────────────────────────────────

def flash_os_image(entry: OSImage, resolved: Resolved, image_path: str, device: str, on_line: Line,
                   on_progress: Progress = None, sig_path: Optional[str] = None,
                   checksums_path: Optional[str] = None, checksums_sig_path: Optional[str] = None,
                   confirmed: bool = False) -> int:
    if not confirmed:
        raise ValueError("flash requires confirmed=True — the entire target USB will be erased")
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"OS image not found: {image_path}")

    fpr = resolved.gpg_fingerprint or entry.gpg_fingerprint
    verified = False

    if resolved.verify_model == "checksums_sig":
        sums_ok: Optional[bool] = None
        if checksums_path and checksums_sig_path:
            sums_ok = verify_gpg_detached(checksums_path, checksums_sig_path, fpr, on_line)
            if sums_ok is False:
                raise ValueError("SHA256SUMS signature is NOT valid for the expected key — refusing.")
        expected = resolved.sha256
        if not expected and checksums_path and os.path.isfile(checksums_path):
            with open(checksums_path, "r", encoding="utf-8", errors="replace") as fh:
                expected = parse_sha256sums(fh.read(), os.path.basename(image_path))
        if expected:
            if not verify_sha256(image_path, expected, on_line, on_progress):
                raise ValueError("SHA-256 does not match SHA256SUMS — refusing to write.")
            verified = True
        if verified and sums_ok is not True:
            on_line("[os] NOTE: checksum matched but the SHA256SUMS GPG signature was not verified "
                    "(gpg missing or signature file absent). Verify the signature for full assurance.")
    else:
        if sig_path:
            result = verify_gpg_detached(image_path, sig_path, fpr, on_line)
            if result is True:
                verified = True
            elif result is False:
                raise ValueError("GPG signature is NOT valid for the expected key — refusing to write.")
        if not verified and resolved.sha256:
            if not verify_sha256(image_path, resolved.sha256, on_line, on_progress):
                raise ValueError("SHA-256 does not match — refusing to write an unverified image.")
            verified = True

    if not verified:
        on_line(f"[os] WARNING: {entry.name} image is UNVERIFIED (no valid signature/checksum). "
                "Strongly verify against the official source before writing.")

    rc = sd.write_image(image_path, device, on_line, on_progress, confirmed=True)
    if rc != 0:
        on_line(f"[os] write FAILED (exit {rc})")
        return rc
    on_line("[os] verifying write (read-back)...")
    if sd.verify_write(image_path, device, on_line, on_progress):
        on_line(f"[os] done — {entry.name} USB is ready. Boot the target machine from this USB.")
        return 0
    on_line("[os] read-back verification FAILED — the USB may be bad; re-flash.")
    return 1


# ── CLI surfaces ─────────────────────────────────────────────────────

def list_catalog_cli() -> int:
    print("=== Universal Flasher — Software OS catalog (flash to USB) ===")
    for i in load_catalog():
        print(f"  {i.id:<8} {i.name:<22} [{i.category}] ({i.image_type})")
        print(f"           {i.description}")
    print("\nFlash with:  universal-flasher --flash-os <id> [--os-image <local.iso/.img>] "
          "[--os-target <device>] [--offline] [--yes]")
    return 0


def run_os_flash_cli(image_id: str, target: Optional[str] = None, image: Optional[str] = None,
                     sig: Optional[str] = None, assume_yes: bool = False, offline: bool = False) -> int:
    import tempfile

    def on(s: str) -> None:
        print(s)

    try:
        entry = get_image(image_id)
    except KeyError:
        avail = ", ".join(i["id"] for i in list_images())
        print(f"Unknown OS id {image_id!r}. Available: {avail}", file=sys.stderr)
        return 2

    print(f"=== Universal Flasher — flash {entry.name} to USB ===")
    print("Writes a verified bootable OS image to a removable USB. The ENTIRE target USB is erased.\n")

    resolved = resolve(entry, on, online=not offline)
    img = image
    sig_path = sig
    checksums_path = checksums_sig_path = None
    cache = os.path.join(tempfile.gettempdir(), f"uf_os_{entry.id}")

    if not img:
        try:
            img = download(resolved.image_url, cache, on)
            if resolved.verify_model == "image_sig" and resolved.sig_url and not sig_path:
                try:
                    sig_path = download(resolved.sig_url, cache, on)
                except (requests.RequestException, ValueError, OSError) as exc:
                    on(f"[os] could not fetch signature ({exc}); will fall back to SHA-256.")
            if resolved.verify_model == "checksums_sig":
                if resolved.checksums_url:
                    checksums_path = download(resolved.checksums_url, cache, on)
                if resolved.checksums_sig_url:
                    try:
                        checksums_sig_path = download(resolved.checksums_sig_url, cache, on)
                    except (requests.RequestException, ValueError, OSError) as exc:
                        on(f"[os] could not fetch SHA256SUMS signature ({exc}).")
        except (requests.RequestException, ValueError, OSError) as exc:
            print(f"Download failed: {exc}\nDownload {entry.name} manually from {entry.homepage} "
                  f"(verify it!) and pass --os-image <path>.", file=sys.stderr)
            return 1

    cards = sd.detect_sd_cards(on)
    if not cards:
        print("No removable USB drives detected. Insert a USB stick and retry.", file=sys.stderr)
        return 1
    dev = target
    if not dev:
        print("\n  Removable drives:")
        for i, c in enumerate(cards, 1):
            gb = (c.get("size") or 0) / (1 << 30)
            print(f"    {i}) {c['device']}  {c.get('name','')}  {gb:.1f} GB")
        raw = input("  Pick a drive number (or device path): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(cards):
            dev = cards[int(raw) - 1]["device"]
        elif raw:
            dev = raw
        else:
            print("No drive chosen — aborted.", file=sys.stderr)
            return 2

    if not assume_yes:
        print(f"\n*** This will ERASE EVERYTHING on {dev} and write {entry.name} {resolved.version}. ***")
        if input(f"  Type the device to confirm ({dev}): ").strip() != dev:
            print("Confirmation mismatch — aborted.", file=sys.stderr)
            return 2

    try:
        return flash_os_image(entry, resolved, img, dev, on, sig_path=sig_path,
                              checksums_path=checksums_path, checksums_sig_path=checksums_sig_path,
                              confirmed=True)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"Flash aborted: {exc}", file=sys.stderr)
        return 1
