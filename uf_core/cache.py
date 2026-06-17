"""Offline firmware cache — download and store firmware binaries for field deployment without internet."""

import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

Line = Callable[[str], None]

_lock = threading.Lock()


def _safe_basename(name: str) -> str:
    """Reject any name that is not a plain, safe basename."""
    if not isinstance(name, str) or name in ("", ".", ".."):
        raise ValueError(f"refusing unsafe name: {name!r}")
    if os.path.basename(name) != name:
        raise ValueError(f"refusing non-basename name: {name!r}")
    if os.path.isabs(name):
        raise ValueError(f"refusing absolute name: {name!r}")
    drive, _ = os.path.splitdrive(name)
    if drive:
        raise ValueError(f"refusing name with drive/UNC prefix: {name!r}")
    norm = name.replace(chr(92), "/")
    if ".." in norm.split("/") or "/" in norm:
        raise ValueError(f"refusing name with path separator/'..': {name!r}")
    return name


def cache_dir() -> str:
    """Return the platform-appropriate firmware cache directory, creating it if needed."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        d = os.path.join(base, "universal-flasher", "cache")
    else:
        d = os.path.join(os.path.expanduser("~"), ".universal-flasher", "cache")
    os.makedirs(d, exist_ok=True)
    return d


def cache_firmware(profile_id: str, tag: str, asset_name: str, data: bytes) -> str:
    """Store a firmware binary in the cache. Returns the path to the cached file."""
    safe_profile = _safe_basename(profile_id)
    safe_tag = _safe_basename(tag)
    safe_asset = _safe_basename(asset_name)

    dest_dir = os.path.join(cache_dir(), safe_profile, safe_tag)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, safe_asset)

    real_dir = os.path.realpath(dest_dir)
    real_dest = os.path.realpath(dest)
    if real_dest != os.path.join(real_dir, safe_asset) and not real_dest.startswith(real_dir + os.sep):
        raise ValueError(f"refusing cache path that escapes the cache dir: {dest!r}")

    with _lock:
        with open(dest, "wb") as f:
            f.write(data)
    return dest


def get_cached(profile_id: str, tag: str, asset_name: str) -> Optional[str]:
    """Return path to a cached firmware file, or None if not cached."""
    safe_profile = _safe_basename(profile_id)
    safe_tag = _safe_basename(tag)
    safe_asset = _safe_basename(asset_name)

    path = os.path.join(cache_dir(), safe_profile, safe_tag, safe_asset)
    return path if os.path.isfile(path) else None


def list_cached() -> Dict[str, List[Dict[str, Any]]]:
    """Return all cached firmware: {profile_id: [{tag, asset_name, size, cached_at}]}."""
    result: Dict[str, List[Dict[str, Any]]] = {}
    root = cache_dir()
    if not os.path.isdir(root):
        return result

    for profile_id in sorted(os.listdir(root)):
        profile_dir = os.path.join(root, profile_id)
        if not os.path.isdir(profile_dir):
            continue
        entries: List[Dict[str, Any]] = []
        for tag in sorted(os.listdir(profile_dir)):
            tag_dir = os.path.join(profile_dir, tag)
            if not os.path.isdir(tag_dir):
                continue
            for asset_name in sorted(os.listdir(tag_dir)):
                asset_path = os.path.join(tag_dir, asset_name)
                if not os.path.isfile(asset_path):
                    continue
                stat = os.stat(asset_path)
                entries.append({
                    "tag": tag,
                    "asset_name": asset_name,
                    "size": stat.st_size,
                    "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
                })
        if entries:
            result[profile_id] = entries
    return result


def cache_size() -> int:
    """Return total bytes used by the cache."""
    total = 0
    root = cache_dir()
    if not os.path.isdir(root):
        return 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total


def clear_cache(profile_id: Optional[str] = None) -> None:
    """Delete cached files. If profile_id is given, only clear that profile's cache."""
    root = cache_dir()
    with _lock:
        if profile_id is not None:
            safe = _safe_basename(profile_id)
            target = os.path.join(root, safe)
            if os.path.isdir(target):
                shutil.rmtree(target)
        else:
            if os.path.isdir(root):
                shutil.rmtree(root)
            os.makedirs(root, exist_ok=True)


def preload_all(profiles: Dict[str, Any], on_line: Line) -> None:
    """Download latest firmware for every profile into cache for offline use.

    `profiles` is the PROFILES dict from flasher.py (profile_id -> FirmwareProfile).
    """
    from .flasher import _http_get, _require_allowed_url

    for pid, profile in profiles.items():
        if profile.repo is None:
            continue
        on_line(f"[cache] checking {profile.label} ...")
        try:
            tag, assets = profile.latest_release()
        except Exception as e:
            on_line(f"[cache] failed to fetch release for {pid}: {e}")
            continue

        if not assets:
            on_line(f"[cache] no assets for {pid}")
            continue

        for asset in assets:
            name = asset.get("name", "")
            url = asset.get("url")
            if not name or not url:
                continue
            existing = get_cached(pid, tag, name)
            if existing:
                on_line(f"[cache] already cached: {pid}/{tag}/{name}")
                continue
            on_line(f"[cache] downloading {pid}/{tag}/{name} ...")
            try:
                _require_allowed_url(url)
                data = _http_get(url)
                cache_firmware(pid, tag, name, data)
                on_line(f"[cache] cached {len(data)} bytes -> {pid}/{tag}/{name}")
            except Exception as e:
                on_line(f"[cache] failed to download {name}: {e}")
