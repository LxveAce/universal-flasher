"""Firmware update checker — check for new versions across all firmware profiles."""

import json
import threading
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

Line = Callable[[str], None]

_UA = {"User-Agent": "universal-flasher"}

# rate-limit cache: {api_url: (timestamp, {"tag", "release_notes", "release_url"})}
_api_cache: Dict[str, tuple] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # 5 minutes


@dataclass
class UpdateInfo:
    """Result of checking one profile for updates."""
    profile_id: str
    profile_label: str
    installed_version: str
    latest_version: str
    update_available: bool
    release_url: str = ""
    release_notes: str = ""


def _github_api_url(repo: str) -> str:
    return f"https://api.github.com/repos/{repo}/releases/latest"


def _fetch_release(repo: str) -> Optional[Dict]:
    """Fetch latest release info from GitHub, with 5-minute caching and rate-limit handling."""
    api_url = _github_api_url(repo)

    with _cache_lock:
        cached = _api_cache.get(api_url)
        if cached and (time.time() - cached[0]) < _CACHE_TTL:
            return cached[1]

    try:
        from .flasher import _http_get, _require_allowed_url
        _require_allowed_url(api_url)
        data = json.loads(_http_get(api_url).decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            # rate limited — use cached if available, even if stale
            with _cache_lock:
                if cached:
                    return cached[1]
            return None
        if e.code == 404:
            return None
        raise
    except (urllib.error.URLError, OSError):
        # network error — use stale cache if available
        with _cache_lock:
            if cached:
                return cached[1]
        return None

    result = {
        "tag": data.get("tag_name", ""),
        "release_notes": data.get("body", ""),
        "release_url": data.get("html_url", ""),
    }

    with _cache_lock:
        _api_cache[api_url] = (time.time(), result)

    return result


def _normalize_version(v: str) -> str:
    """Strip common prefixes for comparison."""
    s = v.strip().lower()
    for prefix in ("v", "release-", "release_"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s


def check_single(profile_id: str, installed_version: str,
                 profiles: Optional[Dict] = None) -> Optional[UpdateInfo]:
    """Check one profile for updates. Returns UpdateInfo or None if the profile has no repo."""
    if profiles is None:
        from .flasher import PROFILES
        profiles = PROFILES

    profile = profiles.get(profile_id)
    if profile is None or profile.repo is None:
        return None

    release = _fetch_release(profile.repo)
    if release is None:
        return UpdateInfo(
            profile_id=profile_id,
            profile_label=getattr(profile, "label", profile_id),
            installed_version=installed_version,
            latest_version="unknown",
            update_available=False,
        )

    latest = release["tag"]
    norm_installed = _normalize_version(installed_version)
    norm_latest = _normalize_version(latest)
    update_available = norm_installed != norm_latest and norm_installed != "" and norm_latest != ""

    return UpdateInfo(
        profile_id=profile_id,
        profile_label=getattr(profile, "label", profile_id),
        installed_version=installed_version,
        latest_version=latest,
        update_available=update_available,
        release_url=release.get("release_url", ""),
        release_notes=release.get("release_notes", ""),
    )


def check_updates(installed: Dict[str, str],
                  profiles: Optional[Dict] = None) -> List[UpdateInfo]:
    """Check all profiles in `installed` (profile_id -> version) for updates."""
    if profiles is None:
        from .flasher import PROFILES
        profiles = PROFILES

    results: List[UpdateInfo] = []
    for pid, version in installed.items():
        info = check_single(pid, version, profiles=profiles)
        if info is not None:
            results.append(info)
    return results


def check_updates_background(installed: Dict[str, str],
                             callback: Callable[[List[UpdateInfo]], None],
                             profiles: Optional[Dict] = None,
                             max_workers: int = 4) -> threading.Thread:
    """Run update checks in a thread pool, then invoke callback with results on completion."""
    if profiles is None:
        from .flasher import PROFILES
        profiles = PROFILES

    def _worker() -> None:
        results: List[UpdateInfo] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(check_single, pid, version, profiles): pid
                for pid, version in installed.items()
            }
            for future in as_completed(futures):
                try:
                    info = future.result()
                    if info is not None:
                        results.append(info)
                except Exception:
                    pass
        callback(results)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t
