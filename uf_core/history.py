"""Flash history log — persistent record of every flash operation performed."""

import json
import os
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional

Line = Callable[[str], None]

_MAX_ENTRIES = 1000
_lock = threading.Lock()


def _history_path() -> str:
    """Return the platform-appropriate history file path."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        d = os.path.join(base, "universal-flasher")
    else:
        d = os.path.join(os.path.expanduser("~"), ".universal-flasher")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "history.json")


def _read_entries() -> List[Dict[str, Any]]:
    """Read the history file. Returns empty list if missing or corrupt."""
    path = _history_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return []


def _write_entries(entries: List[Dict[str, Any]]) -> None:
    """Atomically write entries to the history file."""
    path = _history_path()
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp", prefix="history_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
        # atomic rename (Windows: remove first since os.rename can't overwrite)
        if sys.platform == "win32" and os.path.exists(path):
            os.replace(tmp, path)
        else:
            os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def record_flash(profile_id: str, version: str, chip: str, port: str,
                 mode: str, success: bool, duration_ms: int,
                 profile_label: str = "", error: str = "") -> None:
    """Append a flash operation entry with timestamp. Auto-prunes to _MAX_ENTRIES."""
    entry: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profile_id": profile_id,
        "profile_label": profile_label,
        "version": version,
        "chip": chip,
        "port": port,
        "mode": mode,
        "success": success,
        "duration_ms": duration_ms,
        "error": error,
    }
    with _lock:
        entries = _read_entries()
        entries.append(entry)
        if len(entries) > _MAX_ENTRIES:
            entries = entries[-_MAX_ENTRIES:]
        _write_entries(entries)


def get_history(limit: int = 50, profile_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return recent flash entries (newest first), optionally filtered by profile_id."""
    with _lock:
        entries = _read_entries()
    if profile_id is not None:
        entries = [e for e in entries if e.get("profile_id") == profile_id]
    # newest first
    entries.reverse()
    return entries[:limit]


def get_device_history(port: str) -> Optional[Dict[str, Any]]:
    """Return the most recent flash entry for a given port, or None."""
    with _lock:
        entries = _read_entries()
    for entry in reversed(entries):
        if entry.get("port") == port:
            return entry
    return None


def clear_history() -> None:
    """Wipe the entire flash history log."""
    with _lock:
        _write_entries([])
