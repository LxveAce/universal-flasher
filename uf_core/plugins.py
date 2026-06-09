"""Community firmware plugin system — load custom firmware profiles from JSON files."""

import json
import os
import re
import shutil
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .flasher import FirmwareProfile, IMAGE_MERGED, IMAGE_MULTI

Line = Callable[[str], None]

_REQUIRED_FIELDS = ("id", "label", "repo", "flash_method", "supported_chips")
_OPTIONAL_FIELDS = {
    "image_model": "merged",
    "release_asset_pattern": r".*\.bin$",
    "default_board_hint": "",
    "baud": 921600,
    "notes": "",
}


def plugin_dir() -> str:
    """Return the platform-appropriate plugin directory, creating it if needed."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        d = os.path.join(base, "universal-flasher", "plugins")
    else:
        d = os.path.join(os.path.expanduser("~"), ".universal-flasher", "plugins")
    os.makedirs(d, exist_ok=True)
    return d


def _validate_plugin(data: Any, source: str = "<unknown>") -> Dict[str, Any]:
    """Validate plugin JSON structure. Raises ValueError with a clear message on failure."""
    if not isinstance(data, dict):
        raise ValueError(f"{source}: plugin must be a JSON object, got {type(data).__name__}")

    for field in _REQUIRED_FIELDS:
        if field not in data:
            raise ValueError(f"{source}: missing required field {field!r}")

    pid = data["id"]
    if not isinstance(pid, str) or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", pid):
        raise ValueError(f"{source}: 'id' must be an alphanumeric string (got {pid!r})")

    if not isinstance(data["label"], str) or not data["label"].strip():
        raise ValueError(f"{source}: 'label' must be a non-empty string")

    repo = data["repo"]
    if not isinstance(repo, str) or "/" not in repo or len(repo.split("/")) != 2:
        raise ValueError(f"{source}: 'repo' must be 'owner/name' format (got {repo!r})")

    method = data["flash_method"]
    if method not in ("esptool", "qflipper", "dfu", "uf2"):
        raise ValueError(f"{source}: 'flash_method' must be one of esptool/qflipper/dfu/uf2 (got {method!r})")

    chips = data["supported_chips"]
    if not isinstance(chips, list) or not chips:
        raise ValueError(f"{source}: 'supported_chips' must be a non-empty list")
    for chip in chips:
        if not isinstance(chip, str):
            raise ValueError(f"{source}: 'supported_chips' entries must be strings")

    model = data.get("image_model", "merged")
    if model not in ("merged", "multi"):
        raise ValueError(f"{source}: 'image_model' must be 'merged' or 'multi' (got {model!r})")

    pattern = data.get("release_asset_pattern", r".*\.bin$")
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"{source}: 'release_asset_pattern' is not a valid regex: {e}")

    baud = data.get("baud", 921600)
    if not isinstance(baud, int) or baud <= 0:
        raise ValueError(f"{source}: 'baud' must be a positive integer (got {baud!r})")

    return data


class PluginProfile(FirmwareProfile):
    """A FirmwareProfile constructed from a plugin JSON file."""

    def __init__(self, data: Dict[str, Any]):
        self.id = data["id"]
        self.label = data["label"]
        self.repo = data["repo"]
        self.supports_suicide = False
        self._flash_method = data["flash_method"]
        self._supported_chips = data["supported_chips"]
        self._asset_pattern = re.compile(data.get("release_asset_pattern", r".*\.bin$"))
        self._default_board_hint = data.get("default_board_hint", "")
        self._baud = data.get("baud", 921600)
        self.notes = data.get("notes", "")
        model = data.get("image_model", "merged")
        self.image_model = IMAGE_MERGED if model == "merged" else IMAGE_MULTI

    def latest_release(self) -> Tuple[str, List[Dict]]:
        """Fetch latest release from the plugin's GitHub repo."""
        import urllib.request
        api_url = f"https://api.github.com/repos/{self.repo}/releases/latest"
        req = urllib.request.Request(api_url, headers={"User-Agent": "universal-flasher"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = json.loads(resp.read().decode("utf-8"))

        tag = release.get("tag_name", "latest")
        assets: List[Dict] = []
        for a in release.get("assets", []):
            name = a.get("name", "")
            if not self._asset_pattern.search(name):
                continue
            # try to guess chip from the name or default to the first supported chip
            chip = self._supported_chips[0]
            name_lower = name.lower()
            for c in self._supported_chips:
                if c.lower().replace("esp32", "esp32").replace("-", "") in name_lower.replace("-", ""):
                    chip = c
                    break
            assets.append({
                "name": name,
                "url": a.get("browser_download_url"),
                "chip": chip,
                "label": f"{self.label} - {name}",
                "offset": "0x0" if self.image_model == IMAGE_MERGED else "0x10000",
                "merged": self.image_model == IMAGE_MERGED,
            })
        return tag, assets

    def default_variant(self, assets: List[Dict], chip: str) -> Optional[Dict]:
        cands = self.variants_for_chip(assets, chip)
        if self._default_board_hint:
            hint = self._default_board_hint.lower()
            for a in cands:
                if hint in a["name"].lower():
                    return a
        return cands[0] if cands else None

    def support_files(self, chip: str, cache: str, on_line: Line) -> Optional[Dict[str, str]]:
        return None

    def app_offset(self, chip: str) -> str:
        return "0x0" if self.image_model == IMAGE_MERGED else "0x10000"

    def flash_assets(self, port: str, chip: str, app_path: str, on_line: Line,
                     mode: str = "app", baud: int = 0,
                     support: Optional[Dict[str, str]] = None,
                     app_offset: Optional[str] = None,
                     flash_freq: Optional[str] = None) -> int:
        if baud == 0:
            baud = self._baud
        return super().flash_assets(port, chip, app_path, on_line, mode=mode, baud=baud,
                                    support=support, app_offset=app_offset, flash_freq=flash_freq)


def load_plugins() -> List[PluginProfile]:
    """Scan the plugin directory, validate JSON, return list of PluginProfile objects."""
    d = plugin_dir()
    plugins: List[PluginProfile] = []
    if not os.path.isdir(d):
        return plugins

    for filename in sorted(os.listdir(d)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(d, filename)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            validated = _validate_plugin(data, source=filename)
            plugins.append(PluginProfile(validated))
        except (OSError, json.JSONDecodeError, ValueError):
            # skip malformed plugins silently; the UI can call load_plugins_with_errors for details
            continue
    return plugins


def load_plugins_with_errors() -> Tuple[List[PluginProfile], List[Tuple[str, str]]]:
    """Like load_plugins, but also returns (filename, error_message) for any that failed."""
    d = plugin_dir()
    plugins: List[PluginProfile] = []
    errors: List[Tuple[str, str]] = []
    if not os.path.isdir(d):
        return plugins, errors

    for filename in sorted(os.listdir(d)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(d, filename)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            validated = _validate_plugin(data, source=filename)
            plugins.append(PluginProfile(validated))
        except (OSError, json.JSONDecodeError) as e:
            errors.append((filename, f"invalid JSON: {e}"))
        except ValueError as e:
            errors.append((filename, str(e)))
    return plugins, errors


def register_plugins(profiles_dict: Dict[str, FirmwareProfile]) -> List[str]:
    """Load plugins and add them to the profiles registry. Returns list of registered IDs."""
    plugins = load_plugins()
    registered: List[str] = []
    for plugin in plugins:
        profiles_dict[plugin.id] = plugin
        registered.append(plugin.id)
    return registered


def install_plugin(json_path: str) -> str:
    """Copy a plugin JSON file into the plugin directory. Returns the plugin ID."""
    if not os.path.isfile(json_path):
        raise FileNotFoundError(f"plugin file not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    validated = _validate_plugin(data, source=json_path)
    pid = validated["id"]

    dest = os.path.join(plugin_dir(), f"{pid}.json")
    shutil.copy2(json_path, dest)
    return pid


def uninstall_plugin(plugin_id: str) -> bool:
    """Remove a plugin JSON from the plugin directory. Returns True if removed."""
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", plugin_id):
        raise ValueError(f"invalid plugin id: {plugin_id!r}")

    path = os.path.join(plugin_dir(), f"{plugin_id}.json")
    if os.path.isfile(path):
        os.remove(path)
        return True
    return False
