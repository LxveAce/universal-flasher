"""Tests for the hardware-free security guards.

These cover the pure, deterministic validation paths that gate every download,
cache write, destructive SD/USB write, plugin load, and the frozen-binary esptool
dispatch. No hardware, network, or serial device is touched.
"""

from __future__ import annotations

import json
import sys

import pytest

from uf_core import flasher, plugins
from uf_core import sd_backend as sd


def _silent(_):
    pass


# --------------------------------------------------------------------------- #
# flasher SSRF allowlist + cache-name traversal guard
# --------------------------------------------------------------------------- #

class TestFlasherRequireAllowedUrl:
    @pytest.mark.parametrize("url", [
        "https://api.github.com/repos/x/y/releases/latest",
        "https://github.com/x/y/releases/download/v1/a.bin",
        "https://objects.githubusercontent.com/z/a.bin",
        "https://objects-origin.githubusercontent.com/z/a.bin",
    ])
    def test_accepts_allowlisted_https(self, url):
        assert flasher._require_allowed_url(url) == url

    @pytest.mark.parametrize("url", [
        "http://github.com/x/y/a.bin",                 # non-https
        "https://evil.example.com/a.bin",              # off-allowlist host
        "https://raw.githubusercontent.com.evil.com/a",  # suffix spoof
        "https://169.254.169.254/latest/meta-data/",   # metadata SSRF
        "",                                            # empty
    ])
    def test_rejects_bad_url(self, url):
        with pytest.raises(ValueError):
            flasher._require_allowed_url(url)


class TestFlasherSafeCacheName:
    @pytest.mark.parametrize("name", ["marauder.bin", "esp32_marauder.ino.bin"])
    def test_accepts_plain_basename(self, name):
        assert flasher._safe_cache_name(name) == name

    @pytest.mark.parametrize("name", [
        "", ".", "..",
        "../evil.bin",
        "..\\evil.bin",
        "a/b.bin",
        "a\\b.bin",
        "/abs/evil.bin",
        "C:\\evil.bin",
        "\\\\host\\share\\evil.bin",
    ])
    def test_rejects_traversal(self, name):
        with pytest.raises(ValueError):
            flasher._safe_cache_name(name)


# --------------------------------------------------------------------------- #
# flasher.esptool_argv: frozen vs source dispatch
# --------------------------------------------------------------------------- #

class TestEsptoolArgv:
    def test_source_branch_uses_python_m_esptool(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        argv = flasher.esptool_argv("version")
        assert argv == [sys.executable, "-m", "esptool", "version"]

    def test_frozen_branch_uses_multicall_sentinel(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        argv = flasher.esptool_argv("--port", "COM5", "chip_id")
        assert argv == [sys.executable, flasher.ESPTOOL_SUBCMD, "--port", "COM5", "chip_id"]
        assert "-m" not in argv  # must NOT re-exec `python -m esptool` when frozen


# --------------------------------------------------------------------------- #
# sd_backend SSRF allowlist + filename + destructive-write target guard
# --------------------------------------------------------------------------- #

class TestSdBackendRequireAllowedUrl:
    @pytest.mark.parametrize("url", [
        "https://api.github.com/repos/x/y/releases/latest",
        "https://kali.download/arm-images/kali.img.xz",
        "https://cdimage.kali.download/x.img.xz",
        "https://objects.githubusercontent.com/z/a.img",
    ])
    def test_accepts_allowlisted_https(self, url):
        assert sd._require_allowed_url(url) == url

    @pytest.mark.parametrize("url", [
        "http://kali.download/x.img.xz",   # non-https
        "https://evil.example.com/x.img",  # off-allowlist
        "ftp://github.com/x",              # non-https scheme
        "",
    ])
    def test_rejects_bad_url(self, url):
        with pytest.raises(ValueError):
            sd._require_allowed_url(url)


class TestSdBackendSafeFilename:
    @pytest.mark.parametrize("name", ["kali.img.xz", "pwnagotchi-2.0.img"])
    def test_accepts_plain_basename(self, name):
        assert sd._safe_filename(name) == name

    @pytest.mark.parametrize("name", [
        "", ".", "..",
        "../evil.img",
        "..\\evil.img",
        "a/b.img",
        "/abs/evil.img",
        "C:\\evil.img",
    ])
    def test_rejects_traversal(self, name):
        with pytest.raises(ValueError):
            sd._safe_filename(name)


class TestSdBackendValidateWriteTarget:
    def _card(self, device, removable=True, size=16 * (1 << 30)):
        return {"device": device, "name": "USB", "size": size,
                "bus": "USB", "removable": removable}

    def test_accepts_removable_in_range(self):
        cards = [self._card(r"\\.\PhysicalDrive9")]
        got = sd._validate_write_target(r"\\.\PhysicalDrive9", cards, _silent)
        assert got["device"] == r"\\.\PhysicalDrive9"

    def test_rejects_non_removable(self):
        cards = [self._card(r"\\.\PhysicalDrive0", removable=False)]
        with pytest.raises(ValueError, match="non-removable"):
            sd._validate_write_target(r"\\.\PhysicalDrive0", cards, _silent)

    def test_rejects_over_size_ceiling(self):
        cards = [self._card("/dev/sdz", size=sd._MAX_SD_BYTES + 1)]
        with pytest.raises(ValueError, match="256 GB"):
            sd._validate_write_target("/dev/sdz", cards, _silent)

    def test_rejects_unknown_device(self):
        cards = [self._card("/dev/sdb")]
        with pytest.raises(ValueError, match="not found"):
            sd._validate_write_target("/dev/sdX", cards, _silent)


# --------------------------------------------------------------------------- #
# plugins._validate_plugin: accept + reject
# --------------------------------------------------------------------------- #

def _valid_plugin():
    return {
        "id": "myfw",
        "label": "My Firmware",
        "repo": "owner/name",
        "flash_method": "esptool",
        "supported_chips": ["esp32", "esp32s3"],
    }


class TestValidatePlugin:
    def test_accepts_minimal_valid(self):
        assert plugins._validate_plugin(_valid_plugin())["id"] == "myfw"

    def test_rejects_non_object(self):
        with pytest.raises(ValueError):
            plugins._validate_plugin(["not", "a", "dict"])

    @pytest.mark.parametrize("field", ["id", "label", "repo", "flash_method", "supported_chips"])
    def test_rejects_missing_required_field(self, field):
        data = _valid_plugin()
        del data[field]
        with pytest.raises(ValueError, match=field):
            plugins._validate_plugin(data)

    def test_rejects_bad_id(self):
        data = _valid_plugin()
        data["id"] = "../evil"
        with pytest.raises(ValueError, match="id"):
            plugins._validate_plugin(data)

    def test_rejects_bad_repo(self):
        data = _valid_plugin()
        data["repo"] = "not-a-repo"
        with pytest.raises(ValueError, match="repo"):
            plugins._validate_plugin(data)

    def test_rejects_unknown_flash_method(self):
        data = _valid_plugin()
        data["flash_method"] = "magic"
        with pytest.raises(ValueError, match="flash_method"):
            plugins._validate_plugin(data)

    def test_rejects_empty_supported_chips(self):
        data = _valid_plugin()
        data["supported_chips"] = []
        with pytest.raises(ValueError, match="supported_chips"):
            plugins._validate_plugin(data)

    def test_rejects_bad_regex_pattern(self):
        data = _valid_plugin()
        data["release_asset_pattern"] = "([unclosed"
        with pytest.raises(ValueError, match="regex"):
            plugins._validate_plugin(data)

    def test_rejects_non_positive_baud(self):
        data = _valid_plugin()
        data["baud"] = 0
        with pytest.raises(ValueError, match="baud"):
            plugins._validate_plugin(data)

    @pytest.mark.parametrize("method", ["qflipper", "dfu", "uf2"])
    def test_rejects_unwired_flash_methods(self, method):
        # PluginProfile only dispatches esptool today; accepting these would silently flash with the wrong tool.
        data = _valid_plugin()
        data["flash_method"] = method
        with pytest.raises(ValueError, match="flash_method"):
            plugins._validate_plugin(data)


class TestRegisterPlugins:
    def test_dropped_in_plugin_appears_in_registry(self, tmp_path, monkeypatch):
        # A valid plugin JSON dropped into the plugin dir must be wired into the profile registry
        # (regression guard: register_plugins() is now called at uf_core import; without it the feature is inert).
        pdir = tmp_path / "plugins"
        pdir.mkdir()
        (pdir / "myfw.json").write_text(json.dumps(_valid_plugin()), encoding="utf-8")
        monkeypatch.setattr(plugins, "plugin_dir", lambda: str(pdir))
        registry: dict = {}
        registered = plugins.register_plugins(registry)
        assert "myfw" in registered
        assert "myfw" in registry
        assert registry["myfw"].label == "My Firmware"
