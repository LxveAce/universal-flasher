"""uf_core.uihelp must import (and expose GLOSSARY) on a headless / no-Tk box.

The Textual TUI, the Flask web UI, and the UI-free engine all import uf_core;
a hard `import tkinter` at module top would break them on installs without
python3-tk. This test simulates tkinter being unavailable and asserts the module
still imports and GLOSSARY stays usable.
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest


def test_uihelp_imports_without_tkinter(monkeypatch):
    # Drop uihelp + tkinter so the reload re-runs the top-level import path.
    monkeypatch.delitem(sys.modules, "uf_core.uihelp", raising=False)
    for name in list(sys.modules):
        if name == "tkinter" or name.startswith("tkinter."):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "tkinter" or name.startswith("tkinter."):
            raise ModuleNotFoundError("No module named 'tkinter' (simulated headless)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    uihelp = importlib.import_module("uf_core.uihelp")

    assert uihelp.tk is None  # soft import degraded gracefully
    assert isinstance(uihelp.GLOSSARY, dict)
    assert "deauth" in uihelp.GLOSSARY
    assert uihelp.GLOSSARY["deauth"]  # plain-data copy is intact
    assert hasattr(uihelp, "Tooltip")  # class object still defined


@pytest.fixture(autouse=True)
def _restore_uihelp():
    # Reload a clean, real-tkinter copy afterward so other tests/imports are unaffected.
    yield
    sys.modules.pop("uf_core.uihelp", None)
    importlib.import_module("uf_core.uihelp")
