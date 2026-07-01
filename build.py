#!/usr/bin/env python3
"""
Build standalone executables for Universal Flasher using PyInstaller.

Usage:
    pip install pyinstaller
    python build.py              # builds for the current platform
    python build.py --onefile    # single .exe (slower startup, easier to distribute)

Output goes to dist/
"""

import os
import platform
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

HIDDEN_IMPORTS = [
    "uf_core",
    "uf_core.controller",
    "uf_core.commands",
    "uf_core.parsing",
    "uf_core.capture",
    "uf_core.flasher",
    "uf_core.updater",
    "uf_core.controllers",
    "uf_core.device_detect",
    "uf_core.sd_backend",
    "uf_core.adb_backend",
    "uf_core.cache",
    "uf_core.history",
    "uf_core.update_checker",
    "uf_core.plugins",
    "uf_core.batch",
    "uf_core.backup",
    "uf_core.health",
    "uf_core.uihelp",
    # Software-OS flashing (Kali/Tails/Arch to USB) — reached via conditional imports
    # in gui_qt.app, so pull the module + its Qt tab in defensively for frozen builds.
    "uf_core.os_catalog",
    "gui_qt.software_tab",
    "serial",
    "serial.tools",
    "serial.tools.list_ports",
    "requests",
    "psutil",
    "flask",
    "flask_socketio",
    "engineio",
    "socketio",
]

DATA_FILES = [
    (os.path.join(HERE, "web", "templates"), os.path.join("web", "templates")),
    (os.path.join(HERE, "GUIDE.md"), "."),
    (os.path.join(HERE, "assets", "icon.svg"), "assets"),
    # Software-OS flashing catalog (Kali/Tails/Arch): bundle so --flash-os + the catalog work offline.
    (os.path.join(HERE, "uf_core", "os_catalog.json"), "uf_core"),
]


def build(onefile=False):
    entry = os.path.join(HERE, "gui_qt", "app.py")
    name = "universal-flasher"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", name,
        "--noconfirm",
        "--clean",
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    if platform.system() == "Windows":
        cmd.append("--console")

    for mod in HIDDEN_IMPORTS:
        cmd += ["--hidden-import", mod]

    # esptool loads package DATA at runtime (targets/stub_flasher/*.json). A bare
    # --hidden-import ships the module but NOT that data, so a frozen binary cannot flash.
    # --collect-all pulls esptool's submodules + data + binaries into the bundle.
    cmd += ["--collect-all", "esptool"]

    for src, dst in DATA_FILES:
        sep = ";" if platform.system() == "Windows" else ":"
        cmd += ["--add-data", f"{src}{sep}{dst}"]

    cmd += [
        "--paths", HERE,
        entry,
    ]

    print(f"[*] Building {name} ({'onefile' if onefile else 'onedir'}) for {platform.system()}...")
    print(f"    Entry point: {entry}")
    print(f"    Command: {' '.join(cmd)}\n")

    rc = subprocess.call(cmd, cwd=HERE)
    if rc == 0:
        dist = os.path.join(HERE, "dist")
        print(f"\n[+] Build complete. Output in: {dist}")
        if onefile:
            ext = ".exe" if platform.system() == "Windows" else ""
            print(f"    Executable: {os.path.join(dist, name + ext)}")
        else:
            print(f"    Folder: {os.path.join(dist, name)}")
    else:
        print(f"\n[x] Build failed with exit code {rc}")
    return rc


if __name__ == "__main__":
    onefile = "--onefile" in sys.argv
    sys.exit(build(onefile=onefile))
