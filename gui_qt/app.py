#!/usr/bin/env python3
"""
Universal Flasher — PyQt5 desktop GUI.

Multi-firmware flasher and device manager for ESP32, Raspberry Pi, Flipper Zero, and
ADB-based security hardware. Built on the Headless Marauder scaffold.

Run:   python3 gui_qt/app.py            (auto-detects the port)
       python3 gui_qt/app.py --port /dev/ttyUSB0
       python3 gui_qt/app.py --mock     (no hardware, for trying the UI)

Needs PyQt5:   sudo apt install -y python3-pyqt5     (or: pip install PyQt5)
"""

import argparse
import os
import queue
import sys

# Multi-call binary: when the frozen build re-execs itself to run esptool
# (see uf_core.flasher.esptool_argv), dispatch here before importing the GUI stack.
if getattr(sys, "frozen", False) and len(sys.argv) >= 2 and sys.argv[1] == "--__uf-esptool__":
    import esptool
    sys.exit(esptool.main(sys.argv[2:]))

# Software-OS catalog CLI: list/flash bootable OS images (Kali/Tails/Arch) to USB without the GUI.
if "--list-os" in sys.argv or "--flash-os" in sys.argv:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from uf_core import os_catalog as _oc
    _p = argparse.ArgumentParser(prog="universal-flasher")
    _p.add_argument("--list-os", action="store_true", help="List flashable OSes, then exit.")
    _p.add_argument("--flash-os", default=None, metavar="ID", help="Flash an OS (kali/tails/arch) to USB.")
    _p.add_argument("--os-image", default=None, help="Local OS image (.iso/.img) instead of downloading.")
    _p.add_argument("--os-sig", default=None, help="Detached OpenPGP .sig for image_sig OSes.")
    _p.add_argument("--os-target", default=None, help="Target removable device; skips the picker.")
    _p.add_argument("--offline", action="store_true", help="Use the bundled (pinned) version.")
    _p.add_argument("--yes", action="store_true", help="Skip the destructive-write confirmation.")
    _a, _ = _p.parse_known_args()
    if _a.list_os:
        sys.exit(_oc.list_catalog_cli())
    sys.exit(_oc.run_os_flash_cli(_a.flash_os, target=_a.os_target, image=_a.os_image,
                                  sig=_a.os_sig, assume_yes=_a.yes, offline=_a.offline))

import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QKeySequence
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QPlainTextEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QGroupBox, QScrollArea, QSplitter, QDialog,
    QFormLayout, QCheckBox, QRadioButton, QFileDialog, QMessageBox, QAbstractItemView,
    QHeaderView, QButtonGroup, QAction, QShortcut, QStatusBar, QTextBrowser, QSpinBox,
)

from uf_core import (
    MarauderController, MarauderParser, CaptureLogger, commands, flasher, updater, __version__,
)
from uf_core import uihelp

GLOSSARY = uihelp.GLOSSARY

# Scan commands that should kick off auto "list" polling so the tables fill themselves.
_AP_SCANS = {"scanap", "scanall"}
_STA_SCANS = {"scansta"}


def _clean_manifest_field(value, max_len: int = 64) -> str:
    """Sanitize an operator-facing string pulled from a (possibly tampered) bundle.json.

    A bundle.json is untrusted data: a hostile variant/name/board/chip could embed control
    characters, newlines, or megabytes of text to spoof or disrupt the suicide confirmation
    dialog (e.g. fake a benign board name, push the real warning off-screen). We coerce to str,
    strip C0/C1/DEL control chars, collapse runs of whitespace, and length-cap with an ellipsis
    so the confirm dialog always shows a short, honest label. Empty/None becomes "?".
    """
    if value is None:
        return "?"
    s = str(value)
    # Drop C0 (<0x20), C1 (0x80-0x9f) and DEL (0x7f) control chars; turn any whitespace
    # (incl. newlines/tabs) into a single space, keep other printable text as-is.
    out = []
    for ch in s:
        o = ord(ch)
        if ch.isspace():
            out.append(" ")
        elif o < 0x20 or o == 0x7f or 0x80 <= o <= 0x9f:
            continue
        else:
            out.append(ch)
    cleaned = " ".join("".join(out).split())   # collapse whitespace runs, strip ends
    if not cleaned:
        return "?"
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len - 1] + "…"
    return cleaned


def _cmd_tooltip(c) -> str:
    """Hover text for a command button: what it does + key behaviour flags."""
    tip = c.desc or c.label
    extra = []
    if c.danger:
        extra.append("⚠ attack — authorized targets only")
    if c.longrunning:
        extra.append("runs until STOP")
    if c.params:
        extra.append("opens options")
    if extra:
        tip += "\n(" + "; ".join(extra) + ")"
    tip += f"\nsends:  {c.base}"
    return tip

DARK_QSS = """
QWidget { background: #0b0f0a; color: #c8f7c5; font-size: 12px; }
QGroupBox { border: 1px solid #1d2b18; border-radius: 6px; margin-top: 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; color: #39ff14; }
QPushButton { background: #14210f; border: 1px solid #2a3d22; border-radius: 5px; padding: 6px 8px; min-height: 26px; }
QPushButton:hover { background: #1c3016; border-color: #39ff14; }
QPushButton#danger { color: #ff6b6b; border-color: #5a2222; }
QPushButton#stop { background: #ff4d4d; color: #ffffff; font-weight: bold; }
QPlainTextEdit, QTableWidget { background: #05080a; color: #39ff14; border: 1px solid #1d2b18; }
QLineEdit, QComboBox { background: #11160f; border: 1px solid #2a3d22; border-radius: 4px; padding: 5px; min-height: 22px; }
QHeaderView::section { background: #14210f; color: #39ff14; border: 0; padding: 5px; }
QTabBar::tab { background: #11160f; padding: 8px 14px; }
QTabBar::tab:selected { background: #1c3016; color: #39ff14; }
QCheckBox { spacing: 6px; }
QMenuBar { background: #11160f; } QMenuBar::item:selected { background: #1c3016; }
QMenu { background: #11160f; border: 1px solid #2a3d22; } QMenu::item:selected { background: #1c3016; }
QStatusBar { background: #11160f; color: #7a8f76; }
QLabel#status_ok { color: #39ff14; }
QLabel#status_bad { color: #ff4d4d; }
"""


# --------------------------------------------------------------------------- #
class ParamDialog(QDialog):
    def __init__(self, parent, cmd):
        super().__init__(parent)
        self.setWindowTitle(cmd.label)
        self.cmd = cmd
        self.widgets = {}
        lay = QVBoxLayout(self)
        if cmd.desc:
            lay.addWidget(QLabel(cmd.desc))
        form = QFormLayout()
        for p in cmd.params:
            if p.kind == "bool":
                w = QCheckBox()
            elif p.kind == "select":
                w = QComboBox(); w.addItems(p.choices)
            else:
                w = QLineEdit(); w.setPlaceholderText(p.placeholder or p.help)
            # Always give every input a tooltip; fall back to the param name/kind if no help copy.
            tip = p.help or p.placeholder or f"{p.name} ({p.kind})" + (" — required" if p.required else "")
            w.setToolTip(tip)
            self.widgets[p.name] = w
            form.addRow(p.name + (" *" if p.required else ""), w)
        lay.addLayout(form)
        row = QHBoxLayout()
        ok = QPushButton("RUN ⚠" if cmd.danger else "Run"); ok.clicked.connect(self._ok)
        ok.setToolTip("Build and send this command with the values above"
                      + (" (this is an attack — authorized targets only)" if cmd.danger else "") + ".")
        cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject)
        cancel.setToolTip("Close without sending anything.")
        row.addWidget(ok); row.addWidget(cancel); lay.addLayout(row)
        self.values = None

    def _ok(self):
        vals = {}
        for p in self.cmd.params:
            w = self.widgets[p.name]
            if isinstance(w, QCheckBox):
                vals[p.name] = w.isChecked()
            elif isinstance(w, QComboBox):
                vals[p.name] = w.currentText()
            else:
                vals[p.name] = w.text()
            if p.required and not isinstance(w, QCheckBox) and not str(vals[p.name]).strip():
                QMessageBox.warning(self, "Missing", f"'{p.name}' is required.")
                return
            if p.kind == "int" and str(vals[p.name]).strip():
                try:
                    vals[p.name] = int(str(vals[p.name]).strip())
                except ValueError:
                    QMessageBox.warning(self, "Invalid number", f"'{p.name}' must be a whole number.")
                    return
        self.values = vals
        self.accept()


# --------------------------------------------------------------------------- #
class TargetPicker(QDialog):
    """Pick APs to select from the parsed list (index-accurate) + manual fallback."""

    def __init__(self, parent, controller, parser, base, list_cmd, kind="ap"):
        super().__init__(parent)
        self.ctl = controller
        self.parser = parser
        self.base = base               # e.g. "select -a"
        self.list_cmd = list_cmd       # e.g. "list -a"
        self.kind = kind               # "ap" or "sta"
        self.result_cmd = None
        self.setWindowTitle("Select targets")
        self.resize(580, 500)
        self._checks = []

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"Pick targets for  <b>{base}</b>  —  check rows, or type below"))

        row = QHBoxLayout()
        rb = QPushButton(f"⟳ Refresh ({list_cmd})"); rb.clicked.connect(self._refresh); row.addWidget(rb)
        rb.setToolTip(f"Re-run '{list_cmd}' on the board and repopulate this list with the latest results.")
        self.allbox = QCheckBox("select all"); self.allbox.stateChanged.connect(self._toggle_all); row.addWidget(self.allbox)
        self.allbox.setToolTip("Check/uncheck every row at once.")
        row.addStretch(); lay.addLayout(row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["pick", "#", "SSID / MAC", "Ch", "RSSI"])
        self.table.setToolTip("Check the rows you want to target. The '#' column is the index "
                              "sent to the board (so selection stays index-accurate).")
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table)

        mrow = QHBoxLayout()
        mrow.addWidget(QLabel("or type:"))
        self.manual = QLineEdit(); self.manual.setPlaceholderText("indices/filter, e.g.  0,2,5   or   all")
        self.manual.setToolTip("Type indices/filter to select instead of checking rows "
                               "(e.g. 0,2,5 or 'all'). If filled, this overrides the checkboxes.")
        mrow.addWidget(self.manual)
        lay.addLayout(mrow)

        brow = QHBoxLayout()
        ok = QPushButton("Select"); ok.clicked.connect(self._ok); brow.addWidget(ok)
        ok.setToolTip(f"Apply the selection — sends '{base} <indices>' to the board.")
        cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject); brow.addWidget(cancel)
        cancel.setToolTip("Close without changing the selection.")
        lay.addLayout(brow)

        self._populate()
        if not self._source_rows():             # nothing pulled yet — grab it
            self._refresh()

    def _source_rows(self):
        return self.parser.indexed_stations() if self.kind == "sta" else self.parser.indexed_aps()

    def _populate(self):
        rows = self._source_rows()
        self.table.setRowCount(len(rows))
        self._checks = []
        for r, a in enumerate(rows):
            cb = QCheckBox()
            holder = QWidget(); h = QHBoxLayout(holder)
            h.addWidget(cb); h.setAlignment(Qt.AlignCenter); h.setContentsMargins(0, 0, 0, 0)
            self.table.setCellWidget(r, 0, holder)
            self._checks.append((a.index, cb))
            name = getattr(a, "ssid", "") or getattr(a, "mac", "")
            ch = getattr(a, "channel", "")
            for c, val in enumerate([a.index, name, ch, a.rssi], start=1):
                self.table.setItem(r, c, QTableWidgetItem(str(val)))

    def _refresh(self):
        if self.ctl.connected:
            self.ctl.send(self.list_cmd)
            QTimer.singleShot(900, self._populate)   # let the dump arrive, then repopulate

    def _toggle_all(self, state):
        for _, cb in self._checks:
            cb.setChecked(state == Qt.Checked)

    def _ok(self):
        manual = self.manual.text().strip()
        if manual:
            self.result_cmd = f"{self.base} {manual}"
        else:
            idxs = [str(i) for i, cb in self._checks if cb.isChecked()]
            if not idxs:
                QMessageBox.information(self, "Pick", "Check some targets, or type indices/filter below.")
                return
            self.result_cmd = f"{self.base} {','.join(idxs)}"
        self.accept()


# --------------------------------------------------------------------------- #
class FlasherDialog(QDialog):
    def __init__(self, parent, controller, default_port=""):
        super().__init__(parent)
        self.ctl = controller
        self.setWindowTitle("Universal Flasher")
        self.resize(780, 600)
        self.q = queue.Queue()
        self.chip = None
        self.assets = []
        self.by_name = {}
        self._busy = False
        self._need_refill = False   # set by worker threads; applied on the GUI thread in _drain
        # Selected firmware profile (default = marauder, so existing behaviour is unchanged).
        self.profile = flasher.get_profile("marauder")

        lay = QVBoxLayout(self)

        # --- firmware profile selector (additive; default = Marauder) --------- #
        frow = QHBoxLayout()
        frow.addWidget(QLabel("Firmware:"))
        self.fw_combo = QComboBox()
        self._profiles = flasher.list_profiles()      # [(id, label) ...] in registry order
        for _pid, _plabel in self._profiles:
            self.fw_combo.addItem(_plabel)
        # default to marauder so the existing flow is the default selection
        for _i, (_pid, _plabel) in enumerate(self._profiles):
            if _pid == "marauder":
                self.fw_combo.setCurrentIndex(_i)
                break
        self.fw_combo.setToolTip("Which firmware to flash. Defaults to ESP32 Marauder (the normal "
                                 "flow). Switching re-targets the release list / variant picker at the "
                                 "selected firmware; the suicide-build option is Marauder-only.")
        self.fw_combo.currentIndexChanged.connect(self._on_profile_changed)
        frow.addWidget(self.fw_combo); frow.addStretch()
        lay.addLayout(frow)

        prow = QHBoxLayout()
        prow.addWidget(QLabel("Port:"))
        self.port = QLineEdit(default_port); prow.addWidget(self.port)
        self.port.setToolTip("Serial port of the board to flash (e.g. COM5 or /dev/ttyUSB0). "
                             "Same port the app connects on.")
        b = QPushButton("Detect chip"); b.clicked.connect(self._detect); prow.addWidget(b)
        b.setToolTip("Talk to the board over USB and read which ESP32 chip it is "
                     "(esp32, esp32s3, ...). Run this once so the right firmware variant is picked.")
        self.chip_lbl = QLabel("chip: ?"); prow.addWidget(self.chip_lbl)
        self.chip_lbl.setToolTip("The detected chip family. Shows '?' until you press Detect chip.")
        lay.addLayout(prow)

        # --- normal-mode rows (hidden when 'Suicide build' is checked) -------- #
        self.mode_row_w = QWidget(); mrow = QHBoxLayout(self.mode_row_w); mrow.setContentsMargins(0, 0, 0, 0)
        mrow.addWidget(QLabel("Mode:"))
        self.mode_app = QRadioButton("Update app only"); self.mode_app.setChecked(True)
        self.mode_app.setToolTip(GLOSSARY.get("app-only flash", "Update only the application image."))
        self.mode_full = QRadioButton("Full flash (blank board)")
        self.mode_full.setToolTip(GLOSSARY.get("full flash", "Flash bootloader + partitions + app to a blank board."))
        g = QButtonGroup(self); g.addButton(self.mode_app); g.addButton(self.mode_full)
        mrow.addWidget(self.mode_app); mrow.addWidget(self.mode_full); mrow.addStretch()
        lay.addWidget(self.mode_row_w)

        self.src_row_w = QWidget(); srow = QHBoxLayout(self.src_row_w); srow.setContentsMargins(0, 0, 0, 0)
        srow.addWidget(QLabel("Firmware:"))
        self.src_dl = QRadioButton("Download latest"); self.src_dl.setChecked(True)
        self.src_dl.setToolTip("Fetch the official Marauder firmware for your chip from GitHub releases.")
        self.src_local = QRadioButton("Local .bin")
        self.src_local.setToolTip("Flash a firmware .bin file you already have on disk instead of downloading.")
        sg = QButtonGroup(self); sg.addButton(self.src_dl); sg.addButton(self.src_local)
        srow.addWidget(self.src_dl); srow.addWidget(self.src_local); srow.addStretch()
        lay.addWidget(self.src_row_w)

        self.dl_row_w = QWidget(); drow = QHBoxLayout(self.dl_row_w); drow.setContentsMargins(0, 0, 0, 0)
        lb = QPushButton("Load release list"); lb.clicked.connect(self._load); drow.addWidget(lb)
        lb.setToolTip("Download the list of available firmware variants from the latest GitHub release.")
        self.showall = QCheckBox("show all chips"); self.showall.stateChanged.connect(self._refill)
        self.showall.setToolTip("Show firmware variants for every chip, not just the detected one. "
                                "Leave off to avoid flashing the wrong board's build.")
        drow.addWidget(self.showall)
        self.variant = QComboBox(); self.variant.setMinimumWidth(380); drow.addWidget(self.variant)
        self.variant.setToolTip("Pick the firmware build that matches your exact board/display. "
                                "The best match for the detected chip is preselected.")
        lay.addWidget(self.dl_row_w)

        self.local_row_w = QWidget(); lrow = QHBoxLayout(self.local_row_w); lrow.setContentsMargins(0, 0, 0, 0)
        self.local = QLineEdit(); lrow.addWidget(self.local)
        self.local.setToolTip("Path to a local firmware .bin to flash (used when 'Local .bin' is selected).")
        bb = QPushButton("Browse"); bb.clicked.connect(self._browse); lrow.addWidget(bb)
        bb.setToolTip("Pick a firmware .bin file from disk.")
        lay.addWidget(self.local_row_w)

        # --- suicide-build path (opt-in, hidden until the checkbox is ticked) -- #
        self.suicide_cb = QCheckBox("Suicide build (provision + flash anti-forensic bundle)")
        self.suicide_cb.setToolTip("Owner-only hardened build that can self-wipe. "
                                   "Provisions a bundle with your password and flashes it.")
        self.suicide_cb.stateChanged.connect(self._toggle_suicide)
        lay.addWidget(self.suicide_cb)

        self.suicide_panel = QGroupBox("Suicide build config")
        spv = QVBoxLayout(self.suicide_panel)

        # Mode: provision new bundle vs flash existing
        self.suicide_mode_new = QRadioButton("Provision new bundle")
        self.suicide_mode_new.setToolTip("Enter a password and config — the app hashes it locally and builds "
                                         "a fresh bundle, then flashes it.")
        self.suicide_mode_new.setChecked(True)
        self.suicide_mode_existing = QRadioButton("Flash existing bundle")
        self.suicide_mode_existing.setToolTip("Point at a bundle directory (bundle.json + .bin images) "
                                              "already provisioned externally.")
        smrow = QHBoxLayout()
        smrow.addWidget(self.suicide_mode_new)
        smrow.addWidget(self.suicide_mode_existing)
        smrow.addStretch()
        spv.addLayout(smrow)
        self.suicide_mode_new.toggled.connect(self._toggle_suicide_mode)

        # --- provision sub-panel (new bundle) ---
        self.provision_panel = QWidget()
        ppv = QFormLayout(self.provision_panel)
        ppv.setContentsMargins(0, 4, 0, 0)

        self.s_pw = QLineEdit()
        self.s_pw.setEchoMode(QLineEdit.Password)
        self.s_pw.setPlaceholderText("boot password")
        self.s_pw.setToolTip("Boot password — hashed locally with PBKDF2-HMAC-SHA256. "
                             "Never stored, never logged, never sent anywhere.")
        ppv.addRow("Password:", self.s_pw)

        self.s_pw2 = QLineEdit()
        self.s_pw2.setEchoMode(QLineEdit.Password)
        self.s_pw2.setPlaceholderText("confirm password")
        self.s_pw2.setToolTip("Re-enter to confirm. Passwords must match.")
        ppv.addRow("Confirm:", self.s_pw2)

        self.s_variant = QComboBox()
        self.s_variant.addItems(["fork", "guardian"])
        self.s_variant.setToolTip("fork (default): boots into Marauder with password gate. "
                                  "guardian: boots into a factory gate that protects Marauder in OTA slot.")
        ppv.addRow("Variant:", self.s_variant)

        self.s_arm_pin = QSpinBox()
        self.s_arm_pin.setRange(0, 48)
        self.s_arm_pin.setValue(27)
        self.s_arm_pin.setToolTip("GPIO number for the dead-man arming switch (default 27).")
        ppv.addRow("Arm GPIO:", self.s_arm_pin)

        self.s_arm_level = QComboBox()
        self.s_arm_level.addItems(["HIGH (1)", "LOW (0)"])
        self.s_arm_level.setToolTip("Logic level that means ARMED. Default HIGH.")
        ppv.addRow("Arm level:", self.s_arm_level)

        self.s_deadman = QCheckBox("Dead-man: cut/missing switch wipes when armed")
        self.s_deadman.setChecked(True)
        self.s_deadman.setToolTip("When armed, a cut or disconnected arming wire triggers a wipe at boot.")
        ppv.addRow(self.s_deadman)

        self.s_max_att = QSpinBox()
        self.s_max_att.setRange(1, 10)
        self.s_max_att.setValue(2)
        self.s_max_att.setToolTip("Wrong password attempts before wipe (default 2). Survives power cycles.")
        ppv.addRow("Max attempts:", self.s_max_att)

        self.s_armed = QCheckBox("ARM now (default OFF / DISARMED)")
        self.s_armed.setToolTip("Master arm. Default OFF. A disarmed board can never wipe. "
                                "Only check this on a board you've tested in SAFE_MODE.")
        ppv.addRow(self.s_armed)

        bdrow2 = QHBoxLayout()
        self.s_build_dir = QLineEdit()
        self.s_build_dir.setPlaceholderText("(optional) folder with compiled firmware .bin files")
        self.s_build_dir.setToolTip("Path to compiled suicide firmware (bootloader.bin, partitions.bin, "
                                    "app.bin, boot_app0.bin). Leave blank if firmware is already in "
                                    "the output directory, or to provision config only.")
        bdrow2.addWidget(self.s_build_dir)
        bdb = QPushButton("Browse")
        bdb.setToolTip("Select the directory containing compiled firmware binaries.")
        bdb.clicked.connect(lambda: self._browse_dir(self.s_build_dir))
        bdrow2.addWidget(bdb)
        ppv.addRow("Build dir:", bdrow2)

        spv.addWidget(self.provision_panel)

        # --- existing bundle sub-panel ---
        self.existing_panel = QWidget()
        epv = QHBoxLayout(self.existing_panel)
        epv.setContentsMargins(0, 4, 0, 0)
        epv.addWidget(QLabel("Bundle dir:"))
        self.bundle_dir = QLineEdit()
        self.bundle_dir.setPlaceholderText("folder containing bundle.json + .bin images")
        self.bundle_dir.setToolTip("Folder with an already-provisioned bundle: bundle.json plus .bin images.")
        self.bundle_dir.textChanged.connect(self._bundle_changed)
        epv.addWidget(self.bundle_dir)
        self.bundle_browse = QPushButton("Browse")
        self.bundle_browse.setToolTip("Pick the provisioned bundle folder.")
        self.bundle_browse.clicked.connect(self._browse_bundle)
        epv.addWidget(self.bundle_browse)
        spv.addWidget(self.existing_panel)
        self.existing_panel.setVisible(False)

        self.bundle_summary = QLabel("")
        self.bundle_summary.setWordWrap(True)
        spv.addWidget(self.bundle_summary)

        self.suicide_note = QLabel(
            "⚠ SAFETY: this build can self-wipe. Test in SAFE_MODE first. "
            "Read suicide/docs/SAFETY.md before arming.")
        self.suicide_note.setWordWrap(True)
        self.suicide_note.setStyleSheet("color:#ff4d4d; font-weight:bold;")
        spv.addWidget(self.suicide_note)

        lay.addWidget(self.suicide_panel)
        self.suicide_panel.setVisible(False)

        self.arow_w = QWidget(); arow = QHBoxLayout(self.arow_w); arow.setContentsMargins(0, 0, 0, 0)
        arow.addWidget(QLabel("Baud:"))
        self.baud = QComboBox(); self.baud.addItems(["115200", "460800", "921600"]); self.baud.setCurrentText("921600")
        arow.addWidget(self.baud)
        self.baud.setToolTip(GLOSSARY.get("baud", "Serial transfer speed. Drop to 115200 if a flash stalls."))
        self.flash_btn = QPushButton("⚡ FLASH"); self.flash_btn.clicked.connect(self._flash); arow.addWidget(self.flash_btn)
        self.flash_btn.setToolTip("Write the selected firmware to the board over USB. Don't unplug while it runs.")
        eb = QPushButton("Erase flash"); eb.clicked.connect(self._erase); arow.addWidget(eb)
        eb.setToolTip("Wipe the board's entire flash. Use before a full flash, or to recover a bad install.")
        arow.addStretch()
        lay.addWidget(self.arow_w)

        self.console = QPlainTextEdit(); self.console.setReadOnly(True); self.console.setMaximumBlockCount(10000); lay.addWidget(self.console)
        self.console.setToolTip("Live esptool output for the current detect / flash / erase operation.")

        # Apply the initial profile-dependent visibility (default = marauder: all rows shown,
        # suicide checkbox visible). This is a no-op for the Marauder default beyond confirming
        # the as-designed layout.
        self._apply_profile_ui()

        self.timer = QTimer(self); self.timer.timeout.connect(self._drain); self.timer.start(40)
        if not flasher.esptool_available():
            self._log("[!] esptool not found — pip install esptool")

    def _log(self, s): self.q.put(s)

    def _drain(self):
        try:
            while True:
                self.console.appendPlainText(self.q.get_nowait())
        except queue.Empty:
            pass
        # all widget updates happen here on the GUI thread (workers only set state/flags)
        self.flash_btn.setEnabled(not self._busy)
        self.chip_lbl.setText(f"chip: {self.chip or '?'}")
        if self._need_refill:
            self._need_refill = False
            self._refill()

    def _free(self):
        if self.ctl and self.ctl.connected:
            self._log("[i] closing serial session for esptool")
            self.ctl.disconnect()

    def _work(self, fn):
        if self._busy:
            return
        self._busy = True       # _drain disables/enables the button on the GUI thread

        def run():
            try:
                fn()
            except Exception as e:
                self._log(f"[error] {e}")
            finally:
                self._busy = False
        threading.Thread(target=run, daemon=True).start()

    def _detect(self):
        port = self.port.text().strip()
        if not port:
            return
        self._free()

        def job():
            self.chip = flasher.detect_chip(port, self._log)
            self._need_refill = True
        self._work(job)

    def _load(self):
        profile = self.profile          # captured on the GUI thread
        def job():
            self._log(f"[*] fetching latest release for {profile.label}...")
            tag, self.assets = profile.latest_release()
            self._log(f"[i] {tag}: {len(self.assets)} variants")
            self._need_refill = True
        self._work(job)

    def _refill(self):
        if not self.assets:
            return
        items = self.assets if (self.showall.isChecked() or not self.chip) \
            else self.profile.variants_for_chip(self.assets, self.chip)
        self.by_name = {f"{a['label']}  [{a['name']}]": a for a in items}
        self.variant.clear(); self.variant.addItems(list(self.by_name))
        d = self.profile.default_variant(items, self.chip) if self.chip else None
        if d:
            for i, (lbl, a) in enumerate(self.by_name.items()):
                if a["name"] == d["name"]:
                    self.variant.setCurrentIndex(i); break

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select .bin", "", "Firmware (*.bin);;All (*)")
        if path:
            self.local.setText(path); self.src_local.setChecked(True)

    # --- firmware-profile selection (additive; marauder is the default) ----- #
    def _on_profile_changed(self, idx):
        """Re-target detect/release-list/variant logic at the selected firmware profile.

        Marauder (the default) keeps every existing row and the suicide option. Other
        profiles hide the suicide checkbox; the 'custom' local-only profile additionally
        hides the download/release rows and just uses the local .bin path."""
        if idx < 0 or idx >= len(self._profiles):
            return
        pid = self._profiles[idx][0]
        self.profile = flasher.get_profile(pid)
        # Switching firmware invalidates the previously loaded release list/variants.
        self.assets = []
        self.by_name = {}
        self.variant.clear()
        self._apply_profile_ui()

    def _apply_profile_ui(self):
        """Show/hide profile-dependent widgets. Called on profile change and after the
        suicide toggle so the two stay consistent. Never touches the Marauder defaults."""
        supports_suicide = self.profile.supports_suicide
        is_custom = (self.profile.id == "custom")
        # The suicide checkbox is only meaningful for Marauder; hide+disable it otherwise so
        # it can't be ticked for ESP32-DIV / Bruce / custom.
        if not supports_suicide and self.suicide_cb.isChecked():
            self.suicide_cb.setChecked(False)   # also fires _toggle_suicide -> hides the panel
        self.suicide_cb.setVisible(supports_suicide)
        self.suicide_cb.setEnabled(supports_suicide)
        in_suicide = supports_suicide and self.suicide_cb.isChecked()
        # When NOT in suicide mode, the normal rows are visible — except 'custom' hides the
        # remote download/release rows (it flashes a local .bin only).
        self.mode_row_w.setVisible(not in_suicide)
        self.src_row_w.setVisible(not in_suicide and not is_custom)
        self.dl_row_w.setVisible(not in_suicide and not is_custom)
        # custom is local-only: keep the local-path row visible and force the local source.
        self.local_row_w.setVisible(not in_suicide)
        if is_custom:
            self.src_local.setChecked(True)

    # --- suicide-build path (opt-in; default/core path is untouched) -------- #
    def _toggle_suicide(self):
        """Reveal the bundle sub-panel and hide the normal mode/source/variant rows
        when 'Suicide build' is checked. Unchecked == the dialog behaves exactly as today."""
        on = self.suicide_cb.isChecked()
        self.suicide_panel.setVisible(on)
        # Row visibility (mode/source/download/local) is owned by _apply_profile_ui so the
        # suicide toggle and the firmware-profile selection stay consistent.
        self._apply_profile_ui()

    def _toggle_suicide_mode(self):
        """Switch between provision-new and flash-existing sub-panels."""
        is_new = self.suicide_mode_new.isChecked()
        self.provision_panel.setVisible(is_new)
        self.existing_panel.setVisible(not is_new)
        self.bundle_summary.setText("")

    def _browse_dir(self, line_edit):
        d = QFileDialog.getExistingDirectory(self, "Select folder", line_edit.text().strip())
        if d:
            line_edit.setText(d)

    def _browse_bundle(self):
        d = QFileDialog.getExistingDirectory(self, "Select bundle folder", self.bundle_dir.text().strip())
        if d:
            self.bundle_dir.setText(d)

    def _bundle_changed(self):
        """Parse bundle.json (if present) and show a read-only manifest summary."""
        path = self.bundle_dir.text().strip()
        if not path:
            self.bundle_summary.setText("")
            return
        try:
            m = flasher.read_bundle_manifest(path)
        except Exception as e:
            self.bundle_summary.setText(f"⚠ {e}")
            return
        variant = _clean_manifest_field(m.get("variant") or m.get("name"))
        chip = _clean_manifest_field(m.get("chip"), max_len=24)
        count = len(m.get("files", []))
        self.bundle_summary.setText(
            f"variant: {variant}    chip: {chip}    files: {count}")

    def _resolve_chip(self, port):
        if self.chip:
            return self.chip
        self._log("[*] detecting chip...")
        self.chip = flasher.detect_chip(port, self._log)
        return self.chip

    def _flash(self):
        port = self.port.text().strip()
        if not port:
            return
        # opt-in suicide-bundle path: validate bundle + manifest, confirm, then flash_suicide().
        if self.suicide_cb.isChecked():
            self._flash_suicide(port)
            return
        mode = "app" if self.mode_app.isChecked() else "full"
        if self.src_dl.isChecked() and not self.by_name:
            QMessageBox.information(self, "Firmware", "Load release list + pick a variant."); return
        if self.src_local.isChecked() and not self.local.text().strip():
            QMessageBox.information(self, "Firmware", "Browse to a local .bin."); return
        if QMessageBox.question(self, "Confirm", f"Flash {mode} via {port}?\nDon't unplug.") != QMessageBox.Yes:
            return
        # capture all widget values on the GUI thread BEFORE starting the worker
        baud = int(self.baud.currentText())
        profile = self.profile
        is_marauder = (profile.id == "marauder")
        # 'custom' is local-only and the source row is hidden, so always use the local path.
        use_download = self.src_dl.isChecked() and profile.id != "custom"
        asset = self.by_name.get(self.variant.currentText()) if use_download else None
        local = self.local.text().strip()
        self._free()

        def job():
            chip = self._resolve_chip(port)
            if not chip:
                self._log("[error] chip unknown"); return
            cache = flasher.cache_dir()
            app_offset = None
            if use_download:
                if not asset:
                    self._log("[error] no variant selected"); return
                if asset["chip"] != chip:
                    self._log(f"[!] variant is {asset['chip']} but chip is {chip}")
                app = flasher.download_to(asset["url"], cache, asset["name"], self._log)
                # some profiles (ESP32-DIV/Bruce) pin an explicit per-asset offset
                app_offset = asset.get("offset")
            else:
                app = local
            if is_marauder:
                # Marauder default flow — unchanged, byte-for-byte (back-compat wrappers).
                support = flasher.support_files(chip, cache, self._log) if mode == "full" else None
                rc = flasher.flash(port, chip, app, self._log, mode=mode, baud=baud, support=support)
            else:
                support = profile.support_files(chip, cache, self._log) if mode == "full" else None
                rc = profile.flash_assets(port, chip, app, self._log, mode=mode, baud=baud,
                                          support=support, app_offset=app_offset)
            self._log("[done] power-cycle the board" if rc == 0 else f"[x] exit {rc}")
        self._work(job)

    def _flash_suicide(self, port):
        """Provision (if new) and flash a suicide bundle."""
        baud = int(self.baud.currentText())

        if self.suicide_mode_existing.isChecked():
            # --- existing bundle path (unchanged) ---
            bundle_path = self.bundle_dir.text().strip()
            if not bundle_path:
                QMessageBox.information(self, "Bundle", "Pick a bundle folder (the one with bundle.json).")
                return
            try:
                manifest = flasher.read_bundle_manifest(bundle_path)
            except Exception as e:
                QMessageBox.warning(self, "Bundle", f"Can't read bundle.json:\n{e}")
                return
            board = _clean_manifest_field(
                manifest.get("variant") or manifest.get("name") or manifest.get("board"))
            man_chip = _clean_manifest_field(manifest.get("chip"), max_len=24)
            if QMessageBox.question(
                    self, "Confirm suicide-build flash",
                    f"Flash anti-forensic bundle '{board}' ({man_chip}) via {port}?\n\n"
                    f"This build can self-wipe. Test in SAFE_MODE first.\n"
                    f"Don't unplug while flashing.") != QMessageBox.Yes:
                return
            self._free()

            def job():
                chip = self._resolve_chip(port)
                if not chip:
                    self._log("[error] chip unknown"); return
                rc = flasher.flash_suicide(port, chip, bundle_path, self._log, baud=baud)
                self._log("[done] power-cycle the board" if rc == 0 else f"[x] exit {rc}")
            self._work(job)
            return

        # --- provision new bundle path ---
        pw = self.s_pw.text()
        pw2 = self.s_pw2.text()
        if not pw:
            QMessageBox.warning(self, "Password", "Enter a boot password."); return
        if pw != pw2:
            QMessageBox.warning(self, "Password", "Passwords don't match."); return
        variant = self.s_variant.currentText()
        armed = int(self.s_armed.isChecked())
        arm_level = 1 if self.s_arm_level.currentIndex() == 0 else 0
        build_dir = self.s_build_dir.text().strip() or None

        confirm_msg = (
            f"Provision + flash a suicide build via {port}?\n\n"
            f"variant={variant}  armed={armed}  max_att={self.s_max_att.value()}\n"
            f"The password is hashed locally and never stored.\n"
        )
        if armed:
            confirm_msg += "\n⚠ ARMED=1 — the board WILL self-destruct on trigger conditions!"
        confirm_msg += "\nDon't unplug while flashing."
        if QMessageBox.question(self, "Confirm suicide-build", confirm_msg) != QMessageBox.Yes:
            return

        # Capture all config on GUI thread
        config = dict(
            password=pw,
            variant=variant,
            arm_pin=self.s_arm_pin.value(),
            arm_level=arm_level,
            arm_pull=2 if arm_level == 1 else 1,
            deadman=int(self.s_deadman.isChecked()),
            armed=armed,
            max_att=self.s_max_att.value(),
            build_dir=build_dir,
        )
        # Clear password fields immediately
        self.s_pw.clear()
        self.s_pw2.clear()
        self._free()

        def job():
            chip = self._resolve_chip(port)
            if not chip:
                self._log("[error] chip unknown"); return
            try:
                import suicide
                bundle_path = suicide.build_bundle(
                    chip=chip, on_line=self._log, **config)
            except Exception as e:
                self._log(f"[error] provisioning failed: {e}"); return
            rc = flasher.flash_suicide(port, chip, bundle_path, self._log, baud=baud)
            self._log("[done] power-cycle the board" if rc == 0 else f"[x] exit {rc}")
        self._work(job)

    def _erase(self):
        port = self.port.text().strip()
        if not port:
            return
        if QMessageBox.question(self, "Erase", "Erase entire flash?") != QMessageBox.Yes:
            return
        self._free()
        self._work(lambda: flasher.erase(port, self._resolve_chip(port) or "esp32", self._log))

    def closeEvent(self, ev):
        if self._busy:
            QMessageBox.warning(self, "Flashing",
                                "A flash/erase is in progress — let it finish before closing.")
            ev.ignore(); return
        try:
            self.timer.stop()
        except Exception:
            pass
        ev.accept()


# --------------------------------------------------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self, controller, log_dir=None):
        super().__init__()
        self.ctl = controller
        self.parser = MarauderParser()
        self.logger = CaptureLogger(log_dir)
        self.q = queue.Queue()
        self.ctl.subscribe(self.q.put)
        self._updating = False
        self._autolist_cmd = None
        self._snap_skip = 0

        self.setWindowTitle("Universal Flasher")
        self.resize(1200, 780)
        self.setStyleSheet(DARK_QSS)
        self._build()
        self._build_menu()
        self._build_shortcuts()

        self.t_autolist = QTimer(self); self.t_autolist.timeout.connect(self._do_autolist)
        self.t_drain = QTimer(self); self.t_drain.timeout.connect(self._drain); self.t_drain.start(40)
        self.t_tables = QTimer(self); self.t_tables.timeout.connect(self._refresh_tables); self.t_tables.start(700)
        self._update_statusbar()

    # --- ui --------------------------------------------------------------- #
    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # top bar
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Port:"))
        self.port = QComboBox(); self.port.setEditable(True); self.port.setMinimumWidth(220)
        self.port.setToolTip("Serial port the Marauder is on (e.g. COM5 or /dev/ttyUSB0). "
                             "Pick from the list or type it; press ↻ to rescan.")
        self._refresh_ports(); bar.addWidget(self.port)
        rb = QPushButton("↻"); rb.setFixedWidth(32); rb.clicked.connect(self._refresh_ports); bar.addWidget(rb)
        rb.setToolTip("Rescan for serial ports (F5).")
        self.connect_btn = QPushButton("Connect"); self.connect_btn.clicked.connect(self._toggle); bar.addWidget(self.connect_btn)
        self.connect_btn.setToolTip("Open (or close) the serial session to the selected port.")
        self.status = QLabel("disconnected"); self.status.setObjectName("status_bad"); bar.addWidget(self.status)
        self.status.setToolTip("Connection state: shows the connected port, or 'disconnected'.")
        self.autolist_cb = QCheckBox("Auto-list"); self.autolist_cb.setChecked(True)
        self.autolist_cb.setToolTip("While scanning, auto-pull 'list -a' so the tables fill themselves")
        bar.addWidget(self.autolist_cb)
        self.log_btn = QPushButton("● Log: off"); self.log_btn.setCheckable(True)
        self.log_btn.clicked.connect(self._toggle_log); bar.addWidget(self.log_btn)
        self.log_btn.setToolTip("Toggle capture logging: write the serial stream and periodic "
                                "AP/Station snapshots to the log folder.")
        bar.addStretch()
        fb = QPushButton("⚡ Flash Firmware"); fb.clicked.connect(self._flasher); bar.addWidget(fb)
        fb.setToolTip("Open the firmware flasher: download or pick a build and write it to the board.")
        sb = QPushButton("STOP"); sb.setObjectName("stop"); sb.clicked.connect(self._stop); bar.addWidget(sb)
        sb.setToolTip("Send 'stopscan' and halt auto-listing (Ctrl+.). Stops the current attack/scan.")
        root.addLayout(bar)
        self.setStatusBar(QStatusBar())

        # body splitter
        split = QSplitter(Qt.Horizontal); root.addWidget(split, 1)
        split.addWidget(self._command_panel())

        right = QWidget(); rl = QVBoxLayout(right)
        self.tabs = QTabWidget()
        self.console = QPlainTextEdit(); self.console.setReadOnly(True)
        self.console.setFont(QFont("monospace", 10))
        self.console.setToolTip("Live serial output from the board.")
        ci = self.tabs.addTab(self.console, "Console")
        self.tabs.setTabToolTip(ci, "Live serial output from the board.")
        self.ap_table = self._make_table(["#", "SSID", "Ch", "RSSI", "BSSID"])
        self.ap_table.setToolTip("Access points parsed from the live scan. # is the index used by 'select -a'.")
        for col, tip in enumerate(["Index used by 'select -a'", "Network name (SSID)",
                                   "Wi-Fi channel", "Signal strength (RSSI, dBm)",
                                   GLOSSARY.get("bssid", "Access-point MAC address")]):
            it = self.ap_table.horizontalHeaderItem(col)
            if it is not None:
                it.setToolTip(tip)
        ai = self.tabs.addTab(self.ap_table, "Access Points")
        self.tabs.setTabToolTip(ai, "Access points seen by the last scan (fills while scanning).")
        self.sta_table = self._make_table(["#", "Station MAC", "AP", "RSSI"])
        self.sta_table.setToolTip("Client devices (stations) parsed from the scan. "
                                  "# is the index used by 'select -c'.")
        for col, tip in enumerate(["Index used by 'select -c'",
                                   GLOSSARY.get("station", "Client device MAC address"),
                                   "BSSID of the AP it is associated with", "Signal strength (RSSI, dBm)"]):
            it = self.sta_table.horizontalHeaderItem(col)
            if it is not None:
                it.setToolTip(tip)
        si = self.tabs.addTab(self.sta_table, "Stations")
        self.tabs.setTabToolTip(si, "Client devices seen by the last station scan.")
        self.guide = QTextBrowser(); self.guide.setOpenExternalLinks(True)
        self.guide.setToolTip("The bundled GUIDE.md, rendered. Press F1 to jump here.")
        self._load_guide()
        gi = self.tabs.addTab(self.guide, "Guide")
        self.tabs.setTabToolTip(gi, "Usage guide (GUIDE.md).")
        try:
            from gui_qt.software_tab import SoftwareOSTab
            self.software_os = SoftwareOSTab()
            oi = self.tabs.addTab(self.software_os, "Software OS")
            self.tabs.setTabToolTip(oi, "Flash a bootable OS (Kali / Tails / Arch) to a USB stick.")
        except Exception as exc:  # noqa: BLE001 — never block the main UI on the optional OS tab
            self.console.appendPlainText(f"[software-os] tab unavailable: {exc}")
        rl.addWidget(self.tabs, 1)

        raw = QHBoxLayout()
        self.raw = QLineEdit(); self.raw.setPlaceholderText("raw command (e.g. scanap) — Enter to send")
        self.raw.setToolTip("Type any Marauder command and press Enter to send it (Ctrl+K to focus here).")
        self.raw.returnPressed.connect(self._send_raw); raw.addWidget(self.raw)
        snd = QPushButton("Send"); snd.clicked.connect(self._send_raw); raw.addWidget(snd)
        snd.setToolTip("Send the typed command to the board.")
        clr = QPushButton("Clear"); clr.clicked.connect(lambda: (self.console.clear(), self.parser.clear())); raw.addWidget(clr)
        clr.setToolTip("Clear the console and the parsed AP/Station tables (Ctrl+L).")
        rl.addLayout(raw)
        split.addWidget(right)
        split.setSizes([430, 750])

    def _command_panel(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setMinimumWidth(420)
        inner = QWidget(); v = QVBoxLayout(inner)
        for cat in commands.categories():
            box = QGroupBox(cat); grid = QGridLayout(box)
            cmds = [c for c in commands.COMMANDS if c.category == cat]
            for i, c in enumerate(cmds):
                btn = QPushButton(c.label)
                if c.danger:
                    btn.setObjectName("danger")
                btn.setToolTip(_cmd_tooltip(c))      # hover description
                btn.clicked.connect(lambda _, cmd=c: self._run(cmd))
                grid.addWidget(btn, i // 2, i % 2)
            v.addWidget(box)
        v.addStretch()
        scroll.setWidget(inner)
        return scroll

    def _load_guide(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "GUIDE.md")
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except Exception:
            text = ("# Guide\n\nGUIDE.md not found next to the app.\n\n"
                    "Online: https://github.com/LxveAce/headless-marauder-gui/blob/main/GUIDE.md")
        try:
            self.guide.setMarkdown(text)         # Qt 5.14+
        except Exception:
            self.guide.setPlainText(text)

    def _show_guide(self):
        self.tabs.setCurrentWidget(self.guide)

    def _make_table(self, headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.verticalHeader().setVisible(False)
        t.verticalHeader().setDefaultSectionSize(28)   # touch-friendly rows
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        return t

    # --- actions ---------------------------------------------------------- #
    def _run(self, cmd):
        # Selecting APs/Stations: open the picker fed by the parsed indexed list.
        if cmd.id in ("select_ap", "select_sta"):
            kind = "sta" if cmd.id == "select_sta" else "ap"
            list_cmd = "list -c" if kind == "sta" else "list -a"
            dlg = TargetPicker(self, self.ctl, self.parser, cmd.base, list_cmd, kind=kind)
            if dlg.exec_() == QDialog.Accepted and dlg.result_cmd:
                self._guarded_send(dlg.result_cmd)
            return
        if cmd.danger and QMessageBox.question(
                self, "Confirm", f"Run attack/spam?\n\n{cmd.base}\n\nAuthorized targets only.") != QMessageBox.Yes:
            return
        if cmd.params:
            dlg = ParamDialog(self, cmd)
            if dlg.exec_() != QDialog.Accepted or dlg.values is None:
                return
            line = commands.build(cmd, dlg.values)
        else:
            line = cmd.base
        self._guarded_send(line)

    def _send_raw(self):
        line = self.raw.text().strip()
        if line:
            self._guarded_send(line); self.raw.clear()

    def _guarded_send(self, line):
        if not self.ctl.connected:
            self._append("[error] not connected — click Connect first"); return
        try:
            self.ctl.send(line)
        except Exception as e:
            self._append(f"[error] {e}"); return
        self._react_to_command(line)

    def _react_to_command(self, line):
        first = line.strip().split()[0] if line.strip() else ""
        if first == "stopscan":
            self._stop_autolist()
        elif first in _AP_SCANS and self.autolist_cb.isChecked():
            self._start_autolist("list -a")
        elif first in _STA_SCANS and self.autolist_cb.isChecked():
            self._start_autolist("list -c")

    def _stop(self):
        if self.ctl.connected:
            self.ctl.stop()
        self._stop_autolist()

    def _flasher(self):
        self._stop_autolist()
        self._flash_dlg = FlasherDialog(self, self.ctl, default_port=self.port.currentText().strip())
        self._flash_dlg.exec_()

    # --- auto-list: fills the AP/Station tabs while a scan runs ------------ #
    def _start_autolist(self, cmd):
        self._autolist_cmd = cmd
        QTimer.singleShot(1200, self._do_autolist)   # one quick fill, then poll
        self.t_autolist.start(3000)

    def _stop_autolist(self):
        self.t_autolist.stop()
        self._autolist_cmd = None

    def _do_autolist(self):
        if self._autolist_cmd and self.ctl.connected:
            try:
                self.ctl.send(self._autolist_cmd)
            except Exception:
                pass
        else:
            self.t_autolist.stop()

    # --- logging ---------------------------------------------------------- #
    def _toggle_log(self):
        if self.logger.enabled:
            self.logger.stop()
        else:
            try:
                path = self.logger.start()
                self._append(f"[log] writing to {path}")
            except Exception as e:
                self._append(f"[log] failed: {e}")
        self._update_log_btn()
        self._update_statusbar()

    def _update_log_btn(self):
        on = self.logger.enabled
        self.log_btn.setChecked(on)
        self.log_btn.setText("● Log: ON" if on else "● Log: off")

    def _set_log_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Choose log folder", self.logger.dir)
        if d:
            self.logger.set_dir(d)
            self._append(f"[log] folder: {d}")
            self._update_statusbar()

    def _open_log_folder(self):
        import subprocess
        try:
            os.makedirs(self.logger.dir, exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(self.logger.dir)            # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.logger.dir])
            else:
                subprocess.Popen(["xdg-open", self.logger.dir])
        except Exception as e:
            self._append(f"[log] can't open folder: {e}")

    # --- menus / shortcuts / status / updates ----------------------------- #
    def _build_menu(self):
        m = self.menuBar()
        filem = m.addMenu("&File")
        act = QAction("Set Log Folder…", self); act.triggered.connect(self._set_log_folder)
        act.setToolTip("Choose where capture logs and snapshots are written.")
        act.setStatusTip("Choose where capture logs and snapshots are written.")
        filem.addAction(act)
        act = QAction("Open Log Folder", self); act.triggered.connect(self._open_log_folder)
        act.setToolTip("Open the current log folder in your file manager.")
        act.setStatusTip("Open the current log folder in your file manager.")
        filem.addAction(act)
        filem.addSeparator()
        act = QAction("Quit", self); act.setShortcut(QKeySequence("Ctrl+Q")); act.triggered.connect(self.close)
        act.setToolTip("Close the app (Ctrl+Q). Disconnects the serial session first.")
        act.setStatusTip("Close the app (Ctrl+Q).")
        filem.addAction(act)
        toolsm = m.addMenu("&Tools")
        act = QAction("Flash Firmware…", self); act.triggered.connect(self._flasher)
        act.setToolTip("Open the firmware flasher (download/local/suicide-bundle).")
        act.setStatusTip("Open the firmware flasher.")
        toolsm.addAction(act)
        act = QAction("Refresh Ports", self); act.setShortcut(QKeySequence("F5")); act.triggered.connect(self._refresh_ports)
        act.setToolTip("Rescan for connected serial ports (F5).")
        act.setStatusTip("Rescan for connected serial ports (F5).")
        toolsm.addAction(act)
        helpm = m.addMenu("&Help")
        act = QAction("Guide", self); act.setShortcut(QKeySequence("F1")); act.triggered.connect(self._show_guide)
        act.setToolTip("Open the Guide tab (F1).")
        act.setStatusTip("Open the Guide tab (F1).")
        helpm.addAction(act)
        act = QAction("Check for Updates…", self); act.triggered.connect(self._check_updates)
        act.setToolTip("Pull the latest app version from git (Ctrl+U).")
        act.setStatusTip("Pull the latest app version from git (Ctrl+U).")
        helpm.addAction(act)
        act = QAction("About", self); act.triggered.connect(self._about)
        act.setToolTip("Version, revision and project link.")
        act.setStatusTip("Version, revision and project link.")
        helpm.addAction(act)

    def _build_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self._clear)
        QShortcut(QKeySequence("F5"), self, activated=self._refresh_ports)
        QShortcut(QKeySequence("Ctrl+K"), self, activated=lambda: self.raw.setFocus())
        QShortcut(QKeySequence("Ctrl+."), self, activated=self._stop)
        QShortcut(QKeySequence("Ctrl+U"), self, activated=self._check_updates)

    def _clear(self):
        self.console.clear(); self.parser.clear()

    def _update_statusbar(self):
        rev = updater.current_revision()
        log = self.logger.serial_path if self.logger.enabled else "off"
        self.statusBar().showMessage(f"v{__version__} ({rev})   ·   log: {log}")

    def _check_updates(self):
        if self._updating:
            return
        self._updating = True
        self._append("[update] checking…")

        def job():
            updater.update(self.q.put)
            self._updating = False
        threading.Thread(target=job, daemon=True).start()

    def _about(self):
        QMessageBox.about(
            self, "About Universal Flasher",
            f"<b>Universal Flasher</b> v{__version__} ({updater.current_revision()})<br><br>"
            "Multi-firmware flasher and device manager for ESP32, Raspberry Pi,<br>"
            "Flipper Zero, and ADB-based security hardware.<br><br>"
            "Supports 14+ firmware profiles: Marauder, GhostESP, Bruce, HaleHound,<br>"
            "Meshtastic, Flock-You, OUI-Spy, Sky-Spy, AirTag Scanner, CYT-NG,<br>"
            "ESP32-DIV, Momentum, Unleashed, and custom/community profiles.<br><br>"
            "<a href='https://github.com/LxveAce/universal-flasher'>"
            "github.com/LxveAce/universal-flasher</a><br><br>"
            "Built on the Headless Marauder scaffold. For authorized security testing only.")

    # --- connection ------------------------------------------------------- #
    def _refresh_ports(self):
        cur = self.port.currentText() if hasattr(self, "port") else ""
        self.port.clear()
        self.port.addItems([d for d, _ in MarauderController.list_ports()])
        if cur:
            self.port.setCurrentText(cur)

    def _toggle(self):
        if self.ctl.connected:
            self.ctl.disconnect()
            self.status.setText("disconnected"); self.status.setObjectName("status_bad")
            self.status.setStyleSheet("color:#ff4d4d;")
            self.connect_btn.setText("Connect"); return
        self.ctl.port = self.port.currentText().strip() or None
        try:
            port = self.ctl.connect()
            self.status.setText(f"connected: {port}"); self.status.setStyleSheet("color:#39ff14;")
            self.connect_btn.setText("Disconnect")
            self._append(f"[connected to {port} @ {self.ctl.baud} baud]")
        except Exception as e:
            QMessageBox.critical(self, "Connection failed", str(e))
            self._append(f"[error] {e}")

    # --- streaming -------------------------------------------------------- #
    def _drain(self):
        try:
            while True:
                line = self.q.get_nowait()
                self._append(line)
                self.parser.feed(line)
                self.logger.write_serial(line)
        except queue.Empty:
            pass

    def _append(self, line):
        self.console.appendPlainText(line)

    def _refresh_tables(self):
        if not self.parser.dirty:
            return
        self.parser.dirty = False
        aps = self.parser.ap_rows()
        self.ap_table.setRowCount(len(aps))
        for r, a in enumerate(aps):
            idx = a.index if a.index >= 0 else ""
            for c, val in enumerate([idx, a.ssid, a.channel, a.rssi, a.bssid]):
                self.ap_table.setItem(r, c, QTableWidgetItem(str(val)))
        self.tabs.setTabText(1, f"Access Points ({len(aps)})")
        stas = self.parser.station_rows()
        self.sta_table.setRowCount(len(stas))
        for r, s in enumerate(stas):
            idx = s.index if s.index >= 0 else ""
            for c, val in enumerate([idx, s.mac, s.ap_bssid, s.rssi]):
                self.sta_table.setItem(r, c, QTableWidgetItem(str(val)))
        self.tabs.setTabText(2, f"Stations ({len(stas)})")
        if self.logger.enabled:
            self._snap_skip = (self._snap_skip + 1) % 5
            if self._snap_skip == 0:        # snapshot ~every 3.5s, not on every 700ms refresh
                self.logger.write_snapshot(aps, stas, {"port": self.ctl.port})

    def closeEvent(self, ev):
        try:
            self.t_autolist.stop()
            self.logger.stop()
            self.ctl.disconnect()
        except Exception:
            pass
        ev.accept()


def main():
    ap = argparse.ArgumentParser(description="Universal Flasher Qt GUI")
    ap.add_argument("--port"); ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--no-autoconnect", action="store_true")
    ap.add_argument("--log", nargs="?", const=True, default=None,
                    help="Start logging immediately (optionally to a given dir; default ~/marauder-logs)")
    args = ap.parse_args()

    ctl = MarauderController(port=args.port, baud=args.baud, mock=args.mock)
    app = QApplication(sys.argv)
    log_dir = args.log if isinstance(args.log, str) else None
    win = MainWindow(ctl, log_dir=log_dir)
    if args.log:
        win.logger.start(); win._update_log_btn(); win._update_statusbar()
    win.show()
    if not args.no_autoconnect:
        try:
            port = ctl.connect()
            win.status.setText(f"connected: {port}"); win.status.setStyleSheet("color:#39ff14;")
            win.connect_btn.setText("Disconnect")
            win.port.setCurrentText(port)
            win._append(f"[connected to {port} @ {ctl.baud} baud]")
        except Exception as e:
            win._append(f"[not connected] {e}")
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
