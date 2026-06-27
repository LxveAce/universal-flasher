"""Software-OS tab — flash bootable PC/USB operating systems (Kali / Tails / Arch / ...).

Universal Flasher's "Software" side, separate from firmware: writes whole-disk OS images to a
removable USB. Drives the verified, auto-resolving catalog in :mod:`uf_core.os_catalog` (latest version
online, bundled pinned version offline) and reuses the hardened removable-only writer. The destructive
write happens off the UI thread; every step is logged. Tooltips on every control.
"""

from __future__ import annotations

import logging
import os
import tempfile

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from uf_core import os_catalog as oc
from uf_core import sd_backend as sd

log = logging.getLogger(__name__)


def _make_card(title: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setFrameShape(QFrame.StyledPanel)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(6)
    if title:
        lbl = QLabel(f"<b>{title}</b>")
        layout.addWidget(lbl)
    return card, layout


class _ResolveWorker(QThread):
    done = pyqtSignal(object, str)

    def __init__(self, entry: oc.OSImage, offline: bool) -> None:
        super().__init__()
        self._entry = entry
        self._offline = offline

    def run(self) -> None:
        lines: list[str] = []
        try:
            r = oc.resolve(self._entry, lines.append, online=not self._offline)
        except Exception as exc:  # noqa: BLE001
            r = None
            lines.append(f"resolve failed: {exc}")
        self.done.emit(r, "\n".join(lines))


class _OSFlashWorker(QThread):
    progress = pyqtSignal(int, str)  # pct (-1 = log only), message
    finished = pyqtSignal(bool)

    def __init__(self, entry: oc.OSImage, resolved: oc.Resolved, device: str,
                 local_image: str | None = None) -> None:
        super().__init__()
        self._entry = entry
        self._resolved = resolved
        self._device = device
        self._local_image = local_image

    def run(self) -> None:
        def on(s: str) -> None:
            self.progress.emit(-1, s)

        def prog(f: float) -> None:
            self.progress.emit(int(f * 100), "")

        entry, r = self._entry, self._resolved
        img, sig = self._local_image, None
        sums = sums_sig = None
        cache = os.path.join(tempfile.gettempdir(), f"uf_os_{entry.id}")
        try:
            if not img:
                img = oc.download(r.image_url, cache, on, prog)
                if r.verify_model == "image_sig" and r.sig_url:
                    try:
                        sig = oc.download(r.sig_url, cache, on)
                    except Exception as exc:  # noqa: BLE001
                        on(f"[os] signature fetch failed ({exc}); will fall back to SHA-256.")
                if r.verify_model == "checksums_sig":
                    if r.checksums_url:
                        sums = oc.download(r.checksums_url, cache, on)
                    if r.checksums_sig_url:
                        try:
                            sums_sig = oc.download(r.checksums_sig_url, cache, on)
                        except Exception as exc:  # noqa: BLE001
                            on(f"[os] SHA256SUMS signature fetch failed ({exc}).")
            rc = oc.flash_os_image(entry, r, img, self._device, on, prog, sig_path=sig,
                                   checksums_path=sums, checksums_sig_path=sums_sig, confirmed=True)
            self.finished.emit(rc == 0)
        except Exception as exc:  # noqa: BLE001
            on(f"[os] ERROR: {exc}")
            self.finished.emit(False)


class SoftwareOSTab(QWidget):
    """Flash a bootable OS (Kali / Tails / Arch / ...) to a removable USB stick."""

    def __init__(self) -> None:
        super().__init__()
        self._entries: list[oc.OSImage] = []
        self._resolved: oc.Resolved | None = None
        self._local_image: str | None = None
        self._resolver: _ResolveWorker | None = None
        self._worker: _OSFlashWorker | None = None
        self._build_ui()
        self._load_catalog()
        self._refresh_drives()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        container = QWidget()
        root = QVBoxLayout(container)

        intro = QLabel("Write a verified bootable operating system to a USB stick. Board firmware lives "
                       "on the firmware flasher — this tab is for PC/USB operating systems.")
        intro.setWordWrap(True)
        root.addWidget(intro)

        os_card, os_layout = _make_card("Operating System")
        self._os_combo = QComboBox()
        self._os_combo.setToolTip("Pick the OS to write. Each is downloaded from its official source and "
                                  "integrity-verified (SHA-256 + OpenPGP signature) before writing.")
        self._os_combo.currentIndexChanged.connect(self._on_os_changed)
        os_layout.addWidget(self._os_combo)
        self._os_desc = QLabel("")
        self._os_desc.setWordWrap(True)
        os_layout.addWidget(self._os_desc)
        self._offline_cb = QCheckBox("Use bundled version (offline)")
        self._offline_cb.setToolTip("Unchecked: resolve the latest version live from the OS project. "
                                    "Checked: flash the version bundled with the app (no internet).")
        os_layout.addWidget(self._offline_cb)
        self._btn_check = QPushButton("Check latest")
        self._btn_check.setToolTip("Resolve the current version + download/verification URLs.")
        self._btn_check.clicked.connect(self._on_check)
        os_layout.addWidget(self._btn_check)
        self._os_status = QLabel("No version resolved yet.")
        self._os_status.setWordWrap(True)
        os_layout.addWidget(self._os_status)
        root.addWidget(os_card)

        drive_card, drive_layout = _make_card("Target USB (removable — ERASED)")
        self._drive_combo = QComboBox()
        self._drive_combo.setToolTip("Only removable drives are listed. THE ENTIRE DRIVE IS ERASED.")
        drive_layout.addWidget(self._drive_combo)
        row = QHBoxLayout()
        btn_refresh = QPushButton("Refresh drives")
        btn_refresh.clicked.connect(self._refresh_drives)
        row.addWidget(btn_refresh)
        btn_local = QPushButton("Use local image…")
        btn_local.setToolTip("Flash an OS image (.iso/.img) you already downloaded instead of fetching it.")
        btn_local.clicked.connect(self._browse_local)
        row.addWidget(btn_local)
        drive_layout.addLayout(row)
        self._local_lbl = QLabel("")
        self._local_lbl.setWordWrap(True)
        drive_layout.addWidget(self._local_lbl)
        root.addWidget(drive_card)

        self._btn_flash = QPushButton("Flash OS to USB")
        self._btn_flash.setMinimumHeight(38)
        self._btn_flash.setToolTip("Download (if needed), verify, then write the OS to the selected USB. "
                                   "Destructive — the whole drive is erased.")
        self._btn_flash.clicked.connect(self._on_flash)
        root.addWidget(self._btn_flash)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        root.addWidget(self._progress)

        log_card, log_layout = _make_card("Log")
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(120)
        log_layout.addWidget(self._log)
        root.addWidget(log_card, 1)

        scroll.setWidget(container)
        outer.addWidget(scroll)

    def _load_catalog(self) -> None:
        try:
            self._entries = oc.load_catalog()
        except Exception as exc:  # noqa: BLE001
            self._logmsg(f"Could not load OS catalog: {exc}")
            self._entries = []
        self._os_combo.clear()
        for e in self._entries:
            self._os_combo.addItem(f"{e.name}  [{e.category}]", e.id)
        self._on_os_changed()

    def _current_entry(self) -> oc.OSImage | None:
        oid = self._os_combo.currentData()
        return next((e for e in self._entries if e.id == oid), None)

    def _on_os_changed(self) -> None:
        self._resolved = None
        e = self._current_entry()
        if e:
            self._os_desc.setText(f"{e.description}  ({e.image_type.upper()}, verify: {e.verify_model})")
            self._os_status.setText(f"Bundled version: {e.pinned.get('version', '?')}. "
                                    "Click 'Check latest' to resolve the current release.")

    def _refresh_drives(self) -> None:
        self._drive_combo.clear()
        try:
            for c in sd.detect_sd_cards(lambda *_: None):
                gb = (c.get("size") or 0) / (1 << 30)
                self._drive_combo.addItem(f"{c['device']}  {c.get('name', '')}  {gb:.1f} GB", c["device"])
        except Exception as exc:  # noqa: BLE001
            self._logmsg(f"Drive scan failed: {exc}")
        if self._drive_combo.count() == 0:
            self._drive_combo.addItem("No removable drives found", None)

    def _browse_local(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select an OS image", "",
                                              "Disk images (*.iso *.img);;All files (*)")
        if path:
            self._local_image = path
            self._local_lbl.setText(f"Local image: {os.path.basename(path)}")
        else:
            self._local_image = None
            self._local_lbl.setText("")

    def _on_check(self) -> None:
        e = self._current_entry()
        if not e:
            return
        self._btn_check.setEnabled(False)
        self._os_status.setText("Resolving…")
        self._resolver = _ResolveWorker(e, self._offline_cb.isChecked())
        self._resolver.done.connect(self._on_resolved)
        self._resolver.start()

    def _on_resolved(self, resolved, log_text: str) -> None:
        self._btn_check.setEnabled(True)
        if log_text:
            self._logmsg(log_text)
        self._resolved = resolved
        if resolved is None:
            self._os_status.setText("Could not resolve a version.")
            return
        self._os_status.setText(f"{resolved.version}  (source: {resolved.source}, "
                                f"verify: {resolved.verify_model})")

    def _on_flash(self) -> None:
        e = self._current_entry()
        if not e:
            return
        device = self._drive_combo.currentData()
        if not device:
            self._logmsg("No removable drive selected.")
            return
        if self._resolved is None:
            self._logmsg("Resolving version before flashing… click Flash again once resolved.")
            self._on_check()
            return
        name = self._drive_combo.currentText()
        if QMessageBox.warning(
            self, "Erase and flash?",
            f"This will ERASE EVERYTHING on:\n\n    {name}\n\nand write {e.name} {self._resolved.version}.\n\n"
            "Continue?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            self._logmsg("Flash cancelled.")
            return
        self._btn_flash.setEnabled(False)
        self._progress.setValue(0)
        self._logmsg(f"Flashing {e.name} {self._resolved.version} -> {device} …")
        self._worker = _OSFlashWorker(e, self._resolved, device, local_image=self._local_image)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_done)
        self._worker.start()

    def _on_progress(self, pct: int, msg: str) -> None:
        if pct >= 0:
            self._progress.setValue(pct)
        if msg:
            self._logmsg(msg)

    def _on_done(self, ok: bool) -> None:
        self._btn_flash.setEnabled(True)
        if ok:
            self._progress.setValue(100)
            self._logmsg("OS flash completed — boot the target machine from this USB.")
        else:
            self._logmsg("OS flash failed — see log above.")

    def _logmsg(self, msg: str) -> None:
        self._log.appendPlainText(msg)
        log.info("SoftwareOSTab: %s", msg)
