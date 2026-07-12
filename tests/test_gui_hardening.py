"""Batch UF-3 GUI-hardening regressions (from an adversarial audit; Qt constructed offscreen):

 * the Qt main console was unbounded (the FlasherDialog console + both Tk consoles cap at 10000);
 * the main window kept showing 'connected'/'Disconnect' after the flasher dropped the shared serial
   session for esptool — now it re-derives the button/status from ctl.connected each poll tick;
 * the Software-OS tab's destructive USB-flash QThread was never guarded on app close — now the main
   window refuses to close while it is writing (is_flashing()).

The Tk parity fixes (main-window resync, flasher mid-flash close-guard) mirror these and are verified
by inspection since the repo doesn't spin a Tk root in CI.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PyQt5.QtWidgets")


@pytest.fixture(scope="module")
def qapp():
    from PyQt5.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _mock_controller():
    from uf_core.controller import MarauderController
    return MarauderController(mock=True)


def test_qt_console_is_bounded(qapp):
    from gui_qt.app import MainWindow
    w = MainWindow(_mock_controller())
    assert w.console.maximumBlockCount() == 10000   # was 0 (QPlainTextEdit default = unlimited)


def test_qt_main_window_resyncs_button_after_external_disconnect(qapp):
    from gui_qt.app import MainWindow

    ctl = _mock_controller()
    w = MainWindow(ctl)
    ctl.connect()                                   # mock connect -> connected
    w._drain()                                      # a poll tick reconciles the UI to 'connected'
    assert w.connect_btn.text() == "Disconnect"

    ctl.disconnect()                                # the flasher frees the port out-of-band
    assert ctl.connected is False
    w._drain()                                      # the fix: re-derive the button from ctl.connected
    assert w.connect_btn.text() == "Connect"
    assert "disconnected" in w.status.text()


def test_software_tab_is_flashing_default_false(qapp):
    from gui_qt.software_tab import SoftwareOSTab
    assert SoftwareOSTab().is_flashing() is False    # no worker -> not flashing


def test_main_window_close_blocked_while_os_flashing(qapp, monkeypatch):
    from PyQt5.QtGui import QCloseEvent
    from PyQt5.QtWidgets import QMessageBox
    from gui_qt.app import MainWindow

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: QMessageBox.Ok))

    w = MainWindow(_mock_controller())

    class _FakeTab:
        def is_flashing(self):
            return True

    w.software_os = _FakeTab()
    ev = QCloseEvent()
    ev.accept()                                     # default; the guard must flip it to ignored
    w.closeEvent(ev)
    assert not ev.isAccepted()                      # close refused while the USB write is in flight
