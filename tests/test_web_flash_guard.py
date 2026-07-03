"""UF-WEB (D-1/D-2): the web flash_detect handler must share the esptool busy-guard.

Every esptool entrypoint drives the same serial port, so only one may run at a time and each must
free the live serial session first. flash_detect previously did neither — it read _flash_busy but
never set it (so a detect could race a flash onto the same port) and never called _free_serial()
(so detect-while-connected failed "port busy"). These tests pin the corrected behavior.
"""

import pytest

app_mod = pytest.importorskip("web.app")


def _reset():
    app_mod._flash_busy = False


# ── the atomic claim is mutually exclusive (fixes the check-then-set race) ──
def test_acquire_flash_is_exclusive():
    _reset()
    assert app_mod._acquire_flash() is True
    assert app_mod._acquire_flash() is False      # already claimed — a 2nd tab can't also pass
    app_mod._release_flash()
    assert app_mod._acquire_flash() is True
    app_mod._release_flash()


# ── D-1 + D-2: detect claims the port and frees the serial before esptool ──
def test_flash_detect_claims_busy_and_frees_serial(monkeypatch):
    _reset()
    events = []
    monkeypatch.setattr(app_mod, "emit", lambda *a, **k: events.append(a))
    monkeypatch.setattr(app_mod, "_flash_line", lambda *a, **k: None)
    monkeypatch.setattr(app_mod, "_cancel_autolist_timer", lambda: None)

    freed = {"disconnected": False}

    class FakeCtrl:
        connected = True

        def disconnect(self):
            freed["disconnected"] = True
            self.connected = False

    monkeypatch.setattr(app_mod, "ctrl", FakeCtrl())

    seen = {}

    def fake_detect(port, on_line):
        seen["busy_during"] = app_mod._flash_busy       # claimed for the duration of the detect
        seen["freed_before"] = freed["disconnected"]    # serial released before esptool ran
        return "ESP32-S3"

    monkeypatch.setattr(app_mod.flasher, "detect_chip", fake_detect)

    app_mod.on_flash_detect({"port": "COM7"})

    assert seen["busy_during"] is True                  # D-1
    assert seen["freed_before"] is True                 # D-2
    assert app_mod._flash_busy is False                 # released in finally
    assert any(a[0] == "flash_status" and a[1].get("chip") == "ESP32-S3" for a in events)


# ── a detect is rejected (and never touches esptool) while a flash is running ──
def test_flash_detect_rejected_while_busy(monkeypatch):
    _reset()
    app_mod._flash_busy = True                          # a flash/erase already owns the port
    events = []
    monkeypatch.setattr(app_mod, "emit", lambda *a, **k: events.append(a))
    called = {"detect": False}
    monkeypatch.setattr(app_mod.flasher, "detect_chip",
                        lambda *a, **k: called.__setitem__("detect", True))

    app_mod.on_flash_detect({"port": "COM7"})

    assert called["detect"] is False                    # never spawned a 2nd esptool
    assert app_mod._flash_busy is True                  # left the in-progress flash's claim intact
    assert any("in progress" in str(a) for a in events)
    _reset()
