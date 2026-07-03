"""Robustness tests for uf_core/flasher.py:
  * _run_stream kills+reaps the child on a KeyboardInterrupt (BaseException) mid-stream (A-3);
  * _run_stream's optional timeout watchdog kills a wedged child (A-2);
  * the qFlipper hand-off is never reported as a confirmed flash success (A-1).

None of these touch the esptool argv assembly or the real flash paths' return-code propagation.
"""

import threading

import pytest

flasher = pytest.importorskip("uf_core.flasher")


# ── A-3: BaseException (Ctrl-C) mid-stream still kills+reaps the child ──────
def test_run_stream_kills_child_on_keyboard_interrupt(monkeypatch):
    state = {"killed": 0, "closed": False}

    class _Stdout:
        def __iter__(self):
            raise KeyboardInterrupt  # Ctrl-C while streaming output
        def close(self):
            state["closed"] = True

    class _Proc:
        returncode = None
        stdout = _Stdout()
        def poll(self):
            return None if state["killed"] == 0 else self.returncode
        def kill(self):
            state["killed"] += 1
            self.returncode = -9
        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(flasher.subprocess, "Popen", lambda *a, **k: _Proc())
    with pytest.raises(KeyboardInterrupt):
        flasher._run_stream(["dummy", "run"], lambda _s: None)
    assert state["killed"] == 1     # child killed on the interrupt (the `except Exception` alone would miss it)
    assert state["closed"]          # and stdout closed


# ── A-2: the timeout watchdog kills a wedged child ─────────────────────────
def test_run_stream_timeout_kills_hung_child(monkeypatch):
    state = {"killed": 0}
    released = threading.Event()

    class _Stdout:
        def __iter__(self):
            released.wait(5)   # simulate a wedged child holding the pipe until it's killed
            return iter(())
        def close(self):
            pass

    class _Proc:
        returncode = None
        stdout = _Stdout()
        def poll(self):
            return None if state["killed"] == 0 else self.returncode
        def kill(self):
            state["killed"] += 1
            self.returncode = -9
            released.set()
        def wait(self, timeout=None):
            released.set()
            return self.returncode

    monkeypatch.setattr(flasher.subprocess, "Popen", lambda *a, **k: _Proc())
    rc = flasher._run_stream(["dummy", "run"], lambda _s: None, timeout=0.3)
    assert state["killed"] >= 1     # watchdog fired and killed the wedged child
    assert rc != 0                  # a killed probe is a non-success


# ── A-1: qFlipper hand-off is never a confirmed success ────────────────────
def test_qflipper_launch_is_not_reported_as_success(monkeypatch):
    lines = []
    monkeypatch.setattr(flasher.shutil, "which", lambda name: "/fake/qFlipper")
    # qFlipper GUI launched and exited 0 — but that says nothing about whether the firmware installed.
    monkeypatch.setattr(flasher, "_run_stream", lambda argv, on_line, timeout=None: 0)
    rc = flasher.MomentumProfile().flash_assets("COM3", "flipper", "/tmp/fw.tgz", lines.append)
    assert rc != 0
    assert rc == flasher._QFLIPPER_UNVERIFIED
    assert any("cannot confirm" in l or "Verify in qFlipper" in l for l in lines)


def test_qflipper_real_launch_failure_propagates(monkeypatch):
    lines = []
    monkeypatch.setattr(flasher.shutil, "which", lambda name: "/fake/qFlipper")
    monkeypatch.setattr(flasher, "_run_stream", lambda argv, on_line, timeout=None: 7)
    rc = flasher.MomentumProfile().flash_assets("COM3", "flipper", "/tmp/fw.tgz", lines.append)
    assert rc == 7  # a genuine nonzero qFlipper exit is propagated as a failure, not masked
