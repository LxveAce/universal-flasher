"""Tests for GenericSerialController.send_and_capture.

Hardware-free: the controller is constructed with no port, so send() emits the
command echo plus a '[error] not connected' line without touching a serial device.
The regression target is the ring-buffer 500-line cap silently swallowing captured
output on a chatty device.
"""

from __future__ import annotations

from uf_core.controllers import GenericSerialController


def test_capture_returns_emitted_lines_on_fresh_controller():
    c = GenericSerialController(port=None)
    out = c.send_and_capture("status", wait_ms=0)
    assert ">> status" in out
    assert any("not connected" in line for line in out)


def test_capture_survives_full_ring_buffer():
    """Regression: a device that already filled the 500-line ring buffer must not
    make send_and_capture silently return nothing (the old absolute-index approach did)."""
    c = GenericSerialController(port=None)
    for i in range(500):  # saturate the ring buffer to its cap
        c._emit(f"boot line {i}")
    assert len(c._buffer) == 500
    out = c.send_and_capture("status", wait_ms=0)
    assert ">> status" in out
    assert any("not connected" in line for line in out)


def test_capture_only_sees_its_own_window():
    """Lines emitted before the call are not captured; only send()'s output is."""
    c = GenericSerialController(port=None)
    c._emit("earlier noise")
    out = c.send_and_capture("version", wait_ms=0)
    assert "earlier noise" not in out
    assert ">> version" in out


def test_unsubscribe_removes_temporary_collector():
    """After a capture, no leftover subscriber keeps appending (no leak)."""
    c = GenericSerialController(port=None)
    before = len(c._subs)
    c.send_and_capture("status", wait_ms=0)
    assert len(c._subs) == before
