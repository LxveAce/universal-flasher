"""Robustness tests for uf_core/adb_backend.py:
  * _run_adb enforces a real wall-clock deadline (a no-output command can't hang forever) — B-1;
  * install_manual surfaces a failed push/chmod instead of reporting a false success — B-2.

The temp-file hardening (B-3, mkstemp) has no separate test — it's exercised by the install_manual paths.
"""

import threading

import pytest

adb = pytest.importorskip("uf_core.adb_backend")


# ── B-1: the watchdog kills a wedged adb child (no unbounded hang) ─────────
def test_run_adb_timeout_kills_hung_child(monkeypatch):
    state = {"killed": 0}
    released = threading.Event()

    class _Stdout:
        def __iter__(self):
            released.wait(5)   # a command that emits nothing and never exits (e.g. wait-for-device)
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

    monkeypatch.setattr(adb.subprocess, "Popen", lambda *a, **k: _Proc())
    rc, _out = adb._run_adb(["adb", "wait-for-device"], lambda _s: None, timeout=1)
    assert state["killed"] >= 1   # the watchdog fired (the old code's timeout was dead here)
    assert rc == -1               # timed-out path is a non-success


# ── B-2: install_manual reports a failed step, not a false success ─────────
def _daemon(tmp_path):
    p = tmp_path / "rayhunter-daemon"
    p.write_bytes(b"\x7fELF")
    return str(p)


def test_install_manual_fails_when_config_push_fails(tmp_path, monkeypatch):
    push_calls = {"n": 0}

    def fake_push(local, remote, on_line, serial=None):
        push_calls["n"] += 1
        return 0 if push_calls["n"] == 1 else 5  # daemon push ok, config push fails

    def fake_shell(cmd, on_line, serial=None):
        return (0, "MISSING") if "test -f" in cmd else (0, "")

    monkeypatch.setattr(adb, "adb_push", fake_push)
    monkeypatch.setattr(adb, "adb_shell", fake_shell)
    rc = adb.install_manual(_daemon(tmp_path), lambda _s: None)
    assert rc == 5  # the failed config push is surfaced, not masked as a successful install


def test_install_manual_fails_when_init_chmod_fails(tmp_path, monkeypatch):
    def fake_shell(cmd, on_line, serial=None):
        if "test -f" in cmd:
            return 0, "MISSING"
        if cmd.startswith("chmod") and adb._DEVICE_INIT in cmd:
            return 9, ""   # the init-script chmod fails
        return 0, ""

    monkeypatch.setattr(adb, "adb_push", lambda *a, **k: 0)
    monkeypatch.setattr(adb, "adb_shell", fake_shell)
    rc = adb.install_manual(_daemon(tmp_path), lambda _s: None)
    assert rc == 9


def test_install_manual_succeeds_when_all_steps_ok(tmp_path, monkeypatch):
    def fake_shell(cmd, on_line, serial=None):
        return (0, "MISSING") if "test -f" in cmd else (0, "")

    monkeypatch.setattr(adb, "adb_push", lambda *a, **k: 0)
    monkeypatch.setattr(adb, "adb_shell", fake_shell)
    rc = adb.install_manual(_daemon(tmp_path), lambda _s: None)
    assert rc == 0


# ── B-4: install_rayhunter validates admin_ip before any network/adb work ──
# admin_ip is placed on the EFF installer's `--admin-ip` arg (the box it talks to), so a non-IP
# (hostname/URL/garbage) must be rejected up front — never handed to the installer. Parity with the
# cyber-controller sibling. If validation regresses, these would reach the network; the _github_latest
# stub turns that into a hard failure instead of a slow/flaky real fetch.
def _fail_if_network(*_a, **_k):
    raise AssertionError("network reached before admin_ip was validated")


def test_install_rayhunter_rejects_non_ip_admin_ip(monkeypatch):
    monkeypatch.setattr(adb, "_github_latest", _fail_if_network)
    lines = []
    rc = adb.install_rayhunter(lines.append, admin_ip="evil.example.com")
    assert rc == 1
    assert any("invalid admin_ip" in l for l in lines)


def test_install_rayhunter_rejects_url_admin_ip(monkeypatch):
    monkeypatch.setattr(adb, "_github_latest", _fail_if_network)
    lines = []
    rc = adb.install_rayhunter(lines.append, admin_ip="http://169.254.169.254/")
    assert rc == 1
    assert any("invalid admin_ip" in l for l in lines)


def test_install_rayhunter_accepts_valid_ip_and_usb_skips_check(monkeypatch):
    # A valid IP passes validation; the usb method never uses admin_ip, so even a non-IP must NOT be
    # rejected on that path. In both cases we stop right after by failing the release fetch, and assert
    # the "invalid admin_ip" rejection did NOT fire.
    def _stop(*_a, **_k):
        raise RuntimeError("stop-after-validation")

    monkeypatch.setattr(adb, "_github_latest", _stop)
    for kwargs in ({"admin_ip": "10.0.0.5"}, {"admin_ip": "not-an-ip", "method": "usb"}):
        lines = []
        rc = adb.install_rayhunter(lines.append, **kwargs)
        assert rc == 1  # from the forced release-fetch failure, not from admin_ip validation
        assert not any("invalid admin_ip" in l for l in lines)
        assert any("failed to fetch release info" in l for l in lines)
