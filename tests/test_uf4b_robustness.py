"""Batch UF-4b robustness regressions (from an adversarial audit):

 * CaptureLogger.write_serial raced stop()/set_dir() — a check-then-write on self._fp with no lock could
   null the fp between the check and the write, silently dropping in-flight serial lines. Now a lock
   serializes the fp check-and-write against the close-and-null.
 * the serial reader had no cap on a newline-less stream (unbounded buffer growth) — HMG already caps it.
 * commands.build() interpolated values without stripping CR/LF, so an embedded newline could emit a
   second serial command line.
 * adb_backend._run_adb echoed the full argv including a cleartext --admin-password.
 * update_checker treated GitHub 403 (the unauthenticated rate-limit) as fatal instead of degrading
   gracefully like 429.
"""

import threading

import pytest


# --- capture.py: fp lock ------------------------------------------------------------------------- #
def test_capture_write_after_stop_is_dropped_not_crashed(tmp_path):
    from uf_core.capture import CaptureLogger

    cap = CaptureLogger(str(tmp_path))
    path = cap.start()
    cap.write_serial("alive")
    cap.stop()
    cap.write_serial("after-stop")          # a no-op once stopped — must not write, must not crash
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    assert "alive" in body
    assert "after-stop" not in body


def test_write_serial_and_stop_are_mutually_exclusive(tmp_path):
    """stop() must block until an in-flight write releases the lock — the fix for the silent-drop race.

    Without the lock, stop() would complete immediately while a write is mid-flight; with it, stop()
    cannot proceed until the writer leaves the locked region.
    """
    from uf_core.capture import CaptureLogger

    cap = CaptureLogger(str(tmp_path))
    cap.start()
    real_fp = cap._fp

    in_write = threading.Event()
    let_write_finish = threading.Event()

    class _BlockingFp:
        def write(self, s):
            in_write.set()
            let_write_finish.wait(2)
            return real_fp.write(s)

        def flush(self):
            return real_fp.flush()

        def close(self):
            return real_fp.close()

    cap._fp = _BlockingFp()
    stop_done = threading.Event()

    wt = threading.Thread(target=lambda: cap.write_serial("x"))   # parks inside write, holding the lock
    wt.start()
    assert in_write.wait(2)

    st = threading.Thread(target=lambda: (cap.stop(), stop_done.set()))
    st.start()
    assert not stop_done.wait(0.3), "stop() proceeded during an in-flight write — the lock is missing"

    let_write_finish.set()
    assert stop_done.wait(2)
    wt.join(2)
    st.join(2)


def test_capture_concurrent_toggle_is_race_free(tmp_path):
    from uf_core.capture import CaptureLogger

    cap = CaptureLogger(str(tmp_path))
    cap.start()
    go = {"run": True}

    def writer():
        while go["run"]:
            cap.write_serial("x")

    writers = [threading.Thread(target=writer) for _ in range(3)]
    for t in writers:
        t.start()
    for _ in range(60):
        cap.stop()
        cap.start()
    go["run"] = False
    for t in writers:
        t.join(2)
    cap.stop()   # if the lock deadlocked, the join()s above would have timed out and left threads alive
    assert all(not t.is_alive() for t in writers)


# --- controller.py: newline-less buffer cap ------------------------------------------------------ #
def test_read_loop_caps_newlineless_buffer():
    from uf_core.controller import MarauderController, _MAX_LINE_BYTES

    ctl = MarauderController(mock=False)
    emitted = []
    ctl.subscribe(emitted.append)

    class _FakeSer:
        def __init__(self):
            self._sent = False

        def read(self, _n):
            if not self._sent:
                self._sent = True
                return b"A" * (_MAX_LINE_BYTES + 10)   # no newline, over the cap
            ctl._running = False                       # end the loop cleanly on the next iteration
            return b""

    ctl.ser = _FakeSer()
    ctl._running = True
    ctl._read_loop()
    # the oversized partial was flushed instead of growing the buffer forever
    assert any(len(line) >= _MAX_LINE_BYTES for line in emitted)


# --- commands.py: CR/LF stripping ---------------------------------------------------------------- #
def test_build_strips_embedded_newlines():
    from uf_core.commands import Command, Param, build

    cmd = Command(id="t", label="t", base="cmd", params=[Param(name="ssid", flag="-s")])
    out = build(cmd, {"ssid": "evil\nattack -t deauth"})
    assert "\n" not in out and "\r" not in out
    assert out.count("cmd") == 1                        # no injected second command line
    assert "-s evil attack -t deauth" in out


# --- adb_backend.py: secret redaction ------------------------------------------------------------ #
def test_redact_argv_hides_secrets():
    from uf_core.adb_backend import _redact_argv

    out = _redact_argv(["shell", "cmd", "--admin-password", "hunter2", "--user", "0"])
    assert "hunter2" not in out
    assert "***" in out
    assert "--user" in out and "0" in out               # non-secret args preserved

    out2 = _redact_argv(["--password=s3cret", "list"])
    assert "s3cret" not in " ".join(out2)
    assert "--password=***" in out2


# --- update_checker.py: 403 degrades like 429 ---------------------------------------------------- #
def test_fetch_release_degrades_on_403(monkeypatch):
    import urllib.error

    from uf_core import update_checker as uc

    repo = "owner/repo"
    api = uc._github_api_url(repo)
    cached_payload = {"tag": "v9", "release_notes": "", "release_url": ""}
    with uc._cache_lock:
        uc._api_cache[api] = (0.0, cached_payload)      # present but stale (ts=0) -> forces a fetch

    try:
        import uf_core.flasher as fl

        monkeypatch.setattr(fl, "_require_allowed_url", lambda _u: None)

        def _raise_403(_u):
            raise urllib.error.HTTPError(_u, 403, "rate limited", {}, None)

        monkeypatch.setattr(fl, "_http_get", _raise_403)

        got = uc._fetch_release(repo)
        assert got == cached_payload                    # degraded to cache instead of raising
    finally:
        with uc._cache_lock:
            uc._api_cache.pop(api, None)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
