"""Regression: suicide provisioning must not crash, and the web handler must guard its int fields.

* suicide.build_bundle built an argparse.Namespace OMITTING flash_passes/fast_wipe, but
  provision.build_nvs_rows reads both -> every web/GUI/TUI "provision new bundle" died with
  AttributeError before anything was baked (the CLI path was unaffected; only the wrapper drifted).
* web on_flash_suicide_provision parsed deadman/armed with a bare int() OUTSIDE the try/except that
  guards arm_pin/max_att, so a non-numeric value raised an unhandled exception and the client got no
  error (silent hang) — inconsistent with every other validated field in the same handler.
"""

import argparse
import inspect

import pytest

import suicide


# ── build_bundle exposes flash_passes/fast_wipe with the CLI-matching defaults ─────────────────
def test_build_bundle_signature_carries_flash_passes_and_fast_wipe():
    params = inspect.signature(suicide.build_bundle).parameters
    assert "flash_passes" in params
    assert "fast_wipe" in params
    assert params["flash_passes"].default == 1   # mirrors provision.py --flash-passes default
    assert params["fast_wipe"].default == 0      # mirrors provision.py --fast-wipe default


def _base_namespace(**over):
    ns = dict(kdf_iter=10000, armed=0, arm_pin=27, arm_level=1, arm_pull=2, deadman=1,
              max_att=2, wipe_ota=1, wipe_nvs=1, wipe_spiffs=1, wipe_sd=1, brick=0,
              sd_passes=1, flash_passes=1, fast_wipe=0)
    ns.update(over)
    return argparse.Namespace(**ns)


def test_build_nvs_rows_emits_flash_passes_and_fast_wipe():
    prov = suicide._get_provisioner()
    rows = prov.build_nvs_rows(_base_namespace(), b"\x00" * prov.SALT_LEN, b"\x11" * 32)
    keys = {r[0] for r in rows}
    assert "flash_passes" in keys
    assert "fast_wipe" in keys


def test_build_nvs_rows_without_the_attrs_still_raises():
    prov = suicide._get_provisioner()
    ns = _base_namespace()
    del ns.flash_passes
    del ns.fast_wipe
    with pytest.raises(AttributeError):
        prov.build_nvs_rows(ns, b"\x00" * prov.SALT_LEN, b"\x11" * 32)


def test_build_bundle_wires_flash_passes_and_fast_wipe_into_the_namespace(tmp_path, monkeypatch):
    real_get = suicide._get_provisioner
    captured = {}

    def spy_get():
        prov = real_get()
        real_rows = prov.build_nvs_rows

        def wrapped_rows(args, salt, pwhash):
            captured["args"] = args
            return real_rows(args, salt, pwhash)

        prov.build_nvs_rows = wrapped_rows
        prov.generate_nvs_bin = lambda *a, **k: None  # the only esptool/subprocess dependency
        return prov

    monkeypatch.setattr(suicide, "_get_provisioner", spy_get)
    suicide.build_bundle(password="regression-pw", out_dir=str(tmp_path), fast_wipe=1, flash_passes=3)

    args = captured["args"]
    assert args.flash_passes == 3   # passthrough, not the default
    assert args.fast_wipe == 1


# ── web handler guards deadman/armed like arm_pin/max_att (no silent unhandled crash) ──────────
def test_flash_suicide_provision_guards_nonnumeric_deadman():
    pytest.importorskip("flask_socketio")
    from web import app as webapp

    client = webapp.socketio.test_client(webapp.app, auth={"token": webapp._AUTH_TOKEN})
    assert client.is_connected()
    client.get_received()  # drain anything queued on connect

    # deadman is non-numeric -> before the fix int("x") raised OUTSIDE the guard and no error was emitted
    client.emit("flash_suicide_provision",
                {"port": "COM_TEST", "password": "pw", "password2": "pw", "deadman": "x"})

    msgs = client.get_received()
    errors = [a.get("error", "") for m in msgs if m["name"] == "flash_status" for a in m["args"]]
    assert any("must be numbers" in e for e in errors), (
        "a non-numeric deadman must yield a clean flash_status error, not a silent unhandled crash"
    )
