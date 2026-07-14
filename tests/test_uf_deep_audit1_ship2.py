"""Regression guards for the uf-deep-audit-1 ledgered leads, shipped 2026-07-14 (uf-pass1 SHIP-2).

Five confirmed-then-ledgered survivors, each re-confirmed against the real code before fixing:

#3 (MED) os_catalog.flash_os_image — for the Kali checksums_sig model, the ENFORCED SHA came from
   `resolved.sha256` (the resolve-time, non-GPG-verified fetch); the GPG-verified SHA256SUMS was
   verified and then DISCARDED. An attacker who influenced only the resolve-time fetch could pass off
   H_evil and defeat the signature. Fix: bind the enforced hash to the GPG-verified SHA256SUMS.
#4 (MED) web/app.on_connect_serial — opened a live serial session even while a flash/erase/detect
   owned the shared port (esptool needs it exclusively). Fix: refuse while `_flash_busy` is set.
#5 (MED) parsing.MarauderParser.feed — `_list_kind_of` ran on EVERY line, so a data row whose SSID
   contains `list -c` flipped AP/station routing for that row + the rest of the dump. Fix: detect the
   list kind only from echoed command lines (non-`_LIST_RE` rows).
#8 (LOW) parsing._SCAN_RE — the non-greedy ESSID capture truncated at the FIRST embedded
   ` Beacon: <digit>`. Fix: strip only a genuine trailing `Beacon: <n>` stat (number as final token).
#10 (LOW) controllers.GenericSerialController._read_loop — no max-line cap; a newline-less stream
   grew the buffer without bound (OOM). Fix: flush + reset past `_MAX_LINE_BYTES` (MarauderController parity).

Pure logic + fakes: no hardware, no real device, no network is touched.
"""
import hashlib
import os

import pytest


# ── #5: list-kind routing is set only by echoed command lines, not attacker data rows ──

def test_list_kind_not_flipped_by_data_row_named_list_c():
    from uf_core.parsing import MarauderParser

    p = MarauderParser()
    p.feed(">> list -a")                      # echoed command -> route rows to APs
    assert p._list_kind == "ap"
    # a malicious AP whose NAME contains "list -c" arrives as an indexed DATA ROW; it must NOT flip
    # routing to stations (the bug misrouted this row + every subsequent row in the dump).
    kind, _rec = p.feed("[0][CH:6] list -c cafe -55")
    assert p._list_kind == "ap"               # routing unchanged
    assert kind == "ap"                       # the row itself stored as an AP, not a station


def test_list_kind_still_set_from_echoed_command():
    from uf_core.parsing import MarauderParser

    p = MarauderParser()
    p.feed("> #list -c")                      # the device's echoed command line
    assert p._list_kind == "sta"


# ── #8: an SSID containing "Beacon: <digit>" mid-string is preserved; a trailing stat is stripped ──

def test_scanap_ssid_with_embedded_beacon_is_not_truncated():
    from uf_core.parsing import MarauderParser

    p = MarauderParser()
    kind, ap = p.feed("RSSI: -57 Ch: 3 BSSID: 50:ff:20:84:d6:0f ESSID: xfinity Beacon: 5 area")
    assert kind == "ap"
    assert ap.ssid == "xfinity Beacon: 5 area"   # embedded "Beacon: 5" is NOT a trailing stat


def test_scanap_trailing_beacon_stat_is_stripped():
    from uf_core.parsing import MarauderParser

    p = MarauderParser()
    kind, ap = p.feed("RSSI: -60 Ch: 1 BSSID: aa:bb:cc:dd:ee:ff ESSID: HomeNet Beacon: 42")
    assert ap.ssid == "HomeNet"               # a genuine trailing "Beacon: <n>" stat IS stripped


# ── #10: the generic serial read-loop caps an un-terminated buffer ──

def test_generic_read_loop_caps_unterminated_buffer():
    from uf_core import controllers

    c = controllers.GenericSerialController(port="X")
    emitted: list = []
    c.subscribe(emitted.append)

    class FakeSer:
        def __init__(self):
            self.n = 0

        def read(self, size):
            self.n += 1
            if self.n == 1:
                return b"A" * (controllers._MAX_LINE_BYTES + 10)  # newline-less flood
            c._running = False                # end the loop on the 2nd read
            return b""

    c.ser = FakeSer()
    c._running = True
    c._read_loop()
    # the oversized partial line must have been flushed (not silently accumulated forever)
    assert any(len(line) >= controllers._MAX_LINE_BYTES for line in emitted)


# ── #4: connect_serial refuses while a flash/erase owns the shared port ──

def test_connect_serial_refused_while_flash_busy(monkeypatch):
    app_mod = pytest.importorskip("web.app")
    events: list = []
    monkeypatch.setattr(app_mod, "emit", lambda *a, **k: events.append(a))
    monkeypatch.setattr(app_mod, "ctrl", None)
    made = {"ctrl": False}

    class Boom:
        def __init__(self, *a, **k):
            made["ctrl"] = True

    monkeypatch.setattr(app_mod, "MarauderController", Boom)
    app_mod._flash_busy = True
    try:
        app_mod.on_connect_serial({"port": "COM7"})
    finally:
        app_mod._flash_busy = False

    assert made["ctrl"] is False              # must NOT open a session while a flash owns the port
    assert events and events[-1][0] == "status" and events[-1][1].get("connected") is False


# ── #3: checksums_sig enforces the GPG-verified SHA256SUMS hash, not the resolve-time value ──

def test_checksums_sig_enforces_gpg_signed_hash_not_resolve_time(monkeypatch, tmp_path):
    from uf_core import os_catalog as oc

    image = tmp_path / "kali.iso"
    image.write_bytes(b"the real kali image bytes")
    real_sha = hashlib.sha256(image.read_bytes()).hexdigest()

    captured: dict = {}
    monkeypatch.setattr(oc, "verify_gpg_detached", lambda *a, **k: True)  # signature VALID

    def fake_verify_sha256(p, expected, on_line, on_progress=None):
        captured["expected"] = expected
        return False                          # force an early refuse -> no device write happens

    monkeypatch.setattr(oc, "verify_sha256", fake_verify_sha256)

    sums = tmp_path / "SHA256SUMS"
    sums.write_text(f"{real_sha}  {os.path.basename(str(image))}\n")  # signed file lists the REAL hash
    r = oc.Resolved(image_id="kali", version="2026.2", image_url="https://x", image_type="iso",
                    verify_model="checksums_sig", sha256="b" * 64)  # resolve-time (attacker) value
    with pytest.raises(ValueError, match="SHA-256"):
        oc.flash_os_image(oc.get_image("kali"), r, str(image), r"\\.\PhysicalDrive9", lambda s: None,
                          checksums_path=str(sums), checksums_sig_path=str(sums) + ".gpg",
                          confirmed=True)

    assert captured["expected"] == real_sha   # bound to the SIGNED hash, not resolved.sha256 ("b"*64)
