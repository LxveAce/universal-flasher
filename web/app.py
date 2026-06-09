"""
Universal Flasher — Browser UI (localhost Flask + SocketIO).

Same core, same features, but served as a local web page at http://localhost:5000.
Reuses uf_core (controller, commands, parsing, capture) identically to the
desktop and terminal UIs.
"""

import argparse
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from uf_core import MarauderController, MarauderParser, CaptureLogger, __version__
from uf_core import commands, flasher

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

ctrl = None
parser = MarauderParser()
logger = CaptureLogger()
_autolist_timer = None
_autolist_active = False
_snapshot_counter = 0
# Guards a single esptool operation at a time: detect/flash/suicide/erase all share the serial
# port, and two concurrent esptool runs would collide on the port. Set/cleared by the worker.
_flash_busy = False

# ── helpers ─────────────────────────────────────────────────────────────── #

def _on_line(line: str):
    global _snapshot_counter
    parser.feed(line)
    if logger.enabled:
        logger.write_serial(line)
        _snapshot_counter += 1
        if _snapshot_counter >= 5:
            logger.write_snapshot(parser.ap_rows(), parser.station_rows())
            _snapshot_counter = 0
    socketio.emit("serial", {"line": line})


def _push_tables():
    aps = [{"index": a.index, "ssid": a.ssid, "channel": a.channel,
            "rssi": a.rssi, "bssid": a.bssid} for a in parser.ap_rows()]
    stas = [{"index": s.index, "mac": s.mac, "ap_bssid": s.ap_bssid,
             "rssi": s.rssi} for s in parser.station_rows()]
    socketio.emit("tables", {"aps": aps, "stations": stas})


def _cancel_autolist_timer():
    global _autolist_timer
    if _autolist_timer is not None:
        _autolist_timer.cancel()
        _autolist_timer = None


def _autolist_tick():
    global _autolist_timer
    if _autolist_active and ctrl and ctrl.connected:
        ctrl.send("list -a")
    if _autolist_active:
        _autolist_timer = threading.Timer(3.0, _autolist_tick)
        _autolist_timer.daemon = True
        _autolist_timer.start()


# ── routes ──────────────────────────────────────────────────────────────── #

@app.route("/")
def index():
    return render_template("index.html", version=__version__)


@app.route("/api/commands")
def api_commands():
    return jsonify(commands.to_dict())


@app.route("/api/ports")
def api_ports():
    ports = MarauderController.list_ports()
    return jsonify([{"device": d, "description": desc} for d, desc in ports])


@app.route("/api/status")
def api_status():
    return jsonify({
        "connected": ctrl.connected if ctrl else False,
        "port": ctrl.port if ctrl else None,
        "logging": logger.enabled,
        "log_dir": logger.dir,
        "version": __version__,
    })


@app.route("/api/profiles")
def api_profiles():
    """Firmware profiles for the Flash modal: id/label + the two flags the UI gates on
    (supports_suicide -> shows the suicide checkbox; image_model -> merged vs multi-file)."""
    out = []
    for pid, label in flasher.list_profiles():
        p = flasher.get_profile(pid)
        out.append({
            "id": pid,
            "label": p.label,
            "supports_suicide": bool(p.supports_suicide),
            "image_model": p.image_model,
        })
    return jsonify(out)


# ── socket events ───────────────────────────────────────────────────────── #

@socketio.on("connect_serial")
def on_connect_serial(data):
    global ctrl
    port = data.get("port") or None
    mock = data.get("mock", False)
    try:
        if ctrl and ctrl.connected:
            ctrl.disconnect()
        ctrl = MarauderController(port=port, mock=mock)
        ctrl.subscribe(_on_line)
        connected_port = ctrl.connect()
        emit("status", {"connected": True, "port": connected_port})
    except Exception as e:
        emit("status", {"connected": False, "error": str(e)})


@socketio.on("disconnect_serial")
def on_disconnect_serial():
    global ctrl, _autolist_active
    _autolist_active = False
    _cancel_autolist_timer()
    if ctrl:
        ctrl.disconnect()
    emit("status", {"connected": False, "port": None})


@socketio.on("send_command")
def on_send(data):
    if not ctrl or not ctrl.connected:
        emit("serial", {"line": "[error] not connected"})
        return
    raw = data.get("raw", "").strip()
    cmd_id = data.get("cmd_id")
    values = data.get("values", {})

    if raw:
        ctrl.send(raw)
    elif cmd_id:
        cmd = commands.get(cmd_id)
        if cmd:
            built = commands.build(cmd, values)
            ctrl.send(built)
        else:
            emit("serial", {"line": f"[error] unknown command: {cmd_id}"})


@socketio.on("stop")
def on_stop():
    if ctrl and ctrl.connected:
        ctrl.stop()
    global _autolist_active
    _autolist_active = False
    _cancel_autolist_timer()


@socketio.on("autolist")
def on_autolist(data):
    global _autolist_active
    _cancel_autolist_timer()
    _autolist_active = data.get("enabled", False)
    if _autolist_active:
        _autolist_tick()


@socketio.on("get_tables")
def on_get_tables():
    _push_tables()


@socketio.on("clear_tables")
def on_clear_tables():
    parser.clear()
    _push_tables()


@socketio.on("toggle_log")
def on_toggle_log(data):
    if data.get("enabled"):
        log_dir = data.get("dir") or logger.dir
        logger.set_dir(log_dir)
        path = logger.start()
        emit("log_status", {"enabled": True, "path": path})
    else:
        logger.stop()
        emit("log_status", {"enabled": False})


# ── flasher ─────────────────────────────────────────────────────────────── #

def _flash_line(line):
    """Stream one esptool/flasher output line to the browser console (same channel as
    serial output, so the existing #console 'serial' listener renders it)."""
    socketio.emit("serial", {"line": line})


def _free_serial():
    """Disconnect the live serial session (if any) so esptool can own the port.

    esptool opens the port exclusively; if the app is still connected the flash fails with a
    'port busy' error. Mirrors FlasherDialog._free in the Qt GUI."""
    global ctrl, _autolist_active
    _autolist_active = False
    _cancel_autolist_timer()
    if ctrl and ctrl.connected:
        _flash_line("[i] closing serial session for esptool")
        ctrl.disconnect()


def _run_flash_task(fn):
    """Run a blocking flasher job in a background task under the busy flag.

    Rejects a second concurrent flash (the shared serial port can only be driven by one
    esptool at a time). Always clears the busy flag and emits the done/rc terminator."""
    global _flash_busy
    if _flash_busy:
        socketio.emit("flash_status", {"error": "A flash/erase is already in progress."})
        return
    _flash_busy = True

    def runner():
        global _flash_busy
        rc = -1
        try:
            rc = fn()
        except Exception as e:
            _flash_line(f"[error] {e}")
        finally:
            _flash_busy = False
            socketio.emit("flash_status", {"done": True, "rc": rc})

    socketio.start_background_task(runner)


@socketio.on("flash_detect")
def on_flash_detect(data):
    port = data.get("port", "")
    if not port:
        emit("flash_status", {"error": "No port specified"})
        return
    try:
        chip = flasher.detect_chip(port, _flash_line)
        emit("flash_status", {"chip": chip})
    except Exception as e:
        emit("flash_status", {"error": str(e)})


@socketio.on("flash_releases")
def on_flash_releases(data=None):
    """Load the latest release for the chosen firmware profile (default: marauder) and emit
    the variant list, filtered to the detected chip when one is supplied."""
    data = data or {}
    pid = data.get("profile", "marauder")
    chip = data.get("chip") or None
    try:
        profile = flasher.get_profile(pid)
    except KeyError:
        emit("flash_status", {"error": f"unknown firmware profile: {pid}"})
        return
    try:
        tag, assets = profile.latest_release()
        shown = profile.variants_for_chip(assets, chip) if chip else assets
        emit("flash_status", {
            "tag": tag,
            "assets": [{"name": a["name"], "label": a.get("label", a["name"]),
                        "chip": a.get("chip", "")} for a in shown],
        })
    except Exception as e:
        emit("flash_status", {"error": str(e)})


@socketio.on("flash_run")
def on_flash_run(data):
    """Mirror FlasherDialog._flash for the web: resolve chip, fetch/select the asset, fetch
    support files for a full/multi-image flash, then flash via the chosen profile."""
    port = (data.get("port") or "").strip()
    if not port:
        emit("flash_status", {"error": "No port specified"})
        return
    pid = data.get("profile", "marauder")
    try:
        profile = flasher.get_profile(pid)
    except KeyError:
        emit("flash_status", {"error": f"unknown firmware profile: {pid}"})
        return
    mode = data.get("mode", "app")
    source = data.get("source", "download")
    variant_name = data.get("variant") or None
    local = (data.get("local") or "").strip()
    chip_hint = data.get("chip") or None
    try:
        baud = int(data.get("baud", 921600))
    except (TypeError, ValueError):
        baud = 921600
    is_marauder = (profile.id == "marauder")
    # 'custom' is local-only — never download.
    use_download = (source == "download") and profile.id != "custom"

    _free_serial()

    def job():
        chip = chip_hint or flasher.detect_chip(port, _flash_line)
        if not chip:
            _flash_line("[error] chip unknown")
            return 2
        cache = flasher.cache_dir()
        app_offset = None
        if use_download:
            tag, assets = profile.latest_release()
            asset = next((a for a in assets if a["name"] == variant_name), None)
            if not asset:
                _flash_line("[error] no variant selected")
                return 2
            if asset["chip"] != chip:
                _flash_line(f"[!] variant is {asset['chip']} but chip is {chip}")
            app = flasher.download_to(asset["url"], cache, asset["name"], _flash_line)
            app_offset = asset.get("offset")
        else:
            if not local:
                _flash_line("[error] no local .bin path provided")
                return 2
            app = local
        if is_marauder:
            support = flasher.support_files(chip, cache, _flash_line) if mode == "full" else None
            return flasher.flash(port, chip, app, _flash_line, mode=mode, baud=baud, support=support)
        support = profile.support_files(chip, cache, _flash_line) if mode == "full" else None
        return profile.flash_assets(port, chip, app, _flash_line, mode=mode, baud=baud,
                                    support=support, app_offset=app_offset)

    _run_flash_task(job)


@socketio.on("flash_suicide_run")
def on_flash_suicide_run(data):
    """Flash a pre-provisioned Suicide-Marauder bundle. flasher.flash_suicide enforces the
    sha256 + path-traversal guards; this app never burns eFuses / does T2 here."""
    port = (data.get("port") or "").strip()
    if not port:
        emit("flash_status", {"error": "No port specified"})
        return
    bundle_dir = (data.get("bundle_dir") or "").strip()
    if not bundle_dir:
        emit("flash_status", {"error": "No bundle directory specified"})
        return
    chip_hint = data.get("chip") or None
    try:
        baud = int(data.get("baud", 921600))
    except (TypeError, ValueError):
        baud = 921600

    _free_serial()

    def job():
        chip = chip_hint or flasher.detect_chip(port, _flash_line)
        if not chip:
            _flash_line("[error] chip unknown")
            return 2
        return flasher.flash_suicide(port, chip, bundle_dir, _flash_line, baud=baud)

    _run_flash_task(job)


@socketio.on("flash_suicide_provision")
def on_flash_suicide_provision(data):
    """Provision a new suicide bundle on the host, then flash it to the board."""
    port = (data.get("port") or "").strip()
    if not port:
        emit("flash_status", {"error": "No port specified"})
        return
    pw = data.get("password", "")
    pw2 = data.get("password2", "")
    if not pw:
        emit("flash_status", {"error": "Enter a boot password"})
        return
    if pw != pw2:
        emit("flash_status", {"error": "Passwords don't match"})
        return
    variant = data.get("variant", "fork")
    try:
        arm_pin = int(data.get("arm_pin", 27))
        max_att = int(data.get("max_att", 2))
    except (TypeError, ValueError):
        emit("flash_status", {"error": "arm_pin and max_att must be numbers"})
        return
    deadman = int(data.get("deadman", 1))
    armed = int(data.get("armed", 0))
    build_dir = (data.get("build_dir") or "").strip() or None
    chip_hint = data.get("chip") or None
    try:
        baud = int(data.get("baud", 921600))
    except (TypeError, ValueError):
        baud = 921600

    _free_serial()

    def job():
        chip = chip_hint or flasher.detect_chip(port, _flash_line)
        if not chip:
            _flash_line("[error] chip unknown")
            return 2
        import suicide
        _flash_line("[*] provisioning suicide bundle...")
        try:
            bundle_path = suicide.build_bundle(
                password=pw, chip=chip, variant=variant,
                arm_pin=arm_pin, max_att=max_att,
                deadman=deadman, armed=armed,
                build_dir=build_dir, on_line=_flash_line,
            )
        except Exception as e:
            _flash_line(f"[error] provisioning failed: {e}")
            return 2
        return flasher.flash_suicide(port, chip, bundle_path, _flash_line, baud=baud)

    _run_flash_task(job)


@socketio.on("flash_erase")
def on_flash_erase(data):
    port = (data.get("port") or "").strip()
    if not port:
        emit("flash_status", {"error": "No port specified"})
        return
    chip_hint = data.get("chip") or None

    _free_serial()

    def job():
        chip = chip_hint or flasher.detect_chip(port, _flash_line) or "esp32"
        return flasher.erase(port, chip, _flash_line)

    _run_flash_task(job)


# ── periodic table push ─────────────────────────────────────────────────── #

def _table_pusher():
    while True:
        socketio.sleep(0.7)
        if parser.dirty:
            parser.dirty = False
            _push_tables()

socketio.start_background_task(_table_pusher)


# ── main ────────────────────────────────────────────────────────────────── #

def main():
    ap = argparse.ArgumentParser(description="Universal Flasher — Browser UI")
    ap.add_argument("--port", default=None, help="Serial port (auto-detect if omitted)")
    ap.add_argument("--mock", action="store_true", help="Mock mode (no hardware)")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (default: localhost only)")
    ap.add_argument("--web-port", type=int, default=5000, help="HTTP port (default: 5000)")
    ap.add_argument("--log", nargs="?", const="", default=None, help="Start logging (optionally set dir)")
    args = ap.parse_args()

    if args.log is not None:
        if args.log:
            logger.set_dir(args.log)
        logger.start()

    if args.port or args.mock:
        global ctrl
        ctrl = MarauderController(port=args.port, mock=args.mock)
        ctrl.subscribe(_on_line)
        try:
            ctrl.connect()
            print(f"[+] Connected to {ctrl.port}")
        except Exception as e:
            print(f"[!] Auto-connect failed: {e}")

    print(f"\n  Universal Flasher v{__version__} — Browser UI")
    print(f"  Open http://{args.host}:{args.web_port} in your browser\n")

    socketio.run(app, host=args.host, port=args.web_port, debug=False,
                 allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
