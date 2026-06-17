#!/usr/bin/env python3
"""
Universal Flasher TUI — a terminal application (Textual) for Kali Linux.

Runs entirely in the terminal: a command tree on the left, live serial output on
the right, a raw command box at the bottom. Great over SSH / on a headless console.

Run:   python3 tui/app.py            (auto-detects the port)
       python3 tui/app.py --port /dev/ttyUSB0
       python3 tui/app.py --mock     (no hardware, for trying the UI)
"""

import argparse
import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uf_core import MarauderController, MarauderParser, CaptureLogger, commands, flasher

try:
    # Shared, neutral plain-language copy reused for hover help where a term matches.
    from uf_core.uihelp import GLOSSARY
except Exception:                                  # pragma: no cover - defensive
    GLOSSARY = {}

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Header, Footer, Tree, Input, Button, Select, Static, Label, DataTable

try:
    from textual.widgets import Markdown
except ImportError:
    Markdown = None


def _guide_text():
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "GUIDE.md")
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ("# Guide\n\nGUIDE.md not found.\n\n"
                "https://github.com/LxveAce/headless-marauder-gui/blob/main/GUIDE.md")


class GuideScreen(ModalScreen):
    CSS = "#guidebox { width: 92%; height: 92%; border: round $accent; background: $surface; padding: 1; }"
    BINDINGS = [("escape", "close", "Close"), ("g", "close", "Close")]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="guidebox"):
            if Markdown is not None:
                yield Markdown(_guide_text())
            else:
                yield Static(_guide_text())
        yield Footer()

    def action_close(self):
        self.dismiss()

try:                       # widget was renamed across Textual versions
    from textual.widgets import RichLog
except ImportError:        # older Textual
    from textual.widgets import TextLog as RichLog


def _set_tip(widget, text):
    """Attach hover/help text to a widget without breaking on older Textual.

    Textual exposes a ``tooltip`` property on widgets (>=0.30). We set it
    defensively: if a given widget or Textual version does not support it,
    we silently skip — the focus-driven ``#desc`` help line stays as the
    fallback so the UI is never less helpful, just never broken.
    """
    if not text:
        return widget                  # still safe to yield in compose()
    try:
        widget.tooltip = text
    except Exception:
        pass
    return widget


class FlashScreen(ModalScreen):
    """Modal firmware flasher: detect chip, fetch firmware, flash."""

    CSS = """
    #flash { width: 90%; height: 90%; border: round $accent; background: $surface; padding: 1; }
    #flog { height: 1fr; border: round $accent; }
    #flash Button { margin: 0 1; }
    """
    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, controller: MarauderController):
        super().__init__()
        self.ctl = controller
        self.chip = None
        self.assets = []
        self.tag = ""
        self._by_name = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="flash"):
            yield Label("Flash Marauder Firmware")
            yield _set_tip(
                Input(value=(self.ctl.port or ""), placeholder="port e.g. /dev/ttyUSB0", id="fport"),
                "Serial port of the board to flash (e.g. /dev/ttyUSB0 or COM5). "
                "Defaults to the port this app is connected on.",
            )
            with Horizontal():
                yield _set_tip(
                    Button("Detect chip", id="detect"),
                    "Probe the board over serial to identify the ESP32 family "
                    "(esp32 / esp32-s2 / -s3 / -c3). Run this first so the right "
                    "firmware variant is offered.",
                )
                yield _set_tip(
                    Button("Load release", id="load"),
                    "Fetch the latest Marauder firmware release and list the "
                    "available variants for the detected chip.",
                )
            yield _set_tip(
                Static("chip: ?", id="chiplbl"),
                "The detected ESP32 chip family. Shows '?' until you press "
                "Detect chip (or it is resolved during a flash).",
            )
            yield _set_tip(
                Select([], prompt="firmware variant", id="variant"),
                "Pick which firmware image to write. The list is filtered to the "
                "detected chip after Load release; the recommended default is "
                "preselected.",
            )
            with Horizontal():
                yield _set_tip(
                    Button("Flash app", id="flash_app", variant="success"),
                    GLOSSARY.get(
                        "app-only flash",
                        "Writes only the application image (offset 0x10000), "
                        "leaving the existing bootloader and partitions in place. "
                        "Use to update a board that already runs Marauder.",
                    ),
                )
                yield _set_tip(
                    Button("Full flash", id="flash_full", variant="warning"),
                    GLOSSARY.get(
                        "full flash",
                        "Writes bootloader, partition table, boot_app0 and the "
                        "application image. Use for a brand-new or freshly erased chip.",
                    ),
                )
                yield _set_tip(
                    Button("Erase", id="erase", variant="error"),
                    "Erase the entire flash on the board. This removes the current "
                    "firmware and settings — follow with a Full flash to restore.",
                )
                yield _set_tip(
                    Button("Close", id="close"),
                    "Close this flasher and return to the main TUI (Esc also closes).",
                )
            yield _set_tip(
                RichLog(id="flog", highlight=False, markup=False, wrap=True),
                "Live output from chip detection, downloads and esptool. "
                "Read here if a flash fails — the esptool exit code is shown.",
            )

    def on_mount(self):
        if not flasher.esptool_available():
            self._log("[!] esptool not found — pip install esptool")

    # helpers
    def _log(self, s): self.query_one("#flog", RichLog).write(s)
    def _line(self): return lambda s: self.app.call_from_thread(self._log, s)
    def _port(self): return self.query_one("#fport", Input).value.strip()

    def _free(self, on=None):
        # called from worker threads — never touch widgets here; log via the on() callback
        if self.ctl.connected:
            if on:
                on("[i] closing serial session so esptool can use the port")
            self.ctl.disconnect()

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        port = self._port()                       # read widgets on the UI thread, pass to workers
        if bid == "close":
            self.dismiss(); return
        if bid == "detect":
            self.run_worker(lambda: self._detect(port), thread=True); return
        if bid == "load":
            self.run_worker(self._load, thread=True); return
        if bid == "erase":
            self.run_worker(lambda: self._erase(port), thread=True); return
        if bid in ("flash_app", "flash_full"):
            mode = "app" if bid == "flash_app" else "full"
            name = self.query_one("#variant", Select).value
            self.run_worker(lambda: self._flash(mode, port, name), thread=True)

    # workers (run in threads) — all widget access via call_from_thread, all bodies guarded
    def _set_chip_label(self):
        self.query_one("#chiplbl", Static).update(f"chip: {self.chip or 'unknown'}")

    def _detect(self, port):
        on = self._line()
        try:
            self._free(on)
            self.chip = flasher.detect_chip(port, on)
            self.app.call_from_thread(self._set_chip_label)
            self.app.call_from_thread(self._refill)
        except Exception as e:
            on(f"[error] {e}")

    def _load(self):
        on = self._line()
        try:
            on("[*] fetching latest release...")
            self.tag, self.assets = flasher.latest_release()
            on(f"[i] {self.tag}: {len(self.assets)} variants")
            self.app.call_from_thread(self._refill)
        except Exception as e:
            on(f"[error] {e}")

    def _refill(self):
        items = flasher.variants_for_chip(self.assets, self.chip) if self.chip else self.assets
        if not items:
            items = self.assets
        self._by_name = {a["name"]: a for a in items}
        opts = [(f"{a['label']} [{a['name']}]", a["name"]) for a in items]
        sel = self.query_one("#variant", Select)
        sel.set_options(opts)
        if self.chip and items:
            d = flasher.default_variant(items, self.chip)
            if d:
                sel.value = d["name"]

    def _resolve_chip(self, port, on):
        if self.chip:
            return self.chip
        on("[*] detecting chip...")
        self.chip = flasher.detect_chip(port, on)
        return self.chip

    def _flash(self, mode, port, name):
        on = self._line()
        try:
            self._free(on)
            if not port:
                on("[error] enter a port"); return
            asset = self._by_name.get(name)
            if not asset:
                on("[error] Load release + pick a variant first"); return
            chip = self._resolve_chip(port, on)
            if not chip:
                on("[error] chip unknown"); return
            if asset["chip"] != chip:
                on(f"[!] variant is for {asset['chip']} but chip is {chip}")
            cache = flasher.cache_dir()
            app = flasher.download_to(asset["url"], cache, asset["name"], on)
            support = None
            if mode == "full":
                on("[*] fetching bootloader/partitions/boot_app0...")
                support = flasher.support_files(chip, cache, on)
            rc = flasher.flash(port, chip, app, on, mode=mode, baud=921600, support=support)
            on("[done] power-cycle the board" if rc == 0 else f"[x] esptool exit {rc}")
        except Exception as e:
            on(f"[error] {e}")

    def _erase(self, port):
        on = self._line()
        try:
            self._free(on)
            chip = self._resolve_chip(port, on) or "esp32"
            flasher.erase(port, chip, on)
        except Exception as e:
            on(f"[error] {e}")

    def action_close(self):
        self.dismiss()


class SuicideFlashScreen(ModalScreen):
    """Modal suicide-build provisioner and flasher."""

    CSS = """
    #suicide { width: 90%; height: 92%; border: round $accent; background: $surface; padding: 1; }
    #slog { height: 1fr; border: round $accent; }
    #suicide Button { margin: 0 1; }
    """
    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, controller: MarauderController):
        super().__init__()
        self.ctl = controller
        self.chip = None

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="suicide"):
            yield Label("Suicide Build — Provision & Flash")
            yield Input(value=(self.ctl.port or ""), placeholder="port e.g. /dev/ttyUSB0", id="sport")
            yield Select(
                [("Provision new bundle", "new"), ("Flash existing bundle", "existing")],
                value="new", id="smode",
            )
            yield Static("— Provision settings —")
            yield Input(placeholder="Boot password", password=True, id="spw")
            yield Input(placeholder="Confirm password", password=True, id="spw2")
            yield Select(
                [("fork", "fork"), ("guardian", "guardian")],
                value="fork", id="svariant",
            )
            yield Input(value="27", placeholder="Arm GPIO pin (0-48)", id="sarm")
            yield Input(value="2", placeholder="Max fail attempts (1-10)", id="smaxatt")
            yield Select([("Yes", 1), ("No", 0)], value=1, id="sdeadman")
            yield Static("Dead-man switch ↑  ·  Armed ↓")
            yield Select([("No — safe mode", 0), ("Yes — ARMED", 1)], value=0, id="sarmed")
            yield Input(placeholder="Build dir (compiled firmware, optional)", id="sbuilddir")
            yield Static("— Existing bundle —")
            yield Input(placeholder="Bundle directory path", id="sbundle")
            yield Static("chip: ?", id="schiplbl")
            with Horizontal():
                yield Button("Detect chip", id="sdetect")
                yield Button("Flash", id="sflash", variant="warning")
                yield Button("Close", id="sclose")
            yield RichLog(id="slog", highlight=False, markup=False, wrap=True)

    def on_mount(self):
        if not flasher.esptool_available():
            self._log("[!] esptool not found — pip install esptool")

    def _log(self, s):
        self.query_one("#slog", RichLog).write(s)

    def _line(self):
        return lambda s: self.app.call_from_thread(self._log, s)

    def _port(self):
        return self.query_one("#sport", Input).value.strip()

    def _free(self, on=None):
        if self.ctl.connected:
            if on:
                on("[i] closing serial session for esptool")
            self.ctl.disconnect()

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "sclose":
            self.dismiss(); return
        port = self._port()
        if bid == "sdetect":
            self.run_worker(lambda: self._detect(port), thread=True); return
        if bid == "sflash":
            mode = self.query_one("#smode", Select).value
            if mode == "existing":
                bundle = self.query_one("#sbundle", Input).value.strip()
                self.run_worker(lambda: self._flash_existing(port, bundle), thread=True)
            else:
                pw = self.query_one("#spw", Input).value
                pw2 = self.query_one("#spw2", Input).value
                variant = self.query_one("#svariant", Select).value
                arm_pin = self.query_one("#sarm", Input).value.strip()
                max_att = self.query_one("#smaxatt", Input).value.strip()
                deadman = self.query_one("#sdeadman", Select).value
                armed = self.query_one("#sarmed", Select).value
                build_dir = self.query_one("#sbuilddir", Input).value.strip() or None
                self.query_one("#spw", Input).value = ""
                self.query_one("#spw2", Input).value = ""
                self.run_worker(
                    lambda: self._flash_new(port, pw, pw2, variant, arm_pin, max_att, deadman, armed, build_dir),
                    thread=True,
                )

    def _detect(self, port):
        on = self._line()
        try:
            self._free(on)
            self.chip = flasher.detect_chip(port, on)
            self.app.call_from_thread(
                lambda: self.query_one("#schiplbl", Static).update(f"chip: {self.chip or 'unknown'}")
            )
        except Exception as e:
            on(f"[error] {e}")

    def _resolve_chip(self, port, on):
        if self.chip:
            return self.chip
        on("[*] detecting chip...")
        self.chip = flasher.detect_chip(port, on)
        return self.chip

    def _flash_existing(self, port, bundle_dir):
        on = self._line()
        try:
            if not bundle_dir:
                on("[error] enter a bundle directory path"); return
            manifest = flasher.read_bundle_manifest(bundle_dir)
            man_chip = manifest.get("chip")
            self._free(on)
            chip = man_chip or self._resolve_chip(port, on)
            if not chip:
                on("[error] chip unknown"); return
            on(f"[*] flashing suicide bundle from {bundle_dir} ...")
            rc = flasher.flash_suicide(port, chip, bundle_dir, on, baud=921600)
            on("[done] power-cycle the board" if rc == 0 else f"[x] esptool exit {rc}")
        except Exception as e:
            on(f"[error] {e}")

    def _flash_new(self, port, pw, pw2, variant, arm_pin, max_att, deadman, armed, build_dir):
        on = self._line()
        try:
            if not pw:
                on("[error] enter a boot password"); return
            if pw != pw2:
                on("[error] passwords don't match"); return
            try:
                arm_pin = int(arm_pin)
                max_att = int(max_att)
            except ValueError:
                on("[error] arm pin and max attempts must be numbers"); return
            self._free(on)
            chip = self._resolve_chip(port, on)
            if not chip:
                on("[error] chip unknown"); return
            import suicide
            on("[*] provisioning suicide bundle...")
            bundle_path = suicide.build_bundle(
                password=pw, chip=chip, variant=variant,
                arm_pin=arm_pin, max_att=max_att,
                deadman=int(deadman), armed=int(armed),
                build_dir=build_dir, on_line=on,
            )
            on(f"[*] flashing bundle from {bundle_path} ...")
            rc = flasher.flash_suicide(port, chip, bundle_path, on, baud=921600)
            on("[done] power-cycle the board" if rc == 0 else f"[x] esptool exit {rc}")
        except Exception as e:
            on(f"[error] {e}")

    def action_close(self):
        self.dismiss()


class MarauderTUI(App):
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #tree { width: 42%; border: round $accent; }
    #rightcol { width: 1fr; }
    #log  { height: 1fr; border: round $accent; }
    #aptable { height: 45%; border: round $accent; }
    #desc { height: 1; color: $text-muted; padding: 0 1; }
    Input { dock: bottom; border: round $accent; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "stop", "Stop scan"),
        ("f", "flash", "Flash fw"),
        ("x", "suicide", "Suicide flash"),
        ("g", "guide", "Guide"),
        ("ctrl+l", "clear", "Clear log"),
        ("c", "focus_input", "Command box"),
    ]

    def __init__(self, controller: MarauderController, logger=None):
        super().__init__()
        self.ctl = controller
        self.parser = MarauderParser()
        self.logger = logger or CaptureLogger()
        self._q: "queue.Queue[str]" = queue.Queue()
        self.ctl.subscribe(self._q.put)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield _set_tip(
                Tree("Marauder", id="tree"),
                "Browse Marauder commands by category. Highlight a command to see "
                "what it does in the help line; Enter sends it (or prefills a "
                "template if it needs arguments). ⚠ marks attack/spam commands.",
            )
            with Vertical(id="rightcol"):
                yield _set_tip(
                    RichLog(id="log", highlight=False, markup=False, wrap=True),
                    "Live serial output from the device. Ctrl+L clears it.",
                )
                yield _set_tip(
                    DataTable(id="aptable"),
                    "Access points parsed from the live scan output: index, SSID, "
                    "channel, RSSI (signal) and BSSID (the AP's MAC address). "
                    "Updates while a scan runs.",
                )
        yield _set_tip(
            Static("Select a command to see what it does · press g for the full Guide", id="desc"),
            "Help line: shows the highlighted command's description and the exact "
            "serial string it sends. Press g for the full Guide.",
        )
        yield _set_tip(
            Input(placeholder="raw command (e.g. scanap) — Enter to send", id="raw"),
            "Type any raw Marauder command and press Enter to send it. Selecting a "
            "command in the tree prefills this box; fill in any <placeholders> first.",
        )
        yield Footer()

    def on_mount(self):
        self.title = "Universal Flasher TUI"
        tree = self.query_one("#tree", Tree)
        tree.root.expand()
        for cat in commands.categories():
            node = tree.root.add(cat, expand=False)
            for c in [x for x in commands.COMMANDS if x.category == cat]:
                label = ("⚠ " if c.danger else "") + c.label
                node.add_leaf(label, data=c.id)

        table = self.query_one("#aptable", DataTable)
        table.add_columns("#", "SSID", "Ch", "RSSI", "BSSID")
        table.zebra_stripes = True

        self.set_interval(0.05, self._drain)
        self.set_interval(0.7, self._refresh_aps)

        try:
            port = self.ctl.connect()
            self.sub_title = f"connected: {port}"
            self._log(f"[connected to {port} @ {self.ctl.baud} baud]")
        except Exception as e:
            self.sub_title = "disconnected"
            self._log(f"[not connected] {e}")

    # --- serial output (drained on the UI thread) ------------------------- #
    def _drain(self):
        try:
            while True:
                line = self._q.get_nowait()
                self._log(line)
                self.parser.feed(line)
                self.logger.write_serial(line)
        except queue.Empty:
            pass

    def _refresh_aps(self):
        if not self.parser.dirty:
            return
        self.parser.dirty = False
        table = self.query_one("#aptable", DataTable)
        table.clear()
        rows = self.parser.ap_rows()
        for a in rows[:200]:
            idx = str(a.index) if a.index >= 0 else ""
            table.add_row(idx, a.ssid, a.channel, a.rssi, a.bssid)
        table.border_title = f"Access Points ({len(rows)})"
        if self.logger.enabled:
            self.logger.write_snapshot(rows, self.parser.station_rows(), {"port": self.ctl.port})

    def _log(self, line: str):
        self.query_one("#log", RichLog).write(line)

    # --- interactions ----------------------------------------------------- #
    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted):
        cmd = commands.get(event.node.data) if event.node.data else None
        if cmd:
            tip = f"{cmd.desc}  ·  sends: {cmd.base}"
            if cmd.danger:
                tip += "  ·  ⚠ attack"
            self.query_one("#desc", Static).update(tip)
        else:
            # A category node: surface a neutral glossary blurb when its name
            # matches a known term, otherwise the standard hint. This is the
            # focus-driven fallback that stands in for per-node tooltips, which
            # Textual's TreeNode does not support.
            term = str(event.node.label).strip().lower()
            blurb = GLOSSARY.get(term)
            self.query_one("#desc", Static).update(
                blurb if blurb else "press g for the full Guide"
            )

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        cmd_id = event.node.data
        if not cmd_id:
            return
        cmd = commands.get(cmd_id)
        if not cmd:
            return
        raw = self.query_one("#raw", Input)
        if cmd.params:
            # prefill a template the user can edit, then Enter to send
            tmpl = cmd.base + " " + " ".join(
                (p.flag + " " if p.flag else "") + f"<{p.name}>" for p in cmd.params
            )
            raw.value = tmpl.strip()
            raw.focus()
        else:
            self._send(cmd.base)

    def on_input_submitted(self, event: Input.Submitted):
        self._send(event.value.strip())
        event.input.value = ""

    def _send(self, line: str):
        if not line or "<" in line:
            if "<" in line:
                self._log("[fill in the <placeholders> before sending]")
            return
        if not self.ctl.connected:
            self._log("[error] not connected")
            return
        self.ctl.send(line)

    # --- actions ---------------------------------------------------------- #
    def action_stop(self):
        if self.ctl.connected:
            self.ctl.stop()

    def action_flash(self):
        self.push_screen(FlashScreen(self.ctl))

    def action_suicide(self):
        self.push_screen(SuicideFlashScreen(self.ctl))

    def action_guide(self):
        self.push_screen(GuideScreen())

    def action_clear(self):
        self.query_one("#log", RichLog).clear()
        self.parser.clear()
        self.query_one("#aptable", DataTable).clear()

    def action_focus_input(self):
        self.query_one("#raw", Input).focus()

    def action_quit(self):
        try:
            self.ctl.disconnect()
        except Exception:
            pass
        self.exit()


def main():
    ap = argparse.ArgumentParser(description="Universal Flasher TUI (terminal app)")
    ap.add_argument("--port", help="Serial port (default: auto-detect)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--mock", action="store_true", help="Run without hardware")
    ap.add_argument("--log", nargs="?", const=True, default=None,
                    help="Log to a dir (default ~/marauder-logs)")
    args = ap.parse_args()

    ctl = MarauderController(port=args.port, baud=args.baud, mock=args.mock)
    logger = CaptureLogger(args.log if isinstance(args.log, str) else None)
    if args.log:
        logger.start()
    MarauderTUI(ctl, logger=logger).run()


if __name__ == "__main__":
    main()
