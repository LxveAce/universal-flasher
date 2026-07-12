#!/usr/bin/env python3
"""
Universal Flasher GUI — a native Tkinter desktop application for Kali Linux.

A real window (no browser, no web server): categorized buttons for every Marauder
serial command, parameter dialogs, a live console, a raw command box, and a big STOP.

Run:   python3 gui/app.py            (auto-detects the port)
       python3 gui/app.py --port /dev/ttyUSB0
       python3 gui/app.py --mock     (no hardware, for trying the UI)

Needs Tkinter:  sudo apt install -y python3-tk
"""

import argparse
import os
import queue
import sys

# Make `uf_core` importable whether launched as a script or a module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import ttk, messagebox

from uf_core import MarauderController, CaptureLogger, commands
from uf_core.uihelp import Tooltip

# Dark theme colors
BG = "#0b0f0a"
PANEL = "#11160f"
FG = "#c8f7c5"
ACCENT = "#39ff14"
DANGER = "#ff4d4d"
MUTED = "#7a8f76"


class _Tooltip:
    """Tiny hover tooltip for a Tk widget."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _evt):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, bg=PANEL, fg=FG, justify="left",
                 relief="solid", borderwidth=1, wraplength=360, padx=6, pady=3).pack()

    def _hide(self, _evt):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class ParamDialog(tk.Toplevel):
    """Modal form to fill a command's parameters; returns values via .result."""

    def __init__(self, master, cmd):
        super().__init__(master)
        self.title(cmd.label)
        self.configure(bg=PANEL)
        self.result = None
        self._cmd = cmd
        self._vars = {}

        tk.Label(self, text=cmd.label, bg=PANEL, fg=ACCENT,
                 font=("TkDefaultFont", 11, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 2))
        if cmd.desc:
            tk.Label(self, text=cmd.desc, bg=PANEL, fg=MUTED, wraplength=360,
                     justify="left").grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 8))

        r = 2
        for p in cmd.params:
            label = p.name + (" *" if p.required else "")
            tk.Label(self, text=label, bg=PANEL, fg=FG).grid(row=r, column=0, sticky="e", padx=(10, 6), pady=4)
            ptip = (p.help or (f"e.g. {p.placeholder}" if p.placeholder else "")) \
                + ("\n(required)" if p.required else "")
            if p.kind == "bool":
                var = tk.BooleanVar(value=False)
                w = ttk.Checkbutton(self, variable=var)
                w.grid(row=r, column=1, sticky="w", padx=(0, 10))
            elif p.kind == "select":
                var = tk.StringVar(value=p.choices[0] if p.choices else "")
                w = ttk.Combobox(self, textvariable=var, values=p.choices, state="readonly",
                                 width=24)
                w.grid(row=r, column=1, sticky="w", padx=(0, 10))
            else:
                var = tk.StringVar()
                w = ttk.Entry(self, textvariable=var, width=26)
                w.grid(row=r, column=1, sticky="w", padx=(0, 10))
                if p.placeholder:
                    w.insert(0, "")
            Tooltip(w, ptip.strip())
            self._vars[p.name] = var
            if p.help or p.placeholder:
                hint = p.help or f"e.g. {p.placeholder}"
                tk.Label(self, text=hint, bg=PANEL, fg=MUTED,
                         font=("TkDefaultFont", 8)).grid(row=r + 1, column=1, sticky="w", padx=(0, 10))
                r += 1
            r += 1

        btns = tk.Frame(self, bg=PANEL)
        btns.grid(row=r, column=0, columnspan=2, pady=10)
        runtext = "RUN ⚠" if cmd.danger else "Run"
        run_btn = ttk.Button(btns, text=runtext, command=self._ok)
        run_btn.pack(side="left", padx=6)
        Tooltip(run_btn, ("Build and send this command with the values above.\n"
                          "(attack/spam — authorized targets only)" if cmd.danger
                          else "Build and send this command with the values above."))
        cancel_btn = ttk.Button(btns, text="Cancel", command=self.destroy)
        cancel_btn.pack(side="left", padx=6)
        Tooltip(cancel_btn, "Close this dialog without sending anything.")

        self.transient(master)
        self.grab_set()
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())

    def _ok(self):
        values = {}
        for p in self._cmd.params:
            v = self._vars[p.name].get()
            if p.required and (v is None or str(v).strip() == ""):
                messagebox.showwarning("Missing value", f"'{p.name}' is required.", parent=self)
                return
            if p.kind == "int" and str(v).strip():
                try:
                    v = int(str(v).strip())     # normalize + validate
                except ValueError:
                    messagebox.showwarning("Invalid number", f"'{p.name}' must be a whole number.", parent=self)
                    return
            values[p.name] = v
        self.result = values
        self.destroy()


class MarauderGUI(tk.Tk):
    def __init__(self, controller: MarauderController, logger=None):
        super().__init__()
        self.ctl = controller
        self.logger = logger or CaptureLogger()
        self.q: "queue.Queue[str]" = queue.Queue()
        self.ctl.subscribe(self.q.put)
        self._poll_id = None
        self._closing = False

        self.title("Universal Flasher GUI")
        self.geometry("1100x720")
        self.configure(bg=BG)
        self._build_style()
        self._build_topbar()
        self._build_body()
        self._poll_queue()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # --- styling ---------------------------------------------------------- #
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TButton", padding=4)
        style.configure("Danger.TButton", foreground=DANGER)
        style.configure("Stop.TButton", foreground="#ffffff", background=DANGER, padding=8)

    # --- top bar ---------------------------------------------------------- #
    def _build_topbar(self):
        bar = tk.Frame(self, bg=PANEL)
        bar.pack(side="top", fill="x")

        tk.Label(bar, text="Port:", bg=PANEL, fg=FG).pack(side="left", padx=(10, 4), pady=8)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(bar, textvariable=self.port_var, width=28, state="normal")
        self.port_combo.pack(side="left", pady=8)
        Tooltip(self.port_combo, "Serial port the Marauder board is on "
                "(e.g. /dev/ttyUSB0 or COM5). Pick one or type it; ↻ refreshes the list.")
        refresh_btn = ttk.Button(bar, text="↻", width=3, command=self._refresh_ports)
        refresh_btn.pack(side="left", padx=4)
        Tooltip(refresh_btn, "Re-scan for connected serial ports.")
        self.connect_btn = ttk.Button(bar, text="Connect", command=self._toggle_connect)
        self.connect_btn.pack(side="left", padx=6)
        Tooltip(self.connect_btn, "Open (or close) the live serial session to the selected "
                "port so you can send commands and watch the console.")

        self.status = tk.Label(bar, text="disconnected", bg=PANEL, fg=DANGER)
        self.status.pack(side="left", padx=10)

        stop_btn = ttk.Button(bar, text="STOP", style="Stop.TButton", command=self._stop)
        stop_btn.pack(side="right", padx=10, pady=6)
        Tooltip(stop_btn, "Send the Marauder 'stop' command to halt any running "
                "scan/attack immediately.")
        flash_btn = ttk.Button(bar, text="⚡ Flash Firmware", command=self._open_flasher)
        flash_btn.pack(side="right", padx=4, pady=6)
        Tooltip(flash_btn, "Open the firmware flasher: detect the chip, download or pick "
                "a .bin, and flash the board (also hosts the opt-in suicide-bundle path).")
        self._refresh_ports()

    def _open_flasher(self):
        from gui.flasher_window import FlasherWindow
        FlasherWindow(self, self.ctl, default_port=self.port_var.get().strip())

    # --- body: command panel + console ----------------------------------- #
    def _build_body(self):
        paned = tk.PanedWindow(self, orient="horizontal", bg=BG, sashwidth=4)
        paned.pack(fill="both", expand=True)

        # Left: scrollable command panel
        left = tk.Frame(paned, bg=BG, width=420)
        canvas = tk.Canvas(left, bg=BG, highlightthickness=0, width=420)
        scroll = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        # mouse wheel
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        self._build_command_buttons(inner)
        paned.add(left)

        # Right: console + raw input
        right = tk.Frame(paned, bg=BG)
        self.console = tk.Text(right, bg="#05080a", fg=ACCENT, insertbackground=ACCENT,
                               wrap="word", state="disabled", font=("monospace", 10))
        self.console.pack(side="top", fill="both", expand=True, padx=(6, 0))
        self.console.tag_configure("tx", foreground="#8fd0ff")
        self.console.tag_configure("sys", foreground=MUTED)

        rawbar = tk.Frame(right, bg=BG)
        rawbar.pack(side="bottom", fill="x", padx=(6, 0), pady=4)
        self.raw_var = tk.StringVar()
        raw = ttk.Entry(rawbar, textvariable=self.raw_var)
        raw.pack(side="left", fill="x", expand=True)
        raw.bind("<Return>", lambda e: self._send_raw())
        Tooltip(raw, "Type any raw Marauder serial command and press Enter (or Send) "
                "to transmit it verbatim.")
        send_btn = ttk.Button(rawbar, text="Send", command=self._send_raw)
        send_btn.pack(side="left", padx=4)
        Tooltip(send_btn, "Send the typed raw command to the board.")
        clear_btn = ttk.Button(rawbar, text="Clear", command=self._clear_console)
        clear_btn.pack(side="left")
        Tooltip(clear_btn, "Clear the console output (does not affect the board or any log file).")
        paned.add(right)

    def _build_command_buttons(self, parent):
        for cat in commands.categories():
            lf = tk.LabelFrame(parent, text=cat, bg=BG, fg=ACCENT, bd=1, relief="groove",
                               labelanchor="nw", padx=6, pady=4)
            lf.pack(fill="x", padx=8, pady=5)
            col = 0
            row = 0
            for c in [x for x in commands.COMMANDS if x.category == cat]:
                btn = ttk.Button(lf, text=c.label, width=22,
                                 style="Danger.TButton" if c.danger else "TButton",
                                 command=lambda cmd=c: self._run_command(cmd))
                tip = c.desc + ("\n(attack — authorized only)" if c.danger else "") + f"\nsends: {c.base}"
                Tooltip(btn, tip)
                btn.grid(row=row, column=col, padx=3, pady=3, sticky="w")
                col += 1
                if col >= 2:
                    col = 0
                    row += 1

    # --- actions ---------------------------------------------------------- #
    def _run_command(self, cmd):
        if cmd.danger:
            if not messagebox.askyesno("Confirm", f"Run attack/spam command?\n\n{cmd.base}\n\n"
                                       "Only against systems you are authorized to test."):
                return
        if cmd.params:
            dlg = ParamDialog(self, cmd)
            self.wait_window(dlg)
            if dlg.result is None:
                return
            line = commands.build(cmd, dlg.result)
        else:
            line = cmd.base
        self._guarded_send(line)

    def _send_raw(self):
        line = self.raw_var.get().strip()
        if line:
            self._guarded_send(line)
            self.raw_var.set("")

    def _guarded_send(self, line):
        if not self.ctl.connected:
            self._append("[error] not connected — click Connect first", "sys")
            return
        try:
            self.ctl.send(line)
        except Exception as e:
            self._append(f"[error] {e}", "sys")

    def _stop(self):
        if self.ctl.connected:
            self.ctl.stop()

    # --- connection ------------------------------------------------------- #
    def _refresh_ports(self):
        ports = [d for d, _ in MarauderController.list_ports()]
        self.port_combo["values"] = ports
        if ports and not self.port_var.get():
            self.port_var.set(ports[0])

    def _toggle_connect(self):
        if self.ctl.connected:
            self.ctl.disconnect()
            self.status.config(text="disconnected", fg=DANGER)
            self.connect_btn.config(text="Connect")
            return
        chosen = self.port_var.get().strip()
        self.ctl.port = chosen or None
        try:
            port = self.ctl.connect()
            self.status.config(text=f"connected: {port}", fg=ACCENT)
            self.connect_btn.config(text="Disconnect")
            self._append(f"[connected to {port} @ {self.ctl.baud} baud]", "sys")
        except Exception as e:
            messagebox.showerror("Connection failed", str(e))
            self._append(f"[error] {e}", "sys")

    def _sync_connection_ui(self):
        """Keep the Connect button + status honest when the session is dropped from OUTSIDE
        _toggle_connect (the flasher calls ctl.disconnect() to free the port for esptool). Without
        this the window shows 'connected'/'Disconnect' on a disconnected controller and the button's
        action then inverts (labelled Disconnect but actually connects)."""
        connected = self.ctl.connected
        if connected == getattr(self, "_last_connected", None):
            return
        self._last_connected = connected
        if connected:
            self.status.config(text=f"connected: {self.ctl.port}", fg=ACCENT)
            self.connect_btn.config(text="Disconnect")
        else:
            self.status.config(text="disconnected", fg=DANGER)
            self.connect_btn.config(text="Connect")

    # --- console ---------------------------------------------------------- #
    def _poll_queue(self):
        if self._closing:
            return
        try:
            while True:
                line = self.q.get_nowait()
                tag = "tx" if line.startswith(">>") else ("sys" if line.startswith("[") else None)
                self._append(line, tag)
                self.logger.write_serial(line)
        except queue.Empty:
            pass
        self._sync_connection_ui()
        self._poll_id = self.after(40, self._poll_queue)

    def _append(self, line, tag=None):
        try:
            self.console.config(state="normal")
            if tag:
                self.console.insert("end", line + "\n", tag)
            else:
                self.console.insert("end", line + "\n")
            line_count = int(self.console.index("end-1c").split(".")[0])
            if line_count > 10000:
                self.console.delete("1.0", f"{line_count - 10000}.0")
            self.console.see("end")
            self.console.config(state="disabled")
        except tk.TclError:
            pass   # window torn down mid-update

    def _clear_console(self):
        self.console.config(state="normal")
        self.console.delete("1.0", "end")
        self.console.config(state="disabled")

    def _on_close(self):
        self._closing = True
        if self._poll_id is not None:
            try:
                self.after_cancel(self._poll_id)
            except Exception:
                pass
        try:
            self.logger.stop()
            self.ctl.disconnect()
        except Exception:
            pass
        self.destroy()


def main():
    ap = argparse.ArgumentParser(description="Universal Flasher GUI (Tkinter desktop app)")
    ap.add_argument("--port", help="Serial port (e.g. /dev/ttyUSB0). Default: auto-detect")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--mock", action="store_true", help="Run without hardware")
    ap.add_argument("--no-autoconnect", action="store_true", help="Don't connect on launch")
    ap.add_argument("--log", nargs="?", const=True, default=None,
                    help="Log to a dir (default ~/marauder-logs)")
    args = ap.parse_args()

    ctl = MarauderController(port=args.port, baud=args.baud, mock=args.mock)
    logger = CaptureLogger(args.log if isinstance(args.log, str) else None)
    if args.log:
        logger.start()
    app = MarauderGUI(ctl, logger=logger)
    if not args.no_autoconnect:
        try:
            port = ctl.connect()
            app.status.config(text=f"connected: {port}", fg=ACCENT)
            app.connect_btn.config(text="Disconnect")
            app.port_var.set(port)
            app._append(f"[connected to {port} @ {ctl.baud} baud]", "sys")
        except Exception as e:
            app._append(f"[not connected] {e}", "sys")
    app.mainloop()


if __name__ == "__main__":
    main()
