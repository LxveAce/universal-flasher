"""Flash Firmware window for the desktop GUI — detect chip, fetch firmware, flash."""

import os
import queue
import threading

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from uf_core import flasher
from uf_core.uihelp import Tooltip, GLOSSARY

BG = "#0b0f0a"
PANEL = "#11160f"
FG = "#c8f7c5"
ACCENT = "#39ff14"
DANGER = "#ff4d4d"
MUTED = "#7a8f76"


class FlasherWindow(tk.Toplevel):
    def __init__(self, master, controller, default_port=""):
        super().__init__(master)
        self.ctl = controller
        self.title("Flash Marauder Firmware")
        self.configure(bg=PANEL)
        self.geometry("760x620")

        self.q: "queue.Queue[str]" = queue.Queue()
        self.chip = None
        self.assets = []
        self.tag = ""
        self._label_to_asset = {}
        # Firmware-profile registry (additive): map combobox label -> profile id.
        # Default is "marauder" so the original flow is the out-of-box behaviour.
        self._profiles = flasher.list_profiles()
        self._profile_label_to_id = {label: pid for pid, label in self._profiles}
        self._suicide_row_shown = True   # surow is packed in _build (marauder default)
        self._busy = False
        self._need_refill = False   # set by worker threads; applied on the UI thread in _poll
        self._poll_id = None
        self._closed = False

        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll()
        if not flasher.esptool_available():
            self._log("[!] esptool not found. Install it:  pip install esptool")

        if default_port:
            self.port_var.set(default_port)

    def _on_close(self):
        self._closed = True
        if self._poll_id is not None:
            try:
                self.after_cancel(self._poll_id)
            except Exception:
                pass
        self.destroy()

    # --- layout ----------------------------------------------------------- #
    def _build(self):
        pad = {"padx": 8, "pady": 4}

        # firmware profile selector (additive) — picks WHICH firmware to flash.
        # Defaults to the Marauder profile so the original behaviour is unchanged.
        frow = tk.Frame(self, bg=PANEL); frow.pack(fill="x", **pad)
        tk.Label(frow, text="Firmware:", bg=PANEL, fg=FG).pack(side="left")
        self.profile_var = tk.StringVar()
        profile_labels = [label for _pid, label in self._profiles]
        self.profile_combo = ttk.Combobox(frow, textvariable=self.profile_var, width=34,
                                           state="readonly", values=profile_labels)
        self.profile_combo.pack(side="left", padx=6)
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_change)
        # default to the marauder profile (falls back to the first entry if absent)
        default_label = next((lbl for pid, lbl in self._profiles if pid == "marauder"),
                             profile_labels[0] if profile_labels else "")
        self.profile_var.set(default_label)
        Tooltip(self.profile_combo, "Which firmware to flash. 'ESP32 Marauder' is the default "
                "and keeps the original behaviour (and the suicide-bundle option). Other "
                "profiles flash their stock images byte-for-byte — no extra features are added.")

        row = tk.Frame(self, bg=PANEL); row.pack(fill="x", **pad)
        tk.Label(row, text="Port:", bg=PANEL, fg=FG).pack(side="left")
        self.port_var = tk.StringVar()
        port_ent = ttk.Entry(row, textvariable=self.port_var, width=24)
        port_ent.pack(side="left", padx=6)
        Tooltip(port_ent, "Serial port of the board to flash (e.g. /dev/ttyUSB0 or COM5). "
                "The live console session is dropped automatically so esptool can use it.")
        detect_btn = ttk.Button(row, text="Detect chip", command=self._detect)
        detect_btn.pack(side="left", padx=4)
        Tooltip(detect_btn, "Ask esptool which ESP32 chip is on this port "
                "(esp32, esp32s3, ...). This picks the right firmware variant and offsets.")
        self.chip_lbl = tk.Label(row, text="chip: ?", bg=PANEL, fg=MUTED)
        self.chip_lbl.pack(side="left", padx=8)
        Tooltip(self.chip_lbl, "The detected chip family. Shows '?' until you detect "
                "(or flash, which auto-detects first).")

        # mode
        mrow = tk.Frame(self, bg=PANEL); mrow.pack(fill="x", **pad)
        tk.Label(mrow, text="Mode:", bg=PANEL, fg=FG).pack(side="left")
        self.mode = tk.StringVar(value="app")
        mode_app = ttk.Radiobutton(mrow, text="Update app only (existing board)", value="app",
                                   variable=self.mode)
        mode_app.pack(side="left", padx=6)
        Tooltip(mode_app, GLOSSARY["app-only flash"])
        mode_full = ttk.Radiobutton(mrow, text="Full flash (blank board)", value="full",
                                    variable=self.mode)
        mode_full.pack(side="left", padx=6)
        Tooltip(mode_full, GLOSSARY["full flash"])

        # source
        srow = tk.Frame(self, bg=PANEL); srow.pack(fill="x", **pad)
        tk.Label(srow, text="Firmware:", bg=PANEL, fg=FG).pack(side="left")
        self.source = tk.StringVar(value="download")
        src_dl = ttk.Radiobutton(srow, text="Download latest release", value="download",
                                 variable=self.source)
        src_dl.pack(side="left", padx=6)
        Tooltip(src_dl, "Pull the latest official Marauder release from GitHub and "
                "choose a board variant below.")
        src_local = ttk.Radiobutton(srow, text="Local .bin", value="local",
                                     variable=self.source)
        src_local.pack(side="left", padx=6)
        Tooltip(src_local, "Flash an application .bin you already have on disk "
                "(use the Browse button below).")

        # download row
        drow = tk.Frame(self, bg=PANEL); drow.pack(fill="x", **pad)
        load_btn = ttk.Button(drow, text="Load release list", command=self._load_release)
        load_btn.pack(side="left")
        Tooltip(load_btn, "Fetch the latest release's firmware list from GitHub and "
                "populate the variant menu.")
        self.showall = tk.BooleanVar(value=False)
        showall_cb = ttk.Checkbutton(drow, text="show all chips", variable=self.showall,
                                     command=self._refill_variants)
        showall_cb.pack(side="left", padx=6)
        Tooltip(showall_cb, "By default only variants matching the detected chip are listed. "
                "Tick this to show every variant in the release.")
        self.variant_var = tk.StringVar()
        self.variant_combo = ttk.Combobox(drow, textvariable=self.variant_var, width=46, state="readonly")
        self.variant_combo.pack(side="left", padx=6)
        Tooltip(self.variant_combo, "The specific board/firmware build to download and flash. "
                "Match it to your exact board (display, chip, revision).")

        # local row
        lrow = tk.Frame(self, bg=PANEL); lrow.pack(fill="x", **pad)
        self.local_var = tk.StringVar()
        local_ent = ttk.Entry(lrow, textvariable=self.local_var, width=52)
        local_ent.pack(side="left", padx=(0, 6))
        Tooltip(local_ent, "Path to a local application .bin to flash when 'Local .bin' "
                "is selected.")
        browse_btn = ttk.Button(lrow, text="Browse .bin", command=self._browse)
        browse_btn.pack(side="left")
        Tooltip(browse_btn, "Pick an application .bin from disk; selecting one also "
                "switches the source to 'Local .bin'.")

        # --- opt-in: Suicide build (provision + flash anti-forensic bundle) ---
        self.suicide_row = tk.Frame(self, bg=PANEL); self.suicide_row.pack(fill="x", **pad)
        self.suicide = tk.BooleanVar(value=False)
        suicide_cb = ttk.Checkbutton(self.suicide_row, text="Suicide build (provision + flash)",
                                     variable=self.suicide, command=self._toggle_suicide)
        suicide_cb.pack(side="left")
        Tooltip(suicide_cb, "Owner-only hardened build that can self-wipe. "
                "Enter a password and config, or point at an existing bundle.")

        # suicide sub-panel — hidden until checkbox ticked
        self.suicide_panel = tk.Frame(self, bg=PANEL)

        # mode selector
        self.suicide_mode = tk.StringVar(value="new")
        smrow = tk.Frame(self.suicide_panel, bg=PANEL)
        smrow.pack(fill="x", padx=4, pady=2)
        ttk.Radiobutton(smrow, text="Provision new", variable=self.suicide_mode,
                         value="new", command=self._toggle_suicide_mode).pack(side="left")
        ttk.Radiobutton(smrow, text="Flash existing bundle", variable=self.suicide_mode,
                         value="existing", command=self._toggle_suicide_mode).pack(side="left", padx=8)

        # provision-new sub-panel
        self.provision_frame = tk.Frame(self.suicide_panel, bg=PANEL)
        self.provision_frame.pack(fill="x", padx=4)
        prow1 = tk.Frame(self.provision_frame, bg=PANEL); prow1.pack(fill="x", pady=1)
        tk.Label(prow1, text="Password:", bg=PANEL, fg=FG, width=12, anchor="e").pack(side="left")
        self.s_pw_var = tk.StringVar()
        pw_ent = ttk.Entry(prow1, textvariable=self.s_pw_var, show="*", width=30)
        pw_ent.pack(side="left", padx=4)
        Tooltip(pw_ent, "Boot password — hashed locally, never stored or logged.")
        prow2 = tk.Frame(self.provision_frame, bg=PANEL); prow2.pack(fill="x", pady=1)
        tk.Label(prow2, text="Confirm:", bg=PANEL, fg=FG, width=12, anchor="e").pack(side="left")
        self.s_pw2_var = tk.StringVar()
        pw2_ent = ttk.Entry(prow2, textvariable=self.s_pw2_var, show="*", width=30)
        pw2_ent.pack(side="left", padx=4)
        prow3 = tk.Frame(self.provision_frame, bg=PANEL); prow3.pack(fill="x", pady=1)
        tk.Label(prow3, text="Variant:", bg=PANEL, fg=FG, width=12, anchor="e").pack(side="left")
        self.s_variant_var = tk.StringVar(value="fork")
        ttk.Combobox(prow3, textvariable=self.s_variant_var, values=["fork", "guardian"],
                      state="readonly", width=12).pack(side="left", padx=4)
        tk.Label(prow3, text="Arm GPIO:", bg=PANEL, fg=FG).pack(side="left", padx=(12, 0))
        self.s_arm_pin_var = tk.IntVar(value=27)
        ttk.Spinbox(prow3, textvariable=self.s_arm_pin_var, from_=0, to=48, width=4).pack(side="left", padx=4)
        tk.Label(prow3, text="Max att:", bg=PANEL, fg=FG).pack(side="left", padx=(12, 0))
        self.s_max_att_var = tk.IntVar(value=2)
        ttk.Spinbox(prow3, textvariable=self.s_max_att_var, from_=1, to=10, width=4).pack(side="left", padx=4)
        prow4 = tk.Frame(self.provision_frame, bg=PANEL); prow4.pack(fill="x", pady=1)
        self.s_deadman_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(prow4, text="Dead-man switch", variable=self.s_deadman_var).pack(side="left")
        self.s_armed_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(prow4, text="ARM now (default OFF)", variable=self.s_armed_var).pack(side="left", padx=12)
        prow5 = tk.Frame(self.provision_frame, bg=PANEL); prow5.pack(fill="x", pady=1)
        tk.Label(prow5, text="Build dir:", bg=PANEL, fg=FG, width=12, anchor="e").pack(side="left")
        self.s_build_dir_var = tk.StringVar()
        ttk.Entry(prow5, textvariable=self.s_build_dir_var, width=30).pack(side="left", padx=4)
        ttk.Button(prow5, text="Browse", command=lambda: self._browse_dir(self.s_build_dir_var)).pack(side="left")

        # existing-bundle sub-panel
        self.existing_frame = tk.Frame(self.suicide_panel, bg=PANEL)
        tk.Label(self.existing_frame, text="Bundle:", bg=PANEL, fg=FG).pack(side="left")
        self.bundle_var = tk.StringVar()
        ttk.Entry(self.existing_frame, textvariable=self.bundle_var, width=48).pack(side="left", padx=6)
        ttk.Button(self.existing_frame, text="Browse folder",
                   command=self._browse_bundle).pack(side="left")

        tk.Label(self.suicide_panel, text="⚠ SAFETY: test in SAFE_MODE first. Read suicide/docs/SAFETY.md.",
                 bg=PANEL, fg=DANGER, wraplength=500, justify="left").pack(fill="x", padx=4, pady=2)

        # baud + actions
        arow = tk.Frame(self, bg=PANEL); arow.pack(fill="x", **pad)
        tk.Label(arow, text="Baud:", bg=PANEL, fg=FG).pack(side="left")
        self.baud = tk.StringVar(value="921600")
        baud_combo = ttk.Combobox(arow, textvariable=self.baud, width=10, state="readonly",
                                  values=["115200", "460800", "921600"])
        baud_combo.pack(side="left", padx=6)
        Tooltip(baud_combo, GLOSSARY["baud"])
        self.flash_btn = ttk.Button(arow, text="⚡ FLASH", command=self._flash)
        self.flash_btn.pack(side="left", padx=10)
        Tooltip(self.flash_btn, "Flash the selected firmware to the board. Confirms first, "
                "and won't run while another flash/erase is in progress.")
        erase_btn = ttk.Button(arow, text="Erase flash", command=self._erase)
        erase_btn.pack(side="left")
        Tooltip(erase_btn, "Wipe the entire flash chip. The board has no firmware afterwards — "
                "you'll need a full flash to restore it.")

        tk.Label(self, text="Tip: classic ESP32 Gold boards → pick a non-S3 variant "
                 "(e.g. 'Generic ESP32 / original v4'). S3 → MultiBoard S3.",
                 bg=PANEL, fg=MUTED, wraplength=720, justify="left").pack(fill="x", padx=8)

        self.console = tk.Text(self, bg="#05080a", fg=ACCENT, wrap="word",
                               state="disabled", font=("monospace", 9))
        self.console.pack(fill="both", expand=True, padx=8, pady=6)

        # apply suicide-row visibility for the initial profile (marauder -> visible)
        self._apply_profile_suicide_visibility()

    # --- helpers ---------------------------------------------------------- #
    def _log(self, s):
        self.q.put(s)

    def _poll(self):
        if self._closed or not self.winfo_exists():
            return
        try:
            while True:
                line = self.q.get_nowait()
                self.console.config(state="normal")
                self.console.insert("end", line + "\n")
                line_count = int(self.console.index("end-1c").split(".")[0])
                if line_count > 10000:
                    self.console.delete("1.0", f"{line_count - 10000}.0")
                self.console.see("end")
                self.console.config(state="disabled")
        except queue.Empty:
            pass
        # all widget updates happen here on the UI thread (workers only set state/flags)
        self.flash_btn.config(state="disabled" if self._busy else "normal")
        self.chip_lbl.config(text=f"chip: {self.chip or '?'}",
                             fg=ACCENT if self.chip else MUTED)
        if self._need_refill:
            self._need_refill = False
            self._refill_variants()
        self._poll_id = self.after(40, self._poll)

    def _free_port(self):
        """esptool needs exclusive access — drop the live serial connection."""
        if self.ctl and self.ctl.connected:
            self._log("[i] disconnecting live serial session so esptool can use the port")
            self.ctl.disconnect()

    def _worker(self, fn):
        if self._busy:
            messagebox.showinfo("Busy", "A flash/erase is already running.")
            return
        self._busy = True
        self.flash_btn.config(state="disabled")

        def run():
            try:
                fn()
            except Exception as e:
                self._log(f"[error] {e}")
            finally:
                self._busy = False     # _poll re-enables the button on the UI thread

        threading.Thread(target=run, daemon=True).start()

    # --- firmware profile ------------------------------------------------- #
    def _current_profile(self):
        """Resolve the selected combobox label to its FirmwareProfile (defaults to
        marauder if the selection is somehow unknown)."""
        pid = self._profile_label_to_id.get(self.profile_var.get(), "marauder")
        return flasher.get_profile(pid)

    def _apply_profile_suicide_visibility(self):
        """Show the suicide-bundle row only for profiles that support it (marauder)."""
        supports = self._current_profile().supports_suicide
        if supports:
            if not self._suicide_row_shown:
                # restore it to its original slot: just above the baud/actions row
                self.suicide_row.pack(fill="x", padx=8, pady=4, before=self.flash_btn.master)
                self._suicide_row_shown = True
        else:
            # untick + hide the bundle sub-row so a non-suicide profile can't flash a bundle
            if self.suicide.get():
                self.suicide.set(False)
                self._toggle_suicide()
            if self._suicide_row_shown:
                self.suicide_row.pack_forget()
                self._suicide_row_shown = False

    def _on_profile_change(self, _evt=None):
        """Switching firmware invalidates the previously-loaded release/variant list
        (assets belong to one profile). Clear it and refresh suicide visibility."""
        self.assets = []
        self.tag = ""
        self._label_to_asset = {}
        self.variant_combo["values"] = []
        self.variant_var.set("")
        self._apply_profile_suicide_visibility()
        self._log(f"[i] firmware profile: {self._current_profile().label} "
                  "(click 'Load release list' to fetch its variants)")

    # --- actions ---------------------------------------------------------- #
    def _detect(self):
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Port", "Enter the serial port first."); return
        self._free_port()

        def job():
            self._log("[*] detecting chip...")
            self.chip = flasher.detect_chip(port, self._log)
            self._need_refill = True
        self._worker(job)

    def _load_release(self):
        profile = self._current_profile()
        def job():
            self._log(f"[*] fetching latest release ({profile.label})...")
            self.tag, self.assets = profile.latest_release()
            self._log(f"[i] {self.tag}: {len(self.assets)} firmware variants")
            self._need_refill = True
        self._worker(job)

    def _refill_variants(self):
        if not self.assets:
            return
        profile = self._current_profile()
        items = self.assets if (self.showall.get() or not self.chip) \
            else profile.variants_for_chip(self.assets, self.chip)
        self._label_to_asset = {f"{a['label']}  [{a['name']}]": a for a in items}
        labels = list(self._label_to_asset)
        self.variant_combo["values"] = labels
        if labels:
            default = profile.default_variant(items, self.chip) if self.chip else None
            pick = next((l for l, a in self._label_to_asset.items() if default and a["name"] == default["name"]), labels[0])
            self.variant_var.set(pick)

    def _browse(self):
        path = filedialog.askopenfilename(title="Select firmware .bin",
                                          filetypes=[("Firmware", "*.bin"), ("All", "*.*")])
        if path:
            self.local_var.set(path)
            self.source.set("local")

    def _toggle_suicide(self):
        if self.suicide.get():
            self.suicide_panel.pack(fill="x", padx=8, pady=4, before=self.flash_btn.master)
            self._toggle_suicide_mode()
        else:
            self.suicide_panel.pack_forget()

    def _toggle_suicide_mode(self):
        if self.suicide_mode.get() == "new":
            self.provision_frame.pack(fill="x", padx=4)
            self.existing_frame.pack_forget()
        else:
            self.provision_frame.pack_forget()
            self.existing_frame.pack(fill="x", padx=4, pady=2)

    def _browse_dir(self, var):
        path = filedialog.askdirectory(title="Select folder")
        if path:
            var.set(path)

    def _browse_bundle(self):
        path = filedialog.askdirectory(title="Select provisioned bundle folder")
        if path:
            self.bundle_var.set(path)

    def _resolve_chip(self, port):
        if self.chip:
            return self.chip
        self._log("[*] chip unknown — detecting first...")
        self.chip = flasher.detect_chip(port, self._log)
        self._need_refill = True       # keep the variant list/chip label consistent
        return self.chip

    def _flash(self):
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Port", "Enter the serial port first."); return
        baud = int(self.baud.get())

        # Opt-in suicide path: flash a pre-provisioned bundle instead of normal firmware.
        if self.suicide.get():
            self._flash_suicide(port, baud); return

        mode = self.mode.get()
        source = self.source.get()

        if source == "download" and not self._label_to_asset:
            messagebox.showinfo("Firmware", "Click 'Load release list' and pick a variant."); return
        if source == "local" and not self.local_var.get().strip():
            messagebox.showinfo("Firmware", "Browse to a local .bin first."); return

        if not messagebox.askyesno("Confirm flash",
                                   f"Flash {mode} via {port} @ {baud}?\nDo not unplug during flashing."):
            return
        # capture all widget values on the UI thread BEFORE starting the worker
        profile = self._current_profile()
        asset = self._label_to_asset.get(self.variant_var.get()) if source == "download" else None
        local = self.local_var.get().strip()
        self._free_port()

        def job():
            chip = self._resolve_chip(port)
            if not chip:
                self._log("[error] could not detect chip; aborting"); return
            cache = flasher.cache_dir()

            # an asset may pin its own flash offset (e.g. merged image @0x0, app-only
            # @0x10000); otherwise fall back to the profile's per-chip app_offset.
            app_offset = asset.get("offset") if (source == "download" and asset) else None

            if source == "download":
                if not asset:
                    self._log("[error] no variant selected"); return
                if asset["chip"] != chip:
                    self._log(f"[!] WARNING: variant is for {asset['chip']} but chip is {chip}")
                app = flasher.download_to(asset["url"], cache, asset["name"], self._log)
            else:
                app = local

            support = None
            if mode == "full":
                self._log("[*] fetching bootloader/partitions/boot_app0...")
                support = profile.support_files(chip, cache, self._log)
                if support is None:
                    # merged-single-bin profiles (e.g. Bruce) carry the boot chain inside
                    # the image, so a full flash needs nothing extra — write the image alone.
                    self._log("[i] this firmware is a merged single image; no separate "
                              "bootloader/partitions needed")

            self._log(f"[*] flashing ({mode}) {os.path.basename(app)} to {chip} "
                      f"[{profile.label}]...")
            rc = profile.flash_assets(port, chip, app, self._log, mode=mode, baud=baud,
                                      support=support, app_offset=app_offset)
            self._log("[✓] done — power-cycle the board" if rc == 0 else f"[x] esptool exit {rc}")
        self._worker(job)

    def _flash_suicide(self, port, baud):
        """Provision (if new) and flash a suicide bundle."""
        if self.suicide_mode.get() == "existing":
            bundle_dir = self.bundle_var.get().strip()
            if not bundle_dir:
                messagebox.showinfo("Bundle", "Browse to a provisioned bundle folder first."); return
            try:
                manifest = flasher.read_bundle_manifest(bundle_dir)
            except (FileNotFoundError, ValueError) as e:
                messagebox.showerror("Bundle", f"Not a valid bundle:\n{e}"); return
            man_chip = manifest.get("chip")
            if not messagebox.askyesno(
                    "Confirm SUICIDE-build flash",
                    f"Flash provisioned bundle via {port} @ {baud}?\n\n"
                    f"Folder: {bundle_dir}\n"
                    f"Bundle chip: {man_chip or 'unspecified'}\n\n"
                    "This build can self-wipe. Test in SAFE_MODE first.\n"
                    "Do not unplug during flashing."):
                return
            chip = man_chip or self.chip
            self._free_port()

            def job():
                use_chip = chip or self._resolve_chip(port)
                if not use_chip:
                    self._log("[error] chip unknown; detect first"); return
                rc = flasher.flash_suicide(port, use_chip, bundle_dir, self._log, baud=baud)
                self._log("[done] power-cycle the board" if rc == 0 else f"[x] exit {rc}")
            self._worker(job)
            return

        # --- provision new bundle ---
        pw = self.s_pw_var.get()
        pw2 = self.s_pw2_var.get()
        if not pw:
            messagebox.showwarning("Password", "Enter a boot password."); return
        if pw != pw2:
            messagebox.showwarning("Password", "Passwords don't match."); return
        variant = self.s_variant_var.get()
        armed = int(self.s_armed_var.get())
        build_dir = self.s_build_dir_var.get().strip() or None

        msg = (f"Provision + flash suicide build via {port}?\n"
               f"variant={variant}  armed={armed}  max_att={self.s_max_att_var.get()}\n"
               "Password is hashed locally, never stored.\n"
               "Do not unplug during flashing.")
        if armed:
            msg += "\n\nWARNING: ARMED=1 — board WILL self-destruct on trigger!"
        if not messagebox.askyesno("Confirm suicide-build", msg):
            return

        config = dict(
            password=pw,
            variant=variant,
            arm_pin=self.s_arm_pin_var.get(),
            arm_level=1,
            arm_pull=2,
            deadman=int(self.s_deadman_var.get()),
            armed=armed,
            max_att=self.s_max_att_var.get(),
            build_dir=build_dir,
        )
        self.s_pw_var.set("")
        self.s_pw2_var.set("")
        self._free_port()

        def job():
            use_chip = self._resolve_chip(port)
            if not use_chip:
                self._log("[error] chip unknown"); return
            try:
                import suicide
                bundle_path = suicide.build_bundle(chip=use_chip, on_line=self._log, **config)
            except Exception as e:
                self._log(f"[error] provisioning failed: {e}"); return
            rc = flasher.flash_suicide(port, use_chip, bundle_path, self._log, baud=baud)
            self._log("[done] power-cycle the board" if rc == 0 else f"[x] exit {rc}")
        self._worker(job)

    def _erase(self):
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Port", "Enter the serial port first."); return
        if not messagebox.askyesno("Erase", "Erase the entire flash? This wipes the firmware."):
            return
        self._free_port()

        def job():
            chip = self._resolve_chip(port) or "esp32"
            flasher.erase(port, chip, self._log)
        self._worker(job)
