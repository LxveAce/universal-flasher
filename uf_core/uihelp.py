"""
UI helpers shared across the desktop apps — dependency-free (stdlib + tkinter only).

Two things live here so every front end (Tkinter GUI, flasher window, the opt-in
suicide-bundle panel) can reuse one copy instead of redefining its own:

  * Tooltip  — a hover popup, since Tk has no native tooltip widget.
  * GLOSSARY — short, neutral, plain-language explanations of the recurring terms
               that show up in labels and buttons, so the UI can hang an
               explanatory tooltip off a term without re-typing the copy.

Nothing here touches hardware, the network, or the flasher; it is pure presentation.
Importing this module does not require a running Tk root — the Toplevel for a
tooltip is only created on first hover.
"""

import tkinter as tk

__all__ = ["Tooltip", "GLOSSARY"]


class Tooltip:
    """Attach a hover popup to any Tkinter widget.

    Usage:
        Tooltip(my_button, "What this button does.")

    Behaviour:
      * Appears a short delay after the pointer enters the widget (so it doesn't
        flicker when you sweep the mouse across the UI).
      * Hides on leave, on click, and when the widget itself is destroyed.
      * A falsy/empty ``text`` makes the tooltip a no-op (handy when copy is
        looked up from GLOSSARY and the key might be missing).
      * Written to survive the widget being torn down mid-hover (closing a
        dialog while a tip is queued) without raising TclError.

    Colours default to None, in which case Tk's own theme is used; pass ``bg`` /
    ``fg`` to match a dark theme. ``delay`` and ``wraplength`` are in ms / px.
    """

    def __init__(self, widget, text, *, delay=500, wraplength=360,
                 bg="#11160f", fg="#c8f7c5"):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.wraplength = wraplength
        self.bg = bg
        self.fg = fg
        self._tip = None        # the Toplevel, while shown
        self._after_id = None    # pending "show" callback id

        # bind(..., add="+") so we never clobber handlers the widget already has.
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")
        widget.bind("<Destroy>", self._on_destroy, add="+")

    # -- internals ---------------------------------------------------------- #

    def _schedule(self, _evt=None):
        """Arm the delayed show; cancel any tip already pending/visible first."""
        self._cancel()
        self._hide()
        if not self.text:
            return
        try:
            self._after_id = self.widget.after(self.delay, self._show)
        except tk.TclError:
            self._after_id = None  # widget already gone

    def _cancel(self):
        """Cancel a pending (not-yet-shown) tooltip."""
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _show(self):
        self._after_id = None
        if self._tip is not None or not self.text:
            return
        try:
            # Position just below-left of the widget. winfo_* raises TclError if
            # the widget has been destroyed since the show was scheduled.
            x = self.widget.winfo_rootx() + 18
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
            tip = tk.Toplevel(self.widget)
        except tk.TclError:
            return
        tip.wm_overrideredirect(True)        # no title bar / border
        try:
            # Keep the tip above other windows where the platform supports it.
            tip.wm_attributes("-topmost", True)
        except tk.TclError:
            pass
        tip.wm_geometry(f"+{x}+{y}")
        label_kwargs = dict(text=self.text, justify="left", relief="solid",
                            borderwidth=1, wraplength=self.wraplength,
                            padx=6, pady=3)
        if self.bg:
            label_kwargs["bg"] = self.bg
        if self.fg:
            label_kwargs["fg"] = self.fg
        tk.Label(tip, **label_kwargs).pack()
        self._tip = tip

    def _hide(self, _evt=None):
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except tk.TclError:
                pass
            self._tip = None

    def _on_destroy(self, _evt=None):
        # The widget (and any child Toplevel) is going away; just drop our refs.
        self._cancel()
        self._tip = None


# --------------------------------------------------------------------------- #
# GLOSSARY — concise, neutral, accurate plain-language copy for recurring terms.
# Keys are lowercase. Hang these off labels via Tooltip(widget, GLOSSARY[key]).
# --------------------------------------------------------------------------- #

GLOSSARY = {
    # --- Wi-Fi attack/scan concepts the Marauder firmware exposes ---------- #
    "deauth":
        "Deauthentication: a Wi-Fi management frame that tells a client it has "
        "been disconnected, forcing it off the network. Used to test how a "
        "network handles forced disconnects (and to capture a fresh handshake).",
    "evil portal":
        "A fake captive-portal login page served by the device to a network it "
        "is impersonating, used to demonstrate credential-phishing risk on a "
        "network you own and are authorised to test.",
    "pmkid":
        "Pairwise Master Key Identifier: a value some access points include in "
        "the first handshake frame. It can be captured without a connected "
        "client and cracked offline to recover the Wi-Fi password.",
    "beacon spam":
        "Broadcasting many fake access-point beacon frames so bogus network "
        "names appear in nearby device Wi-Fi lists. Used to test client "
        "behaviour and list-flooding resilience.",
    "bssid":
        "Basic Service Set Identifier: the MAC address of a specific access "
        "point's radio. It uniquely identifies one AP, even when several share "
        "the same network name (SSID).",
    "station":
        "A Wi-Fi client device (phone, laptop, IoT gadget) connected to or "
        "probing for an access point — as opposed to the AP itself.",

    # --- Flashing terms --------------------------------------------------- #
    "full flash":
        "Writes the bootloader, partition table, boot_app0 and the application "
        "image to a blank or wiped board. Use this for a brand-new chip or "
        "after erasing flash.",
    "app-only flash":
        "Writes only the application image (at offset 0x10000), leaving the "
        "existing bootloader and partitions in place. Use this to update a "
        "board that already runs Marauder.",
    "baud":
        "Serial transfer speed in bits per second. Higher (e.g. 921600) flashes "
        "faster; if a flash fails or stalls, dropping to a lower rate (e.g. "
        "115200) is more reliable on long or noisy USB cables.",

    # --- Suicide-build / hardened-bundle terms (opt-in path) -------------- #
    "suicide build":
        "An owner-only hardened firmware variant that can wipe its own secrets "
        "when triggered, so a lost or seized device protects the data on it. "
        "It is provisioned separately; this app only flashes a prepared bundle.",
    "arming switch":
        "A deliberate, manual control that must be set before any self-wipe "
        "behaviour is possible. Until it is armed, the protective trigger does "
        "nothing — preventing accidental wipes.",
    "dead-man":
        "A dead-man (dead-man's-switch) check that expects a periodic, expected "
        "action from the owner; if that check-in stops for too long, the "
        "configured protective action runs on its own.",
    "guardcfg":
        "The guard configuration in a bundle: the settings that decide which "
        "protective triggers are enabled and how they behave. Defined when the "
        "bundle is provisioned, not edited here.",
    "bundle":
        "A folder produced by the provisioning step: a bundle.json manifest plus "
        "the firmware .bin images and their flash offsets. This app reads the "
        "manifest and flashes exactly those files — it does not build them.",
    "flash encryption/t2":
        "Flash Encryption (T2 / two-time-programmable mode) is an ESP32 feature "
        "that encrypts the firmware stored on the chip so it cannot be read out "
        "in the clear. It is burned in during provisioning by the Suicide-"
        "Marauder repo; this app never burns eFuses.",
}
