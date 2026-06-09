"""
MarauderController — the serial layer shared by the TUI and the desktop GUI.

Owns the USB serial connection to a headless ESP32 Marauder, runs a background
reader thread, and fans incoming lines out to any number of subscriber callbacks.
Pure Python + pyserial — no UI, no web, Kali-friendly.
"""

import glob
import threading
import time
from typing import Callable, List, Optional, Tuple

try:
    import serial
    from serial.tools import list_ports
    _HAVE_PYSERIAL = True
except Exception:  # pyserial not installed yet
    _HAVE_PYSERIAL = False


_CH340_HINTS = ("ch340", "ch341", "cp210", "qinheng", "silicon labs", "wch", "usb-serial", "usb serial")


class MarauderController:
    def __init__(self, port: Optional[str] = None, baud: int = 115200, mock: bool = False):
        self.port = port
        self.baud = baud
        self.mock = mock
        self.ser = None
        self._reader: Optional[threading.Thread] = None
        self._running = False
        self._subs: List[Callable[[str], None]] = []
        self._write_lock = threading.Lock()

    # --- discovery -------------------------------------------------------- #
    @staticmethod
    def list_ports() -> List[Tuple[str, str]]:
        """[(device, description), ...] — best effort across platforms."""
        out: List[Tuple[str, str]] = []
        if _HAVE_PYSERIAL:
            for p in list_ports.comports():
                out.append((p.device, p.description or ""))
        # Linux fallback in case enumeration misses something
        seen = {d for d, _ in out}
        for g in sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")):
            if g not in seen:
                out.append((g, "serial"))
        return out

    @classmethod
    def autodetect(cls) -> Optional[str]:
        """Pick the most likely Marauder port (prefers CH340/CP210x).

        Requires a positive signal — a bare port with no USB-serial hint scores 0 and is
        never chosen, so we return None (and connect() raises the helpful 'plug it in' error)
        rather than silently opening e.g. /dev/ttyS0 or a Bluetooth COM port.
        """
        best, best_score = None, 0
        for device, desc in cls.list_ports():
            score = 0
            text = (device + " " + desc).lower()
            if "ttyusb" in device.lower() or "ttyacm" in device.lower():
                score += 1
            if any(h in text for h in _CH340_HINTS):
                score += 5
            if score > best_score:
                best, best_score = device, score
        return best

    # --- lifecycle -------------------------------------------------------- #
    def connect(self) -> str:
        if self.mock:
            self.port = self.port or "MOCK"
            self._start_reader()
            self._emit("[mock] connected — no real device. Commands are echoed.")
            return self.port

        if not _HAVE_PYSERIAL:
            raise RuntimeError("pyserial is not installed. Run: pip install pyserial")

        if not self.port:
            self.port = self.autodetect()
        if not self.port:
            raise RuntimeError(
                "No serial port found. Plug the board in and check /dev/ttyUSB* "
                "(see headless-on-kali troubleshooting: brltty / dialout / cable)."
            )
        self.ser = serial.Serial(self.port, self.baud, timeout=0.2)
        self._start_reader()
        return self.port

    def _start_reader(self):
        self._running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        buf = b""
        while self._running:
            if self.mock:
                time.sleep(0.2)
                continue
            ser = self.ser                 # snapshot — disconnect() may null/close it
            if ser is None:
                break
            try:
                data = ser.read(4096)
            except Exception as e:
                if self._running:          # only noise if it wasn't a clean disconnect
                    self._emit(f"[serial error] {e}")
                break
            if data:
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._emit(line.decode("utf-8", "replace").rstrip("\r"))

    def disconnect(self):
        self._running = False
        ser = self.ser
        if ser:
            try:
                ser.close()        # unblocks a pending read() so the reader exits promptly
            except Exception:
                pass
        if self._reader:
            self._reader.join(timeout=1.0)
            self._reader = None
        self.ser = None

    @property
    def connected(self) -> bool:
        return self._running and (self.mock or self.ser is not None)

    # --- io --------------------------------------------------------------- #
    def subscribe(self, cb: Callable[[str], None]):
        self._subs.append(cb)

    def _emit(self, line: str):
        for cb in list(self._subs):
            try:
                cb(line)
            except Exception:
                pass

    def send(self, command: str):
        command = (command or "").strip()
        if not command:
            return
        self._emit(f">> {command}")
        if self.mock:
            self._emit(f"[mock] would send: {command}")
            return
        if not self.ser:
            self._emit("[error] not connected")
            return
        with self._write_lock:
            self.ser.write((command + "\n").encode())

    def stop(self):
        """Send the universal stop."""
        self.send("stopscan")
