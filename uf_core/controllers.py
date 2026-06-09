"""Serial controllers for non-Marauder firmware.

Each controller knows how to talk to a specific firmware over serial — sending
commands, parsing responses, extracting version info. The MarauderController in
controller.py handles Marauder; this module covers everything else.
"""

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

try:
    import serial
    from serial.tools import list_ports
    _HAVE_PYSERIAL = True
except Exception:
    _HAVE_PYSERIAL = False

Line = Callable[[str], None]


@dataclass
class DeviceStatus:
    firmware: str = "unknown"
    version: str = ""
    chip: str = ""
    uptime: str = ""
    extra: Dict[str, str] = field(default_factory=dict)


class GenericSerialController:
    """Minimal serial controller for firmware that speaks plain text over UART."""

    def __init__(self, port: Optional[str] = None, baud: int = 115200):
        self.port = port
        self.baud = baud
        self.ser: Optional["serial.Serial"] = None
        self._reader: Optional[threading.Thread] = None
        self._running = False
        self._subs: List[Line] = []
        self._write_lock = threading.Lock()
        self._buffer: List[str] = []
        self._buffer_lock = threading.Lock()

    def connect(self) -> str:
        if not _HAVE_PYSERIAL:
            raise RuntimeError("pyserial is not installed")
        if not self.port:
            raise RuntimeError("No port specified")
        self.ser = serial.Serial(self.port, self.baud, timeout=0.2)
        self._running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        return self.port

    def disconnect(self):
        self._running = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        if self._reader:
            self._reader.join(timeout=1.0)
            self._reader = None
        self.ser = None

    @property
    def connected(self) -> bool:
        return self._running and self.ser is not None

    def subscribe(self, cb: Line):
        self._subs.append(cb)

    def _emit(self, line: str):
        with self._buffer_lock:
            self._buffer.append(line)
            if len(self._buffer) > 500:
                self._buffer.pop(0)
        for cb in list(self._subs):
            try:
                cb(line)
            except Exception:
                pass

    def _read_loop(self):
        buf = b""
        while self._running:
            ser = self.ser
            if ser is None:
                break
            try:
                data = ser.read(4096)
            except Exception as e:
                if self._running:
                    self._emit(f"[serial error] {e}")
                break
            if data:
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._emit(line.decode("utf-8", "replace").rstrip("\r"))

    def send(self, command: str):
        if not command or not command.strip():
            return
        self._emit(f">> {command.strip()}")
        if not self.ser:
            self._emit("[error] not connected")
            return
        with self._write_lock:
            self.ser.write((command.strip() + "\n").encode())

    def send_and_capture(self, command: str, wait_ms: int = 500) -> List[str]:
        """Send a command and capture response lines for `wait_ms` milliseconds."""
        start_idx = len(self._buffer)
        self.send(command)
        time.sleep(wait_ms / 1000.0)
        with self._buffer_lock:
            return list(self._buffer[start_idx:])

    def get_buffer(self, last_n: int = 50) -> List[str]:
        with self._buffer_lock:
            return list(self._buffer[-last_n:])


class HaleHoundController(GenericSerialController):
    """Controller for HaleHound-CYD firmware."""

    COMMANDS = {
        "iot_recon": "IoT Recon mode — scan for default-credential IoT devices",
        "wifi_scan": "Scan for WiFi networks",
        "ble_scan": "Scan for BLE devices",
        "deauth": "Deauth attack on selected target",
        "evil_portal": "Launch evil portal captive page",
        "packet_monitor": "Monitor WiFi packets",
        "beacon_spam": "Beacon spam — flood area with fake SSIDs",
        "stop": "Stop current operation",
    }

    def get_status(self) -> DeviceStatus:
        lines = self.send_and_capture("status", wait_ms=800)
        status = DeviceStatus(firmware="halehound")
        for line in lines:
            m = re.search(r"HaleHound.*?[Vv]?([\d.]+)", line)
            if m:
                status.version = m.group(1)
            if "ESP32" in line:
                status.chip = "esp32"
        return status


class MeshtasticController(GenericSerialController):
    """Controller for Meshtastic firmware over serial."""

    def __init__(self, port: Optional[str] = None, baud: int = 115200):
        super().__init__(port, baud)
        self._node_info: Optional[Dict] = None

    def get_status(self) -> DeviceStatus:
        status = DeviceStatus(firmware="meshtastic")
        try:
            lines = self.send_and_capture("", wait_ms=1000)
            for line in lines:
                m = re.search(r"Meshtastic\s+[Vv]?([\d.]+)", line)
                if m:
                    status.version = m.group(1)
        except Exception:
            pass
        return status

    def send_message(self, text: str, dest: str = "^all"):
        self.send(f"meshtastic --sendtext \"{text}\" --dest {dest}")

    def get_nodes(self) -> List[str]:
        lines = self.send_and_capture("meshtastic --nodes", wait_ms=2000)
        return [l for l in lines if not l.startswith(">>")]


class GhostEspController(GenericSerialController):
    """Controller for GhostESP firmware."""

    COMMANDS = {
        "scanap": "Scan for WiFi access points",
        "scansta": "Scan for WiFi stations",
        "beacon": "Beacon spam attack",
        "deauth": "Deauthentication attack",
        "probe": "Probe request flood",
        "sniff": "Packet sniffing mode",
        "blescan": "BLE device scanning",
        "stop": "Stop current operation",
        "reboot": "Reboot the device",
    }

    def get_status(self) -> DeviceStatus:
        lines = self.send_and_capture("version", wait_ms=500)
        status = DeviceStatus(firmware="ghostesp")
        for line in lines:
            m = re.search(r"GhostESP\s+[Vv]?([\w.]+)", line)
            if m:
                status.version = m.group(1)
        return status


class BruceController(GenericSerialController):
    """Controller for Bruce firmware."""

    COMMANDS = {
        "wifi_scan": "Scan WiFi networks",
        "wifi_deauth": "Deauth attack",
        "ble_scan": "BLE scanner",
        "ir_send": "IR transmit",
        "rfid_read": "RFID reader",
        "nfc_read": "NFC reader",
        "badusb": "BadUSB payload execution",
        "gps": "GPS information",
    }

    def get_status(self) -> DeviceStatus:
        lines = self.send_and_capture("version", wait_ms=500)
        status = DeviceStatus(firmware="bruce")
        for line in lines:
            m = re.search(r"Bruce\s+[Vv]?([\d.]+)", line)
            if m:
                status.version = m.group(1)
        return status


# Controller registry — maps firmware profile IDs to controller classes
CONTROLLERS: Dict[str, type] = {
    "halehound": HaleHoundController,
    "meshtastic": MeshtasticController,
    "ghostesp": GhostEspController,
    "bruce": BruceController,
}


def get_controller(firmware_id: str, port: str, baud: int = 115200) -> GenericSerialController:
    """Return the appropriate controller for a firmware type."""
    cls = CONTROLLERS.get(firmware_id, GenericSerialController)
    return cls(port=port, baud=baud)


def list_controllers() -> List[Tuple[str, str]]:
    """Return [(firmware_id, controller_class_name)] for all registered controllers."""
    return [(fid, cls.__name__) for fid, cls in CONTROLLERS.items()]
