"""Universal Flasher core: multi-firmware flasher, serial controllers, device
detection, and management for ESP32, Raspberry Pi, Flipper Zero, and ADB-based
security hardware. Built on the Headless Marauder scaffold."""

__version__ = "1.4.0"

from .controller import MarauderController
from .parsing import MarauderParser, AP, Station
from .capture import CaptureLogger, default_log_dir
from .device_detect import DeviceInfo, scan_ports, generate_manifest
from . import commands
from . import flasher
from . import updater
from . import device_detect

__all__ = [
    "MarauderController", "MarauderParser", "AP", "Station",
    "CaptureLogger", "default_log_dir",
    "DeviceInfo", "scan_ports", "generate_manifest",
    "commands", "flasher", "updater", "device_detect", "__version__",
]
