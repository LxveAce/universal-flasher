"""Post-flash health check — verify a device booted correctly after flashing.

Connects to the serial port after flash, watches for boot output, and validates
the firmware started successfully by checking for known startup signatures.
"""

import re
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

Line = Callable[[str], None]

BOOT_SIGNATURES: Dict[str, List[str]] = {
    "marauder": ["WiFi Started", "Marauder", "Ready"],
    "ghostesp": ["GhostESP", "Ready", "Boot"],
    "bruce": ["Bruce", "Boot", "Ready"],
    "halehound": ["HaleHound", "Boot", "Ready"],
    "meshtastic": ["Meshtastic", "boot", "firmware"],
    "esp32-div": ["ESP32-DIV", "Ready", "Boot"],
    "flock-you": ["Flock", "scanning", "Boot"],
    "oui-spy": ["OUI", "scanning", "Boot"],
    "sky-spy": ["RemoteID", "scanning", "Boot"],
    "airtag-scanner": ["AirTag", "Scanner", "BLE"],
    "cyt-ng": ["Chasing", "Tail", "BLE"],
}

FAILURE_PATTERNS = [
    re.compile(r"guru\s+meditation", re.IGNORECASE),
    re.compile(r"rst:0x[0-9a-f]+.*boot:0x[0-9a-f]+.*rst", re.IGNORECASE),
    re.compile(r"assert\s+failed", re.IGNORECASE),
    re.compile(r"abort\(\)", re.IGNORECASE),
    re.compile(r"Backtrace:", re.IGNORECASE),
    re.compile(r"panic", re.IGNORECASE),
    re.compile(r"flash\s+read\s+err", re.IGNORECASE),
    re.compile(r"invalid\s+header", re.IGNORECASE),
]


@dataclass
class HealthResult:
    healthy: bool
    firmware_detected: str = ""
    version_detected: str = ""
    boot_time_ms: int = 0
    warnings: List[str] = None
    errors: List[str] = None
    raw_output: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.errors is None:
            self.errors = []
        if self.raw_output is None:
            self.raw_output = []


def check_health(port: str, expected_firmware: str, on_line: Line,
                 timeout_s: float = 15.0, baud: int = 115200) -> HealthResult:
    """Open serial port, watch for boot output, and verify firmware started."""
    try:
        import serial
    except ImportError:
        return HealthResult(healthy=False, errors=["pyserial not installed"])

    from .device_detect import FIRMWARE_SIGNATURES

    result = HealthResult(healthy=False)
    lines: List[str] = []
    start = time.monotonic()

    on_line(f"[health] Monitoring {port} for boot output (timeout {timeout_s}s)...")

    try:
        ser = serial.Serial(port, baud, timeout=0.5)
    except Exception as e:
        on_line(f"[health] Could not open {port}: {e}")
        result.errors.append(str(e))
        return result

    try:
        sigs = BOOT_SIGNATURES.get(expected_firmware, [])
        sig_hits = 0

        while (time.monotonic() - start) < timeout_s:
            try:
                data = ser.read(4096)
            except Exception:
                break
            if not data:
                continue
            text = data.decode("utf-8", "replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                lines.append(line)
                on_line(f"[health] {line}")

                for pat in FAILURE_PATTERNS:
                    if pat.search(line):
                        result.errors.append(f"Crash detected: {line}")

                for sig in sigs:
                    if sig.lower() in line.lower():
                        sig_hits += 1
                        break

                for fw_id, pattern in FIRMWARE_SIGNATURES.items():
                    m = re.search(pattern, line)
                    if m:
                        result.firmware_detected = fw_id
                        result.version_detected = m.group(1) if m.lastindex else ""

        elapsed = int((time.monotonic() - start) * 1000)
        result.boot_time_ms = elapsed
        result.raw_output = lines

        if result.errors:
            result.healthy = False
            on_line(f"[health] FAIL — crash/error detected on {port}")
        elif sig_hits >= 1:
            result.healthy = True
            on_line(f"[health] OK — {expected_firmware} booted on {port} ({elapsed}ms)")
        elif result.firmware_detected:
            if result.firmware_detected == expected_firmware:
                result.healthy = True
                on_line(f"[health] OK — {result.firmware_detected} v{result.version_detected} on {port}")
            else:
                result.warnings.append(
                    f"Expected {expected_firmware} but detected {result.firmware_detected}"
                )
                result.healthy = True
                on_line(f"[health] WARN — expected {expected_firmware}, "
                        f"got {result.firmware_detected} on {port}")
        else:
            result.warnings.append("No firmware signature detected in boot output")
            on_line(f"[health] WARN — no boot signature matched on {port} after {elapsed}ms")
            result.healthy = len(lines) > 0

    finally:
        try:
            ser.close()
        except Exception:
            pass

    return result


def check_all_ports(ports: Dict[str, str], on_line: Line,
                    timeout_s: float = 15.0) -> Dict[str, HealthResult]:
    """Check health on multiple ports. ports maps port_name to expected firmware_id."""
    results = {}
    for port, firmware in ports.items():
        results[port] = check_health(port, firmware, on_line, timeout_s)
    return results
