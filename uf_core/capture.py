"""
CaptureLogger — log everything the board says to a folder on the host, live-accessible.

Writes three things into a chosen directory (default ~/marauder-logs):
  * serial-<timestamp>.log   append-only raw serial stream (tail -f friendly)
  * latest.json              atomic snapshot of current APs/stations/status (poll it)
  * aps.csv / stations.csv   current parsed tables (refreshed from the snapshot)

Plain files = the simplest "live access for the connected device": any other process or
machine can `tail -f` the serial log or read latest.json. No server required.
"""

import csv
import json
import os
import time
from dataclasses import asdict, is_dataclass
from typing import List, Optional


def default_log_dir() -> str:
    return os.path.join(os.path.expanduser("~"), "marauder-logs")


def _rows(items) -> list:
    out = []
    for it in items:
        out.append(asdict(it) if is_dataclass(it) else dict(it))
    return out


class CaptureLogger:
    _FLUSH_EVERY = 40   # flush after N lines instead of every line (keeps the UI loop snappy)

    def __init__(self, directory: Optional[str] = None):
        self.dir = directory or default_log_dir()
        self.enabled = False
        self._fp = None
        self._serial_path = None
        self.session = None
        self._pending = 0

    # --- lifecycle -------------------------------------------------------- #
    def set_dir(self, directory: str):
        running = self.enabled
        if running:
            self.stop()
        self.dir = directory
        if running:
            self.start()

    def start(self, stamp: Optional[str] = None) -> str:
        os.makedirs(self.dir, exist_ok=True)
        self.session = stamp or time.strftime("%Y%m%d-%H%M%S")
        self._serial_path = os.path.join(self.dir, f"serial-{self.session}.log")
        self._fp = open(self._serial_path, "a", encoding="utf-8")
        self._fp.write(f"# session {self.session} started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._fp.flush()
        self._pending = 0
        self.enabled = True
        return self._serial_path

    def stop(self):
        self.enabled = False
        if self._fp:
            try:
                self._fp.flush()
                self._fp.close()
            except Exception:
                pass
        self._fp = None

    @property
    def serial_path(self) -> Optional[str]:
        return self._serial_path

    # --- writes ----------------------------------------------------------- #
    def write_serial(self, line: str):
        if not (self.enabled and self._fp):
            return
        try:
            self._fp.write(line + "\n")
            self._pending += 1
            if self._pending >= self._FLUSH_EVERY:   # batch flushes — don't stall the UI per line
                self._fp.flush()
                self._pending = 0
        except Exception:
            pass

    def write_snapshot(self, aps: List, stations: List, meta: Optional[dict] = None):
        """Atomically refresh latest.json + aps.csv + stations.csv from parsed state."""
        if not self.enabled:
            return
        try:
            if self._fp:                       # keep the serial log reasonably current too
                self._fp.flush(); self._pending = 0
            os.makedirs(self.dir, exist_ok=True)
            ap_rows = _rows(aps)
            sta_rows = _rows(stations)
            data = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "session": self.session,
                "meta": meta or {},
                "ap_count": len(ap_rows),
                "station_count": len(sta_rows),
                "aps": ap_rows,
                "stations": sta_rows,
            }
            self._atomic_write("latest.json", json.dumps(data, indent=2))
            self._write_csv("aps.csv", ["index", "ssid", "channel", "rssi", "bssid"], ap_rows)
            self._write_csv("stations.csv", ["mac", "ap_bssid", "rssi"], sta_rows)
        except Exception:
            pass

    # --- helpers ---------------------------------------------------------- #
    def _atomic_write(self, name: str, text: str):
        path = os.path.join(self.dir, name)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)   # atomic on POSIX — readers never see a partial file
        except Exception:
            self._cleanup(tmp)       # e.g. Windows: dest held open by a reader
            raise

    def _write_csv(self, name: str, fields: List[str], rows: List[dict]):
        path = os.path.join(self.dir, name)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(fields)
                for r in rows:
                    w.writerow([r.get(k, "") for k in fields])
            os.replace(tmp, path)
        except Exception:
            self._cleanup(tmp)
            raise

    @staticmethod
    def _cleanup(tmp: str):
        try:
            os.remove(tmp)
        except Exception:
            pass
