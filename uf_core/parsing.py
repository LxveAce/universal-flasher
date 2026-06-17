"""
Parse Marauder serial output into structured records for live tables + the target picker.

Two AP formats are handled (they differ by command and firmware):

  scanap stream:   RSSI: -57 Ch: 3 BSSID: 50:ff:20:84:d6:0f ESSID: Octoglass Beacon: ...
  list dump:       [0][CH:5] SpectrumSetup-B566 -54

`list -a` (APs) and `list -c` (stations) emit the SAME `[idx][CH:n] <value> -rssi` shape, so we
track which list command is in flight (from the echoed line) and route rows to APs vs stations
accordingly. The list index is what `select -a N` / `select -c N` expect, so it's the
authoritative source for the tables and pickers.
"""

import re
from dataclasses import dataclass

_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"

# scanap stream line — only strip a *trailing* "Beacon: <n>" stat, so an SSID that merely
# contains the word "Beacon:" is not truncated.
_SCAN_RE = re.compile(
    r"RSSI:\s*(-?\d+)\s+Ch:\s*(\d+)\s+BSSID:\s*(" + _MAC + r")\s+ESSID:\s*(.*?)(?:\s+Beacon:\s*\d.*)?$"
)
# list -a / list -c dump line:  [0][CH:5] <name or mac> -54
_LIST_RE = re.compile(r"^\s*\[(\d+)\]\[CH:\s*(\d+)\]\s+(.*?)\s+(-?\d+)\s*$")
_STA_RE = re.compile(r"(?i)\b(?:sta(?:tion)?|client)\b.*?(" + _MAC + r")(?:.*?(" + _MAC + r"))?")
_RSSI_RE = re.compile(r"RSSI:\s*(-?\d+)")


@dataclass
class AP:
    index: int = -1          # Marauder's own index (from list -a); -1 if unknown
    ssid: str = ""
    channel: str = ""
    rssi: str = ""
    bssid: str = ""          # only from scanap stream


@dataclass
class Station:
    index: int = -1          # Marauder's own index (from list -c); -1 if unknown
    mac: str = ""
    ap_bssid: str = ""
    rssi: str = ""


def _is_tag(line: str) -> bool:
    if line.startswith((">>", "$")):
        return True
    return line[:1] == "[" and not (len(line) > 1 and line[1].isdigit())


def _list_kind_of(line: str):
    """Detect which list is being dumped from an echoed command line."""
    low = line.lower()
    if "list -c" in low:
        return "sta"
    if "list -s" in low:
        return "ssid"
    if "list -a" in low:
        return "ap"
    return None


class MarauderParser:
    def __init__(self):
        self.aps: dict = {}          # index -> AP  (list -a)
        self.scan_aps: dict = {}     # bssid -> AP  (scanap stream)
        self.stations: dict = {}     # index -> Station (list -c)
        self.scan_sta: dict = {}     # mac -> Station (scansta stream)
        self._list_kind = "ap"
        self.dirty = False

    def clear(self):
        self.aps.clear(); self.scan_aps.clear()
        self.stations.clear(); self.scan_sta.clear()
        self.dirty = True

    def feed(self, line: str):
        if not line:
            return (None, None)

        # note which list is being dumped (works for our ">> list -c" echo and the
        # device's "> #list -c" echo) so the indexed rows route correctly
        k = _list_kind_of(line)
        if k:
            self._list_kind = k

        if _is_tag(line):
            return (None, None)

        # indexed list dump — route by the active list kind
        m = _LIST_RE.match(line)
        if m:
            idx, ch, name, rssi = m.groups()
            idx = int(idx)
            if self._list_kind == "sta":
                if idx == 0:
                    self.stations.clear()
                self.stations[idx] = Station(index=idx, mac=name.strip().lower(), rssi=rssi)
                self.dirty = True
                return ("sta", self.stations[idx])
            if self._list_kind == "ssid":
                return (None, None)   # SSID list — not tabled
            if idx == 0:
                self.aps.clear()
            self.aps[idx] = AP(index=idx, ssid=(name.strip() or "<hidden>"), channel=ch, rssi=rssi)
            self.dirty = True
            return ("ap", self.aps[idx])

        # scanap stream (carries BSSID)
        m = _SCAN_RE.search(line)
        if m:
            rssi, ch, bssid, ssid = m.groups()
            key = bssid.lower()
            self.scan_aps[key] = AP(ssid=(ssid.strip() or "<hidden>"), channel=ch, rssi=rssi, bssid=key)
            self.dirty = True
            return ("ap", self.scan_aps[key])

        # station stream (tolerant)
        m = _STA_RE.search(line)
        if m:
            mac = m.group(1).lower()
            rm = _RSSI_RE.search(line)
            self.scan_sta[mac] = Station(mac=mac, ap_bssid=(m.group(2) or "").lower(),
                                         rssi=rm.group(1) if rm else "")
            self.dirty = True
            return ("sta", self.scan_sta[mac])

        return (None, None)

    # --- accessors -------------------------------------------------------- #
    def indexed_aps(self):
        return [self.aps[i] for i in sorted(self.aps)]

    def indexed_stations(self):
        return [self.stations[i] for i in sorted(self.stations)]

    def ap_rows(self):
        if self.aps:
            return self.indexed_aps()

        def strength(a):
            try:
                return int(a.rssi)
            except (ValueError, TypeError):
                return -999
        return sorted(self.scan_aps.values(), key=strength, reverse=True)

    def station_rows(self):
        if self.stations:
            return self.indexed_stations()
        return list(self.scan_sta.values())
