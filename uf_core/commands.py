"""
Marauder serial command catalog — the single source of truth shared by the TUI and the web GUI.

Data-driven on purpose: add a command here once and it shows up in BOTH front-ends.
Commands and flags are taken from the official ESP32 Marauder CLI:
  https://github.com/justcallmekoko/ESP32Marauder/wiki/cli
Run `help` on the device to confirm the exact set for your firmware version.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class Param:
    """One user-supplied argument for a command."""
    name: str                       # internal key + label
    flag: str = ""                  # e.g. "-s"; "" = positional / value appended bare
    kind: str = "text"              # text | int | select | bool
    choices: List[str] = field(default_factory=list)
    required: bool = False
    placeholder: str = ""
    help: str = ""


@dataclass
class Command:
    id: str
    label: str
    base: str                       # the fixed part, e.g. "attack -t deauth"
    category: str = "Misc"
    desc: str = ""
    params: List[Param] = field(default_factory=list)
    danger: bool = False            # attacks / spam — rendered in red, confirm before run
    longrunning: bool = False       # scans/sniffs — remind the user about `stopscan`


def build(cmd: Command, values: Optional[Dict[str, Any]] = None) -> str:
    """Turn a Command + user values into the exact serial string to send."""
    values = values or {}
    parts = [cmd.base]
    for p in cmd.params:
        v = values.get(p.name)
        if p.kind == "bool":
            if v:
                parts.append(p.flag)
            continue
        if v in (None, ""):
            continue
        token = f"{p.flag} {v}" if p.flag else str(v)
        parts.append(token)
    return " ".join(str(x) for x in parts).strip()


# --------------------------------------------------------------------------- #
# The catalog. Grouped by category; order here is the order shown in the UIs.
# --------------------------------------------------------------------------- #

COMMANDS: List[Command] = [
    # ---- WiFi: Scan ------------------------------------------------------- #
    Command("scanap", "Scan APs", "scanap", "WiFi · Scan",
            "Discover nearby access points.", longrunning=True),
    Command("scansta", "Scan Stations", "scansta", "WiFi · Scan",
            "Find client stations (run scanap first).", longrunning=True),
    Command("scanall", "Scan All", "scanall", "WiFi · Scan",
            "Scan APs and stations together.", longrunning=True),
    Command("sigmon", "Signal Monitor", "sigmon", "WiFi · Scan",
            "Live signal-strength monitor.", longrunning=True),
    Command("packetcount", "Packet Count", "packetcount", "WiFi · Scan",
            "Live packets-per-second counter.", longrunning=True),
    Command("mactrack", "MAC Track", "mactrack", "WiFi · Scan",
            "Track signal strength of selected MAC(s).", longrunning=True),
    Command("wardrive", "Wardrive", "wardrive", "WiFi · Scan",
            "GPS-tagged AP logging to SD.", longrunning=True,
            params=[Param("silent", "-s", "bool", help="Silent mode (no screen spam)")]),

    # ---- WiFi: Sniff ------------------------------------------------------ #
    Command("sniffraw", "Sniff Raw", "sniffraw", "WiFi · Sniff",
            "Capture raw 802.11 frames.", longrunning=True),
    Command("sniffbeacon", "Sniff Beacons", "sniffbeacon", "WiFi · Sniff",
            "Capture beacon frames.", longrunning=True),
    Command("sniffprobe", "Sniff Probes", "sniffprobe", "WiFi · Sniff",
            "Capture probe requests.", longrunning=True),
    Command("sniffdeauth", "Sniff Deauth", "sniffdeauth", "WiFi · Sniff",
            "Detect deauthentication frames (defensive).", longrunning=True),
    Command("sniffesp", "Sniff ESP", "sniffesp", "WiFi · Sniff",
            "Detect ESP-based devices.", longrunning=True),
    Command("sniffpwn", "Sniff Pwnagotchi", "sniffpwn", "WiFi · Sniff",
            "Detect nearby Pwnagotchi units.", longrunning=True),
    Command("sniffpmkid", "Sniff PMKID", "sniffpmkid", "WiFi · Sniff",
            "Capture PMKID/EAPOL handshakes (SavePCAP to SD).", longrunning=True,
            params=[
                Param("channel", "-c", "int", placeholder="6", help="Lock to a channel"),
                Param("deauth", "-d", "bool", help="Send deauth to force handshakes"),
                Param("targeted", "-l", "bool", help="Only selected APs"),
            ]),

    # ---- WiFi: Attack ----------------------------------------------------- #
    Command("deauth", "Deauth (selected APs)", "attack -t deauth", "WiFi · Attack",
            "Deauth all clients on the selected APs.", danger=True, longrunning=True,
            params=[
                Param("src", "-s", "text", placeholder="AA:BB:CC:DD:EE:FF", help="Manual source MAC"),
                Param("dst", "-d", "text", placeholder="AA:BB:CC:DD:EE:FF", help="Manual destination MAC"),
            ]),
    Command("deauth_clients", "Deauth (selected clients)", "attack -t deauth -c", "WiFi · Attack",
            "Deauth only the selected client stations.", danger=True, longrunning=True),
    Command("beacon_list", "Beacon Spam (list)", "attack -t beacon -l", "WiFi · Attack",
            "Broadcast SSIDs from your list.", danger=True, longrunning=True),
    Command("beacon_random", "Beacon Spam (random)", "attack -t beacon -r", "WiFi · Attack",
            "Broadcast random SSIDs.", danger=True, longrunning=True),
    Command("beacon_clone", "Beacon Spam (clone APs)", "attack -t beacon -a", "WiFi · Attack",
            "Clone scanned APs' SSIDs.", danger=True, longrunning=True),
    Command("probe_flood", "Probe Flood", "attack -t probe", "WiFi · Attack",
            "Flood probe requests.", danger=True, longrunning=True),
    Command("rickroll", "Rickroll Beacon", "attack -t rickroll", "WiFi · Attack",
            "Beacon-spam Rick Astley lyrics as SSIDs.", danger=True, longrunning=True),
    Command("badmsg", "Bad Msg (clients)", "attack -t badmsg -c", "WiFi · Attack",
            "Malformed-frame attack on selected clients.", danger=True, longrunning=True),
    Command("evilportal", "Evil Portal", "evilportal -c start", "WiFi · Attack",
            "Start a captive-portal credential harvester (needs SD HTML).", danger=True, longrunning=True,
            params=[Param("html", "-w", "text", placeholder="index.html", help="Template file on SD")]),
    Command("karma", "Karma", "karma", "WiFi · Attack",
            "Karma attack against a probed SSID.", danger=True, longrunning=True,
            params=[Param("index", "-p", "int", required=True, placeholder="0", help="Probe index")]),

    # ---- WiFi: Network ---------------------------------------------------- #
    Command("join", "Join Network", "join", "WiFi · Network",
            "Connect to a scanned AP.",
            params=[
                Param("index", "-a", "int", required=True, placeholder="0", help="AP index"),
                Param("password", "-p", "text", placeholder="hunter2", help="Network password"),
            ]),
    Command("pingscan", "Ping Scan", "pingscan", "WiFi · Network",
            "Find live IPs on the joined network.", longrunning=True),
    Command("portscan", "Port Scan", "portscan", "WiFi · Network",
            "Scan ports on a discovered host.", longrunning=True,
            params=[
                Param("all", "-a", "bool", help="All ports (not just common)"),
                Param("ip_index", "-t", "int", required=True, placeholder="0", help="IP index from pingscan"),
            ]),

    # ---- Bluetooth / BLE -------------------------------------------------- #
    Command("sniffbt", "Sniff Bluetooth", "sniffbt", "Bluetooth",
            "Scan BLE devices; filter by type.", longrunning=True,
            params=[Param("type", "-t", "select",
                          choices=["airtag", "flipper", "flock"],
                          help="Filter (airtag / flipper / flock cameras)")]),
    Command("btwardrive", "BT Wardrive", "btwardrive", "Bluetooth",
            "GPS-tagged Bluetooth logging.", longrunning=True,
            params=[Param("continuous", "-c", "bool", help="Continuous mode")]),
    Command("sniffskim", "Detect Skimmers", "sniffskim", "Bluetooth",
            "Scan for card-skimmer BLE signatures.", longrunning=True),
    Command("blespam", "BLE Spam", "blespam -t", "Bluetooth",
            "Spam BLE pairing pop-ups.", danger=True, longrunning=True,
            params=[Param("type", "", "select", required=True,
                          choices=["sourapple", "applejuice", "google", "samsung", "windows", "flipper", "all"],
                          help="Target ecosystem (firmware blespam -t types)")]),
    Command("spoofat", "Spoof AirTag", "spoofat", "Bluetooth",
            "Broadcast a cloned AirTag.", danger=True, longrunning=True,
            params=[Param("index", "-t", "int", required=True, placeholder="0", help="AirTag index")]),
    Command("sourapple", "Sour Apple", "sourapple", "Bluetooth",
            "iOS 17 BLE pop-up crash spam.", danger=True, longrunning=True),
    Command("swiftpair", "Swiftpair Spam", "swiftpair", "Bluetooth",
            "Windows BLE pairing-notification spam.", danger=True, longrunning=True),
    Command("samsungblespam", "Samsung BLE Spam", "samsungblespam", "Bluetooth",
            "Samsung BLE pairing spam.", danger=True, longrunning=True),
    Command("btspamall", "BLE Spam All", "btspamall", "Bluetooth",
            "Run all BLE spam attacks at once.", danger=True, longrunning=True),

    # ---- Lists & Targets -------------------------------------------------- #
    Command("list_ap", "List APs", "list -a", "Lists & Targets", "Show scanned access points."),
    Command("list_sta", "List Stations", "list -c", "Lists & Targets", "Show scanned client stations."),
    Command("list_ssid", "List SSIDs", "list -s", "Lists & Targets", "Show the SSID list."),
    Command("list_targets", "List Targets", "list -t", "Lists & Targets", "Show selected targets."),
    Command("select_ap", "Select APs", "select -a", "Lists & Targets",
            "Select APs by index (comma list, or 'all').",
            params=[Param("index", "", "text", required=True, placeholder="0,2,5  or  all")]),
    Command("select_sta", "Select Stations", "select -c", "Lists & Targets",
            "Select client stations by index.",
            params=[Param("index", "", "text", required=True, placeholder="0,1  or  all")]),
    Command("select_ssid", "Select SSIDs", "select -s", "Lists & Targets",
            "Select SSIDs by index.",
            params=[Param("index", "", "text", required=True, placeholder="0  or  all")]),
    Command("select_filter", "Select by Filter", "select -f", "Lists & Targets",
            "Select by a filter expression.",
            params=[Param("filter", "", "text", required=True, placeholder='"OPEN"')]),
    Command("clearlist_ap", "Clear APs", "clearlist -a", "Lists & Targets", "Clear the AP list."),
    Command("clearlist_sta", "Clear Stations", "clearlist -c", "Lists & Targets", "Clear the station list."),
    Command("clearlist_ssid", "Clear SSIDs", "clearlist -s", "Lists & Targets", "Clear the SSID list."),
    Command("info", "Device Info", "info", "Lists & Targets",
            "Device info, or details for one AP.",
            params=[Param("index", "-a", "int", placeholder="(blank = device)", help="AP index")]),

    # ---- SSID management -------------------------------------------------- #
    Command("ssid_add_named", "Add SSID (name)", "ssid -a -n", "SSID",
            "Add a named SSID to the list.",
            params=[Param("name", "", "text", required=True, placeholder="Free_WiFi")]),
    Command("ssid_add_random", "Add SSIDs (random)", "ssid -a -g", "SSID",
            "Generate N random SSIDs.",
            params=[Param("count", "", "int", required=True, placeholder="20")]),
    Command("ssid_remove", "Remove SSID", "ssid -r", "SSID",
            "Remove an SSID by index.",
            params=[Param("index", "", "int", required=True, placeholder="0")]),

    # ---- Channel ---------------------------------------------------------- #
    Command("channel_show", "Show Channel", "channel", "Channel", "Show the current channel."),
    Command("channel_set", "Set Channel", "channel -s", "Channel",
            "Set the WiFi channel.",
            params=[Param("channel", "", "int", required=True, placeholder="6")]),

    # ---- GPS -------------------------------------------------------------- #
    Command("gpsdata", "GPS Data", "gpsdata", "GPS", "Live GPS readout."),
    Command("nmea", "NMEA Stream", "nmea", "GPS", "Raw NMEA sentences.", longrunning=True),
    Command("gps_get", "GPS Field", "gps -g", "GPS",
            "Query one GPS field.",
            params=[Param("field", "", "select", required=True,
                          choices=["fix", "sat", "lat", "lon", "alt", "date", "accuracy", "text", "nmea"])]),

    # ---- Files (SD) ------------------------------------------------------- #
    Command("ls", "List Files", "ls", "Files",
            "List SD-card directory.",
            params=[Param("dir", "", "text", placeholder="/", help="Path (default /)")]),
    Command("save_ap", "Save APs", "save -a", "Files", "Save AP list to SD."),
    Command("save_ssid", "Save SSIDs", "save -s", "Files", "Save SSID list to SD."),
    Command("load_ap", "Load APs", "load -a", "Files", "Load AP list from SD."),
    Command("load_ssid", "Load SSIDs", "load -s", "Files", "Load SSID list from SD."),

    # ---- Settings / System ----------------------------------------------- #
    Command("settings_set", "Set Setting", "settings -s", "System",
            "Enable/disable a setting (e.g. SavePCAP).",
            params=[
                Param("name", "", "text", required=True, placeholder="SavePCAP"),
                Param("state", "", "select", required=True, choices=["enable", "disable"]),
            ]),
    Command("settings_reset", "Reset Settings", "settings -r", "System", "Reset settings to default."),
    Command("led_color", "LED Color", "led -s", "System",
            "Set LED to a hex color.",
            params=[Param("hex", "", "text", required=True, placeholder="FF0000")]),
    Command("led_rainbow", "LED Rainbow", "led -p rainbow", "System", "Rainbow LED effect."),
    Command("update_serial", "Update (serial)", "update -s", "System", "OTA update over serial.", danger=True),
    Command("update_web", "Update (web)", "update -w", "System", "OTA update over WiFi.", danger=True),
    Command("info_help", "Help", "help", "System", "Print the device's command list."),
    Command("reboot", "Reboot", "reboot", "System", "Restart the board.", danger=True),
    Command("stopscan", "Stop (stopscan)", "stopscan", "System",
            "Stop the running scan/attack.",
            params=[Param("force", "-f", "bool", help="Force-disconnect")]),
]


# Convenience lookups ------------------------------------------------------- #

def get(cmd_id: str) -> Optional[Command]:
    for c in COMMANDS:
        if c.id == cmd_id:
            return c
    return None


def categories() -> List[str]:
    seen = []
    for c in COMMANDS:
        if c.category not in seen:
            seen.append(c.category)
    return seen


def to_dict() -> List[Dict[str, Any]]:
    """JSON-able catalog grouped by category, for the web front-end."""
    out = []
    for cat in categories():
        cmds = []
        for c in COMMANDS:
            if c.category != cat:
                continue
            cmds.append({
                "id": c.id, "label": c.label, "base": c.base, "desc": c.desc,
                "danger": c.danger, "longrunning": c.longrunning,
                "params": [
                    {"name": p.name, "flag": p.flag, "kind": p.kind,
                     "choices": p.choices, "required": p.required,
                     "placeholder": p.placeholder, "help": p.help}
                    for p in c.params
                ],
            })
        out.append({"category": cat, "commands": cmds})
    return out
