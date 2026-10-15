"""Fictional demonstration site: Kestrel Ridge Energy Complex (KREC).

Entirely fictional: no real location, vendor, device or vulnerability. Coordinates are site metres,
origin at the south-west corner (docs/REQUIREMENTS.md, plan section 4). "Voltek" is an invented vendor.
"""
from __future__ import annotations

from typing import Any

SITE = {"name": "Kestrel Ridge Energy Complex", "width_m": 1000, "height_m": 700, "centre": [500, 350]}


def _rect(x0: float, y0: float, x1: float, y1: float) -> list[list[float]]:
    return [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]


ZONES: list[dict[str, Any]] = [
    {"code": "Z0", "name": "Buffer and south field", "criticality": "low", "polygon": _rect(0, 0, 1000, 700),
     "description": "Fallback area: parking, maintenance workshop, access road"},
    {"code": "Z1", "name": "Gate and Administration", "criticality": "medium", "polygon": _rect(0, 0, 300, 220),
     "description": "B0 gatehouse, B1 administration and SOC"},
    {"code": "Z2", "name": "Control and SCADA core", "criticality": "critical", "polygon": _rect(300, 220, 620, 460),
     "description": "B2 control building, SCADA servers, historian, engineering workstation"},
    {"code": "Z3", "name": "Generation hall", "criticality": "critical", "polygon": _rect(300, 460, 650, 680),
     "description": "B3 hall with two gas turbine sets"},
    {"code": "Z4", "name": "Switchyard 110/22 kV", "criticality": "critical", "polygon": _rect(660, 40, 1000, 400),
     "description": "Transformers T1, T2 and B4 relay house"},
    {"code": "Z5", "name": "Battery storage yard", "criticality": "high", "polygon": _rect(0, 440, 280, 700),
     "description": "Containers C1 to C4, power conversion cabinet B5"},
    {"code": "Z6", "name": "Fuel gas and utilities", "criticality": "high", "polygon": _rect(660, 420, 1000, 700),
     "description": "B6 gas pressure reduction, B7 telecom shelter and mast"},
]


def _a(code: str, name: str, typ: str, level: str, zone: str, loc: str, x: float, y: float, crit: str,
       ip: str = "", exposure: tuple[str, ...] = (), vendor: str = "", model: str = "", fw: str = "",
       protocols: tuple[str, ...] = (), software: tuple[tuple[str, str, str, str], ...] = (),
       notes: str = "") -> dict[str, Any]:
    return {
        "code": code, "name": name, "asset_type": typ, "purdue_level": level, "zone": zone, "location": loc,
        "x": x, "y": y, "criticality": crit, "ip_address": ip, "exposure": list(exposure), "vendor": vendor,
        "model": model, "firmware_version": fw, "protocols": list(protocols),
        "software": [{"name": n, "vendor": v, "version": ver, "cpe": cpe} for n, v, ver, cpe in software],
        "notes": notes,
    }


_WIN19 = ("Windows Server 2019", "Microsoft", "10.0.17763", "cpe:2.3:o:microsoft:windows_server_2019:-")
_SCADA = ("Voltek SCADA Server", "Voltek", "4.2.1", "cpe:2.3:a:voltek:scada_server:4.2.1")
_SCADA_WEB = ("Voltek SCADA Web Console", "Voltek", "4.2.1", "cpe:2.3:a:voltek:scada_web_console:4.2.1")

B1, B2, B3, B4 = "B1 Administration", "B2 Control building", "B3 Generation hall", "B4 Relay house"

ASSETS: list[dict[str, Any]] = [
    # Purdue level 4: enterprise IT (B1 server room)
    _a("DC-01", "Directory controller", "server", "4", "Z1", B1, 90, 130, "high", "10.20.10.11",
       vendor="Microsoft", software=(_WIN19,)),
    _a("FILE-01", "File server", "server", "4", "Z1", B1, 92, 132, "medium", "10.20.10.12", software=(_WIN19,)),
    _a("MAIL-GW", "Mail gateway", "gateway", "4", "Z1", B1, 94, 130, "medium", "10.20.10.13"),
    _a("ARGUS-APP", "ArgusGrid application server", "server", "4", "Z1", B1, 96, 130, "high", "10.20.10.20",
       software=(("ArgusGrid", "Expert Solutions", "0.1", ""),)),
    _a("ARGUS-DB", "ArgusGrid database server", "server", "4", "Z1", B1, 98, 130, "high", "10.20.10.21",
       software=(("PostgreSQL", "PostgreSQL Global Development Group", "16.13", "cpe:2.3:a:postgresql:postgresql:16.13"),)),
    # Level 3.5: DMZ
    _a("FW-ITOT-A", "IT/OT firewall A", "firewall", "3.5", "Z1", B1, 100, 128, "high", "10.20.20.1"),
    _a("FW-ITOT-B", "IT/OT firewall B", "firewall", "3.5", "Z1", B1, 102, 128, "high", "10.20.20.2"),
    _a("JUMP-01", "Jump host", "server", "3.5", "Z1", B1, 104, 128, "high", "10.20.20.10", protocols=("RDP", "SSH"),
       software=(_WIN19,)),
    _a("PATCH-01", "Patch relay", "server", "3.5", "Z1", B1, 106, 128, "medium", "10.20.20.11", software=(_WIN19,)),
    _a("HIST-DMZ", "Historian mirror", "server", "3.5", "Z1", B1, 108, 128, "medium", "10.20.20.12",
       software=(("Voltek Historian", "Voltek", "3.8.0", "cpe:2.3:a:voltek:historian:3.8.0"),)),
    # Level 3: operations (B2)
    _a("SCADA-SRV-01", "SCADA server (primary)", "server", "3", "Z2", B2, 440, 320, "critical", "10.20.30.10",
       vendor="Voltek", model="SCADA Server 4", protocols=("OPC UA", "Modbus/TCP", "IEC 60870-5-104"),
       software=(_SCADA, _SCADA_WEB, _WIN19)),
    _a("SCADA-SRV-02", "SCADA server (standby)", "server", "3", "Z2", B2, 442, 320, "high", "10.20.30.11",
       vendor="Voltek", model="SCADA Server 4", software=(_SCADA, _SCADA_WEB, _WIN19)),
    _a("HIST-01", "Historian", "server", "3", "Z2", B2, 444, 320, "high", "10.20.30.12", vendor="Voltek",
       software=(("Voltek Historian", "Voltek", "3.8.0", "cpe:2.3:a:voltek:historian:3.8.0"), _WIN19)),
    _a("EWS-01", "Engineering workstation", "workstation", "3", "Z2", B2, 446, 322, "high", "10.20.30.20",
       exposure=("physical_access",), software=(("Voltek Engineering Studio", "Voltek", "7.1", ""), _WIN19)),
    _a("HMI-01", "Operator HMI 1", "hmi", "3", "Z2", B2, 436, 316, "medium", "10.20.30.31",
       software=(("Voltek HMI Runtime", "Voltek", "4.2.1", ""),)),
    _a("HMI-02", "Operator HMI 2", "hmi", "3", "Z2", B2, 438, 316, "medium", "10.20.30.32",
       software=(("Voltek HMI Runtime", "Voltek", "4.2.1", ""),)),
    _a("HMI-03", "Maintenance tablet HMI", "hmi", "3", "Z2", B2, 450, 318, "medium", "10.20.30.33",
       exposure=("wireless",), software=(("Voltek HMI Runtime", "Voltek", "4.2.1", ""),)),
    _a("TIME-01", "GNSS time server", "time_server", "3", "Z2", B2, 452, 324, "medium", "10.20.30.40",
       exposure=("gnss",)),
    _a("WIFI-AP-MNT", "Maintenance wireless access point", "wireless_ap", "3", "Z2", B2, 454, 326, "medium",
       "10.20.30.50", exposure=("wireless",)),
    # Level 2: control network switches
    _a("SW-CORE-A", "Core switch A", "switch", "2", "Z2", B2, 430, 310, "high", "10.20.30.2"),
    _a("SW-CORE-B", "Core switch B", "switch", "2", "Z2", B2, 432, 310, "high", "10.20.30.3"),
    _a("SW-GH", "Generation hall switch", "switch", "2", "Z3", B3, 420, 570, "high", "10.20.40.2"),
    _a("SW-SWY", "Switchyard switch", "switch", "2", "Z4", B4, 790, 230, "high", "10.20.40.3"),
    _a("SW-BESS", "Battery yard switch", "switch", "2", "Z5", "B5 Power conversion", 130, 600, "medium", "10.20.40.4"),
    # Level 1: controllers
    _a("PLC-GT1", "Gas turbine 1 controller", "plc", "1", "Z3", B3, 405, 570, "critical", "10.20.40.11",
       exposure=("physical_access",), protocols=("Modbus/TCP",), vendor="Voltek", model="TC-900", fw="2.4.0"),
    _a("PLC-GT2", "Gas turbine 2 controller", "plc", "1", "Z3", B3, 435, 570, "critical", "10.20.40.12",
       exposure=("physical_access",), protocols=("Modbus/TCP",), vendor="Voltek", model="TC-900", fw="2.4.0"),
    _a("PLC-AUX", "Auxiliary systems controller", "plc", "1", "Z3", B3, 420, 585, "high", "10.20.40.13",
       exposure=("physical_access",), protocols=("Modbus/TCP",), vendor="Voltek", model="TC-500", fw="2.1.3"),
    _a("PLC-SW1", "Switchyard bay controller", "plc", "1", "Z4", B4, 785, 232, "critical", "10.20.40.21",
       exposure=("physical_access",), protocols=("IEC 61850",), vendor="Voltek", model="BC-300", fw="1.9.2"),
    _a("RTU-SW1", "Switchyard RTU", "rtu", "1", "Z4", B4, 795, 232, "high", "10.20.40.22",
       protocols=("IEC 60870-5-104",), vendor="Voltek", model="RT-120", fw="3.0.1"),
    _a("IED-PROT-01", "Protection relay 1", "ied", "1", "Z4", B4, 780, 228, "high", "10.20.40.23",
       protocols=("IEC 61850",)),
    _a("IED-PROT-02", "Protection relay 2", "ied", "1", "Z4", B4, 790, 228, "high", "10.20.40.24",
       protocols=("IEC 61850",)),
    _a("IED-PROT-03", "Protection relay 3", "ied", "1", "Z4", B4, 800, 228, "high", "10.20.40.25",
       protocols=("IEC 61850",)),
    _a("PLC-BESS1", "Battery storage controller", "plc", "1", "Z5", "B5 Power conversion", 128, 600, "high",
       "10.20.40.31", protocols=("Modbus/TCP",), vendor="Voltek", model="TC-300", fw="1.4.0"),
    _a("BMS-GW", "Battery management gateway", "gateway", "1", "Z5", "B5 Power conversion", 132, 600, "medium",
       "10.20.40.32"),
    _a("PLC-GAS1", "Fuel gas station controller", "plc", "1", "Z6", "B6 Gas pressure reduction", 800, 500, "high",
       "10.20.40.41", protocols=("Modbus/TCP",), vendor="Voltek", model="TC-300", fw="1.4.0"),
    # Communication nodes
    _a("GW-104", "IEC 60870-5-104 gateway", "gateway", "2", "Z4", B4, 792, 236, "high", "10.20.60.10",
       exposure=("wireless",), protocols=("IEC 60870-5-104",), notes="Telecontrol link to the grid dispatcher"),
    _a("RTR-WAN", "WAN router", "router", "3", "Z6", "B7 Telecom shelter", 940, 660, "high", "10.20.60.1",
       exposure=("wireless",), notes="Microwave link and 4G backup"),
    _a("SH-N", "Mast sensor hub", "gateway", "0", "Z6", "B7 Telecom shelter", 942, 660, "medium", "10.20.50.5",
       exposure=("wireless",)),
    _a("SENS-GW-01", "Sensor ingest gateway", "gateway", "3", "Z2", B2, 428, 322, "high", "10.20.50.1",
       exposure=("wireless",)),
    # Physical sensors
    _a("RAD-01", "Surveillance radar", "sensor", "0", "Z2", B2, 425, 335, "high", "10.20.50.11",
       notes="Small-target radar, 360 degrees, 1500 m"),
    _a("RF-01", "RF detector NW", "sensor", "0", "Z5", "Corner NW", 20, 680, "medium", "10.20.50.21"),
    _a("RF-02", "RF detector NE (mast)", "sensor", "0", "Z6", "B7 mast", 940, 660, "medium", "10.20.50.22"),
    _a("RF-03", "RF detector SW (gate)", "sensor", "0", "Z1", "Corner SW", 30, 30, "medium", "10.20.50.23"),
    _a("RF-04", "RF detector SE", "sensor", "0", "Z0", "Corner SE", 980, 30, "medium", "10.20.50.24"),
    _a("EO-01", "EO/IR camera (generation hall)", "sensor", "0", "Z3", B3, 420, 600, "medium", "10.20.50.31"),
    _a("EO-02", "EO/IR camera (switchyard)", "sensor", "0", "Z4", B4, 800, 240, "medium", "10.20.50.32"),
    _a("AC-01", "Acoustic array", "sensor", "0", "Z4", "Switchyard", 850, 300, "low", "10.20.50.41"),
    _a("FOS-N", "Fence vibration sensing north", "sensor", "0", "Z0", "Perimeter N", 500, 700, "medium", "10.20.50.51"),
    _a("FOS-E", "Fence vibration sensing east", "sensor", "0", "Z0", "Perimeter E", 1000, 350, "medium", "10.20.50.52"),
    _a("FOS-S", "Fence vibration sensing south", "sensor", "0", "Z0", "Perimeter S", 500, 0, "medium", "10.20.50.53"),
    _a("FOS-W", "Fence vibration sensing west", "sensor", "0", "Z0", "Perimeter W", 0, 350, "medium", "10.20.50.54"),
    _a("ACR-B0", "Door reader B0", "sensor", "0", "Z1", "B0 Gatehouse", 230, 20, "low", "10.20.50.61"),
    _a("ACR-B1", "Door reader B1", "sensor", "0", "Z1", B1, 90, 130, "low", "10.20.50.62"),
    _a("ACR-B2", "Door reader B2", "sensor", "0", "Z2", B2, 440, 320, "medium", "10.20.50.63"),
    _a("ACR-B3", "Door reader B3", "sensor", "0", "Z3", B3, 420, 570, "medium", "10.20.50.64"),
    _a("ACR-B4", "Door reader B4", "sensor", "0", "Z4", B4, 790, 230, "medium", "10.20.50.65"),
    _a("WX-01", "Weather station", "sensor", "0", "Z2", B2, 450, 300, "low", "10.20.50.71"),
]

# (source, target, relation, protocol, note)
RELATIONS: list[tuple[str, str, str, str, str]] = [
    ("JUMP-01", "SCADA-SRV-01", "remote_access", "RDP/SSH", "Administrative access"),
    ("WIFI-AP-MNT", "HMI-03", "wireless_link", "Wi-Fi", "Maintenance tablets"),
    ("HMI-01", "SCADA-SRV-01", "operator_session", "OPC UA", ""),
    ("HMI-02", "SCADA-SRV-01", "operator_session", "OPC UA", ""),
    ("HMI-03", "SCADA-SRV-01", "operator_session", "OPC UA", ""),
    ("SCADA-SRV-01", "SCADA-SRV-02", "replication", "vendor", ""),
    ("SCADA-SRV-01", "PLC-GT1", "control", "Modbus/TCP", ""),
    ("SCADA-SRV-01", "PLC-GT2", "control", "Modbus/TCP", ""),
    ("SCADA-SRV-01", "PLC-AUX", "control", "Modbus/TCP", ""),
    ("SCADA-SRV-01", "PLC-SW1", "control", "IEC 61850", "via GW-104"),
    ("SCADA-SRV-01", "RTU-SW1", "control", "IEC 60870-5-104", "via GW-104"),
    ("SCADA-SRV-01", "PLC-BESS1", "control", "Modbus/TCP", "via BMS-GW"),
    ("SCADA-SRV-01", "PLC-GAS1", "control", "Modbus/TCP", ""),
    ("SCADA-SRV-01", "HIST-01", "data_flow", "vendor", ""),
    ("HIST-01", "HIST-DMZ", "data_flow", "vendor", ""),
    ("HIST-DMZ", "ARGUS-APP", "data_flow", "HTTPS", ""),
    ("SENS-GW-01", "ARGUS-APP", "data_flow", "HTTPS", "Sensor events"),
    ("RF-02", "SH-N", "data_flow", "Ethernet", ""),
    ("SH-N", "SENS-GW-01", "data_flow", "Ethernet", ""),
    *[("EWS-01", t, "engineering", "vendor engineering protocol", "")
      for t in ("PLC-GT1", "PLC-GT2", "PLC-AUX", "PLC-SW1", "RTU-SW1", "PLC-BESS1", "PLC-GAS1")],
    *[(s, "SENS-GW-01", "data_flow", "Ethernet", "")
      for s in ("RAD-01", "RF-01", "RF-03", "RF-04", "EO-01", "EO-02", "AC-01", "FOS-N", "FOS-E", "FOS-S", "FOS-W",
                "ACR-B0", "ACR-B1", "ACR-B2", "ACR-B3", "ACR-B4", "WX-01")],
]

# device scope per sensor family; every credential also gets ingest:heartbeat
SCOPE_BY_PREFIX = {
    "RAD": "ingest:radar", "RF": "ingest:rf", "EO": "ingest:eoir", "AC": "ingest:acoustic", "FOS": "ingest:fence",
    "ACR": "ingest:access", "WX": "ingest:weather",
}
GATEWAYS_WITH_CREDENTIALS = ("SENS-GW-01", "SH-N")

# Buildings and structures for the map (fictional footprints in site metres: x, y of the centre, width, depth).
BUILDINGS: list[dict[str, Any]] = [
    {"code": "B0", "name": "Gatehouse", "x": 230, "y": 20, "w": 12, "d": 8},
    {"code": "B1", "name": "Administration and SOC", "x": 90, "y": 130, "w": 60, "d": 30},
    {"code": "B2", "name": "Control building", "x": 440, "y": 320, "w": 50, "d": 30},
    {"code": "B3", "name": "Generation hall", "x": 420, "y": 570, "w": 80, "d": 40},
    {"code": "B4", "name": "Relay and control house", "x": 790, "y": 230, "w": 30, "d": 14},
    {"code": "T1", "name": "Transformer T1", "x": 730, "y": 150, "w": 10, "d": 8},
    {"code": "T2", "name": "Transformer T2", "x": 730, "y": 300, "w": 10, "d": 8},
    {"code": "C1", "name": "Battery container C1", "x": 70, "y": 500, "w": 12, "d": 3},
    {"code": "C2", "name": "Battery container C2", "x": 110, "y": 500, "w": 12, "d": 3},
    {"code": "C3", "name": "Battery container C3", "x": 150, "y": 500, "w": 12, "d": 3},
    {"code": "C4", "name": "Battery container C4", "x": 190, "y": 500, "w": 12, "d": 3},
    {"code": "B5", "name": "Power conversion and BMS", "x": 130, "y": 600, "w": 10, "d": 6},
    {"code": "B6", "name": "Gas pressure reduction", "x": 800, "y": 500, "w": 20, "d": 12},
    {"code": "B7", "name": "Telecom shelter and mast", "x": 940, "y": 660, "w": 8, "d": 8},
    {"code": "B8", "name": "Maintenance workshop", "x": 150, "y": 330, "w": 30, "d": 15},
]
GATES = [
    {"code": "G1", "name": "Main gate", "x": 150, "y": 0},
    {"code": "G2", "name": "Service gate", "x": 1000, "y": 200},
    {"code": "G3", "name": "Core turnstile", "x": 290, "y": 330},
]
