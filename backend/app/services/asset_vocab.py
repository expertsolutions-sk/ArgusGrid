"""Controlled vocabularies of the asset registry. One source for validation, the API and the client."""
from __future__ import annotations

# asset type -> category (device, communication node or endpoint; ARG-012)
TYPES: dict[str, str] = {
    "server": "endpoint",
    "workstation": "endpoint",
    "hmi": "endpoint",
    "time_server": "endpoint",
    "plc": "device",
    "rtu": "device",
    "ied": "device",
    "sensor": "device",
    "switch": "comm_node",
    "router": "comm_node",
    "firewall": "comm_node",
    "gateway": "comm_node",
    "wireless_ap": "comm_node",
}
CATEGORIES = ("device", "comm_node", "endpoint")
LEVELS = ("0", "1", "2", "3", "3.5", "4", "5")  # Purdue levels
CRITICALITY = ("low", "medium", "high", "critical")
STATUSES = ("planned", "active", "maintenance", "decommissioned")
EXPOSURE = ("wireless", "physical_access", "line_of_sight", "electromagnetic", "gnss")
RELATIONS = (
    "remote_access", "operator_session", "control", "engineering", "replication", "data_flow", "wireless_link",
)
# Only these types may hold a device credential and talk to the ingestion API.
INGEST_TYPES = ("sensor", "gateway")
SCOPES = (
    "ingest:heartbeat", "ingest:rf", "ingest:radar", "ingest:eoir", "ingest:acoustic", "ingest:fence",
    "ingest:access", "ingest:weather", "ingest:cyber",
)
# Allowed status transitions. A decommissioned asset is final (it can only be deleted).
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "planned": ("planned", "active", "decommissioned"),
    "active": ("active", "maintenance", "decommissioned"),
    "maintenance": ("maintenance", "active", "decommissioned"),
    "decommissioned": ("decommissioned",),
}
