"""Fictional vulnerability records for the demo site. Identifiers are DEMO-2026-NNNN: none is a real CVE,
and "Voltek" is an invented vendor. Published times are relative to the moment the demo data is created."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


def demo_records(now: datetime) -> list[dict[str, Any]]:
    def ago(**kw: float) -> str:
        return (now - timedelta(**kw)).isoformat()

    return [
        {
            "vuln_id": "DEMO-2026-0001", "severity": "critical", "cvss": 9.8, "kev": True, "fix_status": "none",
            "title": "Remote code execution in the Voltek SCADA Web Console (demo)",
            "description": "Fictional. An unauthenticated request to the web console of the SCADA server executes "
                           "code with the privileges of the service. Exploitation was observed shortly after "
                           "disclosure and the vendor has no fix yet.",
            "published_at": ago(hours=2),
            "affected": [{"vendor": "Voltek", "product": "SCADA Web Console", "cpe": "",
                          "versions": {"lt": "4.3.0"}}],
            "references": ["https://example.invalid/demo/DEMO-2026-0001"],
        },
        {
            "vuln_id": "DEMO-2026-0002", "severity": "high", "cvss": 8.1, "epss": 0.82, "fix_status": "none",
            "title": "Authentication bypass in the Voltek Historian service (demo)",
            "description": "Fictional. The historian accepts a crafted session token. No vendor fix is available.",
            "published_at": ago(days=10),
            "affected": [{"vendor": "Voltek", "product": "Historian", "cpe": "", "versions": {"lt": "3.9.0"}}],
        },
        {
            "vuln_id": "DEMO-2026-0003", "severity": "medium", "cvss": 6.5, "epss": 0.05, "fix_status": "available",
            "title": "Privilege escalation in PostgreSQL 16 before 16.14 (demo)",
            "description": "Fictional. A database role can escalate privileges. Fixed in 16.14.",
            "published_at": ago(days=30),
            "affected": [{"vendor": "postgresql", "product": "postgresql",
                          "cpe": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
                          "versions": {"gte": "16.0", "lt": "16.14"}}],
        },
        {
            "vuln_id": "DEMO-2026-0004", "severity": "high", "cvss": 7.5, "epss": 0.12, "fix_status": "available",
            "title": "Memory corruption in Voltek TC-900 controller firmware before 2.5.0 (demo)",
            "description": "Fictional. A crafted Modbus request corrupts memory. Fixed in firmware 2.5.0.",
            "published_at": ago(days=20),
            "affected": [{"vendor": "Voltek", "product": "TC-900", "cpe": "", "versions": {"lt": "2.5.0"}}],
        },
        {
            "vuln_id": "DEMO-2026-0005", "severity": "medium", "cvss": 5.3, "fix_status": "available",
            "title": "Information disclosure in Orion PrintServer (demo, not in the inventory)",
            "description": "Fictional. Used to show that products outside the inventory produce no finding.",
            "published_at": ago(days=3),
            "affected": [{"vendor": "Orion", "product": "PrintServer", "cpe": "", "versions": {"lt": "9.1"}}],
        },
        {
            "vuln_id": "DEMO-2026-0006", "severity": "high", "cvss": 8.8, "kev": True, "fix_status": "available",
            "title": "Remote service flaw in Windows Server 2019 (demo)",
            "description": "Fictional. Known to be exploited, but a vendor fix exists and the flaw is not new.",
            "published_at": ago(days=6),
            "affected": [{"vendor": "microsoft", "product": "windows_server_2019",
                          "cpe": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",
                          "versions": {"lte": "10.0.17763"}}],
        },
    ]
