"""Parsers of public vulnerability feeds into one normalised record.

Supported: CISA KEV (JSON), NVD CVE API 2.0 (JSON), FIRST EPSS (JSON API or CSV), CSAF 2.0 advisories (subset).
Every parser is pure (text or object in, records out) and tolerant: an unusable entry is skipped and counted.

Normalised record keys: vuln_id, title, description, severity, cvss, epss, kev, fix_status, published_at,
affected, references. Keys a source does not know are absent, so merging never erases information.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$")


class FeedError(ValueError):
    """The content is not in the expected format."""


def _iso(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if len(text) == 10:  # a plain date (KEV dateAdded)
            return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat()
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def parse_cpe(cpe: str) -> dict[str, str]:
    """Split a CPE 2.3 formatted string: part, vendor, product, version."""
    pieces = cpe.split(":")
    if len(pieces) < 6 or pieces[0] != "cpe":
        return {}
    version = pieces[5]
    return {"part": pieces[2], "vendor": pieces[3], "product": pieces[4],
            "version": "" if version in ("*", "-") else version}


def _load(content: Any) -> Any:
    if isinstance(content, (bytes, bytearray)):
        raw = bytes(content)
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        content = raw.decode("utf-8-sig")
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise FeedError("not valid JSON") from exc
    return content


# -- CISA KEV ------------------------------------------------------------------------------------------
def parse_kev(content: Any) -> list[dict[str, Any]]:
    data = _load(content)
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise FeedError("missing 'vulnerabilities' list")
    out: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict) or not VULN_ID.match(str(it.get("cveID", ""))):
            continue
        action = str(it.get("requiredAction", ""))
        # KEV's required action tells whether a vendor fix exists. The generic phrase "discontinue use if
        # mitigations are unavailable" appears on most entries and does NOT mean that no fix exists.
        if re.search(r"end[- ]of[- ]life|no longer supported|unsupported|no (patch|fix|update)s? (is |are )?available",
                     action, re.IGNORECASE):
            fix = "none"
        elif re.search(r"apply (the )?(updates|patch)", action, re.IGNORECASE):
            fix = "available"
        elif re.search(r"apply (the )?mitigations|workaround", action, re.IGNORECASE):
            fix = "workaround"
        else:
            fix = "unknown"
        out.append({
            "vuln_id": str(it["cveID"]).upper(),
            "title": str(it.get("vulnerabilityName", ""))[:255],
            "description": str(it.get("shortDescription", "")),
            "kev": True,
            "fix_status": fix,
            "published_at": _iso(it.get("dateAdded")),
            "affected": [{"vendor": str(it.get("vendorProject", "")), "product": str(it.get("product", "")),
                          "cpe": "", "versions": {}}],
            "references": [],
        })
    return out


# -- NVD CVE API 2.0 -----------------------------------------------------------------------------------
def _nvd_affected(cve: dict[str, Any]) -> list[dict[str, Any]]:
    affected: list[dict[str, Any]] = []

    def walk(node: dict[str, Any]) -> None:
        if node.get("negate"):
            return
        for m in node.get("cpeMatch", []) or []:
            if not m.get("vulnerable", True):
                continue
            cpe = parse_cpe(str(m.get("criteria", "")))
            if not cpe or cpe["part"] not in ("a", "o", "h"):
                continue
            versions: dict[str, Any] = {}
            if m.get("versionStartIncluding"):
                versions["gte"] = m["versionStartIncluding"]
            if m.get("versionStartExcluding"):
                versions["gt"] = m["versionStartExcluding"]
            if m.get("versionEndIncluding"):
                versions["lte"] = m["versionEndIncluding"]
            if m.get("versionEndExcluding"):
                versions["lt"] = m["versionEndExcluding"]
            if not versions and cpe["version"]:
                versions["eq"] = [cpe["version"]]
            affected.append({"vendor": cpe["vendor"], "product": cpe["product"],
                             "cpe": str(m.get("criteria", "")), "versions": versions})

    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            walk(node)
    return affected


def parse_nvd(content: Any) -> list[dict[str, Any]]:
    data = _load(content)
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise FeedError("missing 'vulnerabilities' list")
    out: list[dict[str, Any]] = []
    for item in items:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not CVE.match(str(cve.get("id", ""))):
            continue
        description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        score: float | None = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = (cve.get("metrics") or {}).get(key) or []
            if metrics:
                value = (metrics[0].get("cvssData") or {}).get("baseScore")
                if isinstance(value, (int, float)):
                    score = float(value)
                    break
        status = str(cve.get("vulnStatus", ""))
        rec: dict[str, Any] = {
            "vuln_id": str(cve["id"]).upper(), "title": description[:120], "description": description,
            "cvss": score, "published_at": _iso(cve.get("published")),
            "affected": _nvd_affected(cve),
            "references": [r.get("url", "") for r in cve.get("references", []) if r.get("url")][:10],
        }
        sev = severity_from_cvss(score)
        if sev:
            rec["severity"] = sev
        if status.lower() == "rejected":
            continue
        if cve.get("cisaExploitAdd"):
            rec["kev"] = True
        out.append(rec)
    return out


# -- FIRST EPSS ----------------------------------------------------------------------------------------
def parse_epss(content: Any) -> list[dict[str, Any]]:
    """EPSS scores as `{"data": [{"cve": .., "epss": ..}]}` (API) or CSV with a `cve,epss,percentile` header."""
    if isinstance(content, (bytes, bytearray)):
        raw = bytes(content)
        content = (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode("utf-8-sig")
    rows: list[tuple[str, float]] = []
    if isinstance(content, dict) or (isinstance(content, str) and content.lstrip().startswith("{")):
        data = _load(content)
        for it in data.get("data", []) if isinstance(data, dict) else []:
            try:
                rows.append((str(it["cve"]).upper(), float(it["epss"])))
            except (KeyError, TypeError, ValueError):
                continue
    elif isinstance(content, str):
        lines = [ln for ln in content.splitlines() if ln and not ln.startswith("#")]
        for rec in csv.DictReader(io.StringIO("\n".join(lines))):
            try:
                rows.append((str(rec["cve"]).upper(), float(rec["epss"])))
            except (KeyError, TypeError, ValueError):
                continue
    else:
        raise FeedError("unsupported EPSS content")
    return [{"vuln_id": cve, "epss": min(1.0, max(0.0, score))} for cve, score in rows if CVE.match(cve)]


# -- CSAF 2.0 (subset) ---------------------------------------------------------------------------------
def parse_csaf(content: Any) -> list[dict[str, Any]]:
    """One record per CVE in `vulnerabilities`; products come from the product tree (name and CPE)."""
    data = _load(content)
    if not isinstance(data, dict) or "vulnerabilities" not in data:
        raise FeedError("not a CSAF document")
    tracking = (data.get("document") or {}).get("tracking") or {}
    published = _iso(tracking.get("initial_release_date"))
    advisory = str(tracking.get("id", ""))

    products: dict[str, dict[str, str]] = {}

    def collect(branch: dict[str, Any], vendor: str = "") -> None:
        category = branch.get("category")
        if category == "vendor":
            vendor = str(branch.get("name", ""))
        product = branch.get("product")
        if isinstance(product, dict) and product.get("product_id"):
            cpe = ((product.get("product_identification_helper") or {}).get("cpe")) or ""
            version = ""
            if category == "product_version":
                version = str(branch.get("name", ""))
            elif parse_cpe(cpe):
                version = parse_cpe(cpe)["version"]
            products[str(product["product_id"])] = {
                "name": str(product.get("name", "")), "cpe": cpe, "vendor": vendor, "version": version,
            }
        for child in branch.get("branches", []) or []:
            collect(child, vendor)

    tree = data.get("product_tree") or {}
    for branch in tree.get("branches", []) or []:
        collect(branch)
    for fp in tree.get("full_product_names", []) or []:
        products.setdefault(str(fp.get("product_id")), {
            "name": str(fp.get("name", "")),
            "cpe": ((fp.get("product_identification_helper") or {}).get("cpe")) or "",
            "vendor": "", "version": ""})

    out: list[dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []) or []:
        cve = str(vuln.get("cve", ""))
        if not CVE.match(cve) and not VULN_ID.match(cve):
            continue
        status = vuln.get("product_status") or {}
        affected_ids = (status.get("known_affected") or []) + (status.get("first_affected") or [])
        fixed_ids = (status.get("fixed") or []) + (status.get("first_fixed") or [])
        affected: list[dict[str, Any]] = []
        for pid in affected_ids:
            p = products.get(str(pid))
            if not p:
                continue
            c = parse_cpe(p["cpe"]) if p["cpe"] else {}
            affected.append({
                "vendor": c.get("vendor") or p["vendor"], "product": c.get("product") or p["name"],
                "cpe": p["cpe"], "versions": {"eq": [p["version"]]} if p["version"] else {},
            })
        remediations = {str(r.get("category")) for r in vuln.get("remediations", []) or []}
        if fixed_ids or "vendor_fix" in remediations:
            fix = "available"
        elif "workaround" in remediations or "mitigation" in remediations:
            fix = "workaround"
        elif "no_fix_planned" in remediations or "none_available" in remediations:
            fix = "none"
        else:
            fix = "unknown"
        score: float | None = None
        for sc in vuln.get("scores", []) or []:
            for key in ("cvss_v3", "cvss_v31", "cvss_v4"):
                base = (sc.get(key) or {}).get("baseScore")
                if isinstance(base, (int, float)):
                    score = float(base)
        rec: dict[str, Any] = {
            "vuln_id": cve.upper(), "title": str(vuln.get("title", advisory))[:255],
            "description": next((n.get("text", "") for n in vuln.get("notes", []) or []
                                if n.get("category") in ("description", "summary")), ""),
            "fix_status": fix, "published_at": published, "affected": affected,
            "references": [r.get("url", "") for r in vuln.get("references", []) or [] if r.get("url")][:10],
        }
        if score is not None:
            rec["cvss"] = score
            rec["severity"] = severity_from_cvss(score)
        out.append(rec)
    return out


PARSERS = {"kev": parse_kev, "nvd": parse_nvd, "epss": parse_epss, "csaf": parse_csaf}
