"""Person 3: CycloneDX 1.5 JSON SBOM export (step 3)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from checks import normalize
from result_format import PackageResult

TOOL_VERSION = "0.3.0"


def _purl(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{normalize(name)}"
    return f"{base}@{version}" if version else base


def build_sbom(results: list[PackageResult]) -> dict:
    components, vulns, seen = [], [], set()
    for r in results:
        version = r.evidence.get("resolved_version")
        if version is None and r.version != "latest":
            version = r.version
        ref = _purl(r.name, version)
        if ref in seen:
            continue
        seen.add(ref)
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": normalize(r.name),
            "version": version or "unknown",
            "purl": ref,
            "properties": [
                {"name": "packageguard:verdict", "value": r.verdict},
                {"name": "packageguard:confidence", "value": r.confidence},
            ],
        })
        osv = r.evidence.get("osv", {})
        for vid in osv.get("malware_ids", []) + osv.get("vuln_ids", []):
            vulns.append({
                "id": vid,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
                "affects": [{"ref": ref}],
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "PackageGuard", "version": TOOL_VERSION}]},
        },
        "components": components,
        "vulnerabilities": vulns,
    }


def write_sbom(results: list[PackageResult], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(build_sbom(results), indent=2), encoding="utf-8")
    return path
