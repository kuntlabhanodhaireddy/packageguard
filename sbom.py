"""CycloneDX 1.5 JSON SBOM export."""
from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from checks import normalize
from result_format import PackageResult

TOOL_NAME = "PackageGuard"
TOOL_VERSION = "0.4.0"
ROOT_REF = "app-under-scan"


def _purl(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{normalize(name)}"
    return f"{base}@{version}" if version else base


def _resolve_version(r: PackageResult) -> str | None:
    version = r.evidence.get("resolved_version")
    if version is None and r.version not in (None, "latest"):
        version = r.version
    return version


def summarize(results: list[PackageResult]) -> dict:
    """Counts for the UI header."""
    verdicts = Counter(r.verdict for r in results)
    vuln_ids = set()
    for r in results:
        osv = r.evidence.get("osv", {})
        vuln_ids.update(osv.get("malware_ids", []))
        vuln_ids.update(osv.get("vuln_ids", []))
    return {
        "total": len(results),
        "danger": verdicts.get("Danger", 0),
        "caution": verdicts.get("Caution", 0),
        "safe": verdicts.get("Safe", 0),
        "vulnerabilities": len(vuln_ids),
    }


def build_sbom(results: list[PackageResult], source_name: str = "requirements.txt") -> dict:
    components, vulns, seen_refs, seen_vulns = [], [], set(), set()

    for r in results:
        version = _resolve_version(r)
        ref = _purl(r.name, version)
        if ref in seen_refs:
            continue
        seen_refs.add(ref)

        props = [
            {"name": "packageguard:verdict", "value": r.verdict},
            {"name": "packageguard:confidence", "value": r.confidence},
            {"name": "packageguard:reasons", "value": " | ".join(r.reasons)},
        ]
        if getattr(r, "fix", None):
            props.append({"name": "packageguard:suggested-fix", "value": r.fix})
        if r.verdict == "Danger" and any("404" in x or "slopsquatting" in x.lower() for x in r.reasons):
            props.append({"name": "packageguard:suspected-slopsquatting", "value": "true"})

        comp = {
            "type": "library",
            "bom-ref": ref,
            "name": normalize(r.name),
            "purl": ref,
            "scope": "required",
            "externalReferences": [
                {"type": "distribution", "url": f"https://pypi.org/project/{normalize(r.name)}/"}
            ],
            "properties": props,
        }
        if version:
            comp["version"] = version
        components.append(comp)

        osv = r.evidence.get("osv", {})
        for vid, is_malware in (
            [(v, True) for v in osv.get("malware_ids", [])]
            + [(v, False) for v in osv.get("vuln_ids", [])]
        ):
            if (vid, ref) in seen_vulns:
                continue
            seen_vulns.add((vid, ref))
            entry = {
                "id": vid,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
                "description": "Known malicious package" if is_malware else "Known vulnerability reported in OSV",
                "affects": [{"ref": ref}],
                "analysis": {"state": "exploitable" if is_malware else "in_triage"},
            }
            if is_malware:
                entry["ratings"] = [{"source": {"name": TOOL_NAME}, "severity": "critical", "method": "other"}]
            if getattr(r, "fix", None):
                entry["recommendation"] = r.fix
            vulns.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {"components": [{
                "type": "application", "name": TOOL_NAME, "version": TOOL_VERSION,
            }]},
            "component": {"type": "application", "bom-ref": ROOT_REF, "name": source_name},
            "properties": [
                {"name": "packageguard:scope", "value": "direct-dependencies-only"},
                {"name": "packageguard:summary", "value": json.dumps(summarize(results))},
            ],
        },
        "components": components,
        "dependencies": [{"ref": ROOT_REF, "dependsOn": [c["bom-ref"] for c in components]}],
        "vulnerabilities": vulns,
    }


def validate_sbom(sbom: dict) -> list[str]:
    """Light sanity checks. Returns a list of problems (empty = OK)."""
    problems = []
    refs = {c["bom-ref"] for c in sbom.get("components", [])}
    if sbom.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat is not CycloneDX")
    for v in sbom.get("vulnerabilities", []):
        for a in v.get("affects", []):
            if a["ref"] not in refs:
                problems.append(f"{v['id']} points at unknown component {a['ref']}")
    return problems


def write_sbom(results: list[PackageResult], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(build_sbom(results), indent=2), encoding="utf-8")
    return path