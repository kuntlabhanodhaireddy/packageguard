"""Human-friendly HTML report for a PackageGuard scan."""
from __future__ import annotations

from datetime import datetime
from html import escape

from sbom import summarize

STYLE = {
    "Danger":  {"bg": "#fde8ea", "fg": "#a61e2d", "icon": "&#10060;", "label": "Do not install"},
    "Caution": {"bg": "#fff4d6", "fg": "#8a6100", "icon": "&#9888;&#65039;", "label": "Review first"},
    "Safe":    {"bg": "#e3f5e8", "fg": "#1b6e3a", "icon": "&#9989;", "label": "OK to install"},
}

MEANING = {
    "Danger": "This package is likely fake or malicious. Installing it could run attacker code on your machine.",
    "Caution": "This package exists but has known security issues. Upgrade or pin a patched version.",
    "Safe": "No known problems found. This package looks established and clean.",
}

CSS = """
*{box-sizing:border-box}
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:24px;background:#f5f6f8;color:#1f2430}
.wrap{max-width:1000px;margin:auto}
h1{margin:0 0 4px;font-size:26px}
.sub{color:#666;font-size:13px;margin-bottom:18px}
.banner{padding:16px 20px;border-radius:10px;font-size:20px;font-weight:700;margin-bottom:16px}
.banner small{display:block;font-weight:400;font-size:14px;margin-top:4px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:22px}
.card{background:#fff;border-radius:10px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card b{display:block;font-size:28px}
.card span{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:18px;margin:26px 0 10px}
.pkg{background:#fff;border-radius:10px;padding:14px 16px;margin-bottom:10px;border-left:6px solid;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.pkg-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px}
.pkg-name{font-size:17px;font-weight:700}
.pkg-ver{color:#666;font-weight:400;font-size:14px}
.badge{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700}
.meaning{margin:8px 0 4px;font-size:14px}
ul{margin:6px 0 0 18px;padding:0;font-size:13px;color:#444}
.fix{margin-top:8px;padding:8px 10px;background:#eef4ff;border-radius:6px;font-size:13px}
.ai{margin-top:8px;padding:8px 10px;background:#f3eefc;border-radius:6px;font-size:13px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;font-size:13px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid #eee}
th{background:#fafafa}
a{color:#2459c7;text-decoration:none}
code{background:#f0f0f0;padding:1px 5px;border-radius:4px;font-size:12px}
.foot{margin-top:26px;font-size:12px;color:#777}
"""


def _badge(verdict: str) -> str:
    st = STYLE.get(verdict, STYLE["Caution"])
    return f'<span class="badge" style="background:{st["bg"]};color:{st["fg"]}">{st["icon"]} {escape(verdict)}</span>'


def build_html_report(results, sbom: dict, explain: dict | None = None, risk: str = "Safe") -> str:
    s = summarize(results)
    rs = STYLE.get(risk, STYLE["Caution"])
    explain = explain or {}
    parts = [
        f"<!doctype html><html><head><meta charset='utf-8'><title>PackageGuard Report</title>"
        f"<style>{CSS}</style></head><body><div class='wrap'>",
        "<h1>PackageGuard Report</h1>",
        f"<div class='sub'>Generated {datetime.now():%d %b %Y, %H:%M} &middot; "
        f"CycloneDX {escape(sbom['specVersion'])} &middot; {escape(sbom['serialNumber'])}</div>",
        f"<div class='banner' style='background:{rs['bg']};color:{rs['fg']}'>"
        f"{rs['icon']} Overall risk: {escape(risk.upper())}"
        f"<small>{s['danger']} dangerous, {s['caution']} need review, {s['safe']} safe "
        f"out of {s['total']} packages.</small></div>",
        "<div class='cards'>"
        f"<div class='card'><b>{s['total']}</b><span>Packages</span></div>"
        f"<div class='card'><b style='color:#a61e2d'>{s['danger']}</b><span>Danger</span></div>"
        f"<div class='card'><b style='color:#8a6100'>{s['caution']}</b><span>Caution</span></div>"
        f"<div class='card'><b style='color:#1b6e3a'>{s['safe']}</b><span>Safe</span></div>"
        f"<div class='card'><b>{s['vulnerabilities']}</b><span>Known vulns</span></div></div>",
        "<h2>What to do</h2>",
    ]

    order = {"Danger": 0, "Caution": 1, "Safe": 2}
    for r in sorted(results, key=lambda x: order.get(x.verdict, 3)):
        st = STYLE.get(r.verdict, STYLE["Caution"])
        parts.append(
            f"<div class='pkg' style='border-color:{st['fg']}'>"
            f"<div class='pkg-head'><div class='pkg-name'>{escape(r.name)} "
            f"<span class='pkg-ver'>{escape(str(r.version))}</span></div>"
            f"<div>{_badge(r.verdict)} <span class='pkg-ver'>confidence: {escape(str(r.confidence))}</span></div></div>"
            f"<div class='meaning'><b>{st['label']}.</b> {escape(MEANING.get(r.verdict, ''))}</div>"
        )
        if r.reasons:
            parts.append("<ul>" + "".join(f"<li>{escape(x)}</li>" for x in r.reasons) + "</ul>")
        if getattr(r, "fix", None):
            parts.append(f"<div class='fix'><b>Suggested fix:</b> {escape(r.fix)}</div>")
        if explain.get(r.name):
            parts.append(f"<div class='ai'><b>AI explanation:</b> {escape(explain[r.name])}</div>")
        parts.append("</div>")

    vulns = sbom.get("vulnerabilities", [])
    parts.append("<h2>Known vulnerabilities</h2>")
    if vulns:
        parts.append("<table><tr><th>ID</th><th>Affects</th><th>Type</th><th>Details</th></tr>")
        for v in vulns:
            kind = "Malware" if v.get("analysis", {}).get("state") == "exploitable" else "Vulnerability"
            url = escape(v["source"]["url"])
            parts.append(
                f"<tr><td><code>{escape(v['id'])}</code></td>"
                f"<td>{escape(v['affects'][0]['ref'])}</td><td>{kind}</td>"
                f"<td><a href='{url}' target='_blank' rel='noopener'>View on OSV</a></td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>No known vulnerabilities found.</p>")

    parts.append("<h2>SBOM components</h2><table><tr><th>Component</th><th>Version</th><th>Package URL</th><th>Verdict</th></tr>")
    for c in sbom.get("components", []):
        verdict = next((p["value"] for p in c.get("properties", []) if p["name"] == "packageguard:verdict"), "")
        parts.append(
            f"<tr><td>{escape(c['name'])}</td><td>{escape(c.get('version', 'n/a'))}</td>"
            f"<td><code>{escape(c['purl'])}</code></td><td>{_badge(verdict)}</td></tr>"
        )
    parts.append("</table>")
    parts.append("<div class='foot'>An SBOM (Software Bill of Materials) lists every component in your software, "
                 "like an ingredient label. Import the JSON file into tools such as Dependency-Track.</div>")
    parts.append("</div></body></html>")
    return "".join(parts)