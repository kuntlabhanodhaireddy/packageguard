"""Person 1: core checks (STEP 2: real checks).

For each package we gather evidence from:
  1. PyPI registry  -> exists? age, release count, repo link, downloads
  2. Name similarity -> close to a popular package? (typosquat signal)
  3. OSV.dev        -> known vulnerabilities and MAL- malware reports
Simple rules then turn the evidence into Safe / Caution / Danger + confidence.
The LLM (step 3) only explains this evidence; it never decides facts.

Env switches:
  PG_OFFLINE=1  use only cached responses (cache/http_cache.json). For Wi-Fi failures.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests

from popular_packages import POPULAR_PYPI
from result_format import PackageResult

TIMEOUT = 15
CACHE_FILE = Path(__file__).parent / "cache" / "http_cache.json"
_cache_lock = threading.Lock()
_cache: dict | None = None


class NetworkError(Exception):
    """Raised when a registry/OSV call fails and there is no cached answer."""


# ----------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def normalize(name: str) -> str:
    """PEP 503 normalisation: Foo_Bar.baz -> foo-bar-baz."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Turn requirements.txt text into (name, version) pairs.

    Version is the pinned one for '==', otherwise 'latest'.
    Skips blanks, comments, options (-r, -e, --index-url) and URLs.
    """
    packages = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        pin = re.search(r"(?<![<>~!=])==\s*([^\s,]+)", rest)
        packages.append((name, pin.group(1) if pin else "latest"))
    return packages


# ----------------------------------------------------------------------------
# HTTP with a JSON disk cache (makes the demo repeatable and offline-safe)
# ----------------------------------------------------------------------------
def _load_cache() -> dict:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(CACHE_FILE.read_text())
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save_cache() -> None:
    CACHE_FILE.parent.mkdir(exist_ok=True)
    CACHE_FILE.write_text(json.dumps(_cache))


def _http(method: str, url: str, body: dict | None = None) -> tuple[int, dict | None]:
    """Return (status_code, json). Only 200 and 404 are treated as answers."""
    key = hashlib.sha1(f"{method} {url} {json.dumps(body, sort_keys=True)}".encode()).hexdigest()
    with _cache_lock:
        hit = _load_cache().get(key)
    if hit is not None:
        return hit["status"], hit["json"]
    if os.getenv("PG_OFFLINE") == "1":
        raise NetworkError(f"offline mode and no cached answer for {url}")

    last_err = None
    for _ in range(2):  # one retry
        try:
            r = requests.request(method, url, json=body, timeout=TIMEOUT)
            if r.status_code in (200, 404):
                data = r.json() if r.status_code == 200 else None
                with _cache_lock:
                    _load_cache()[key] = {"status": r.status_code, "json": data}
                    _save_cache()
                return r.status_code, data
            last_err = f"HTTP {r.status_code}"
        except (requests.RequestException, ValueError) as err:
            last_err = str(err)
    raise NetworkError(f"{url}: {last_err}")


# ----------------------------------------------------------------------------
# Evidence collectors
# ----------------------------------------------------------------------------
def fetch_pypi(name: str) -> dict:
    """Registry facts. exists=False means PyPI returned 404."""
    status, data = _http("GET", f"https://pypi.org/pypi/{normalize(name)}/json")
    if status == 404 or not data:
        return {"exists": False}

    info = data.get("info", {})
    releases = data.get("releases", {})
    uploads = [
        f["upload_time_iso_8601"]
        for files in releases.values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    age_days = None
    if uploads:
        first = min(datetime.fromisoformat(u.replace("Z", "+00:00")) for u in uploads)
        age_days = (datetime.now(timezone.utc) - first).days

    urls = info.get("project_urls") or {}
    repo = next(
        (u for u in list(urls.values()) + [info.get("home_page") or ""] if "github.com" in u or "gitlab.com" in u),
        None,
    )
    return {
        "exists": True,
        "latest_version": info.get("version"),
        "versions": list(releases.keys()),
        "release_count": len(releases),
        "age_days": age_days,
        "repo_url": repo,
        "summary": info.get("summary"),
        "monthly_downloads": fetch_downloads(name),
    }


def fetch_downloads(name: str) -> int | None:
    """Last-month downloads from pypistats.org. None if unavailable (never fails the scan)."""
    try:
        status, data = _http("GET", f"https://pypistats.org/api/packages/{normalize(name)}/recent")
        if status == 200 and data:
            return data["data"]["last_month"]
    except (NetworkError, KeyError, TypeError):
        pass
    return None


def fetch_osv(name: str, version: str | None) -> dict:
    """Known vulnerabilities (for this version) and malware reports (any version, MAL- ids)."""
    pkg = {"name": normalize(name), "ecosystem": "PyPI"}
    vulns = []
    if version:
        _, data = _http("POST", "https://api.osv.dev/v1/query", {"package": pkg, "version": version})
        vulns = (data or {}).get("vulns", [])
    _, anyver = _http("POST", "https://api.osv.dev/v1/query", {"package": pkg})
    malware = [v["id"] for v in (anyver or {}).get("vulns", []) if v.get("id", "").startswith("MAL-")]
    return {
        "vuln_ids": [v["id"] for v in vulns if not v["id"].startswith("MAL-")],
        "vuln_summaries": [v.get("summary", "") for v in vulns[:3]],
        "malware_ids": malware,
    }


def _osa_distance(a: str, b: str) -> int:
    """Edit distance where swapping two neighbouring letters costs 1 (reqeusts -> requests = 1)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def similar_popular(name: str) -> dict | None:
    """Closest popular package within a small edit distance, or None.

    A name that IS popular is never a typosquat of itself.
    """
    n = normalize(name)
    if n in POPULAR_PYPI or len(n) < 4:
        return None
    limit = 1 if len(n) <= 6 else 2
    best = min(((_osa_distance(n, p), p) for p in POPULAR_PYPI), default=None)
    if best and best[0] <= limit:
        return {"looks_like": best[1], "distance": best[0]}
    return None


# ----------------------------------------------------------------------------
# Rules: evidence -> verdict
# ----------------------------------------------------------------------------
def check_package(name: str, version: str = "latest") -> PackageResult:
    """Run all checks for one package and return a PackageResult in the shared format."""
    evidence: dict = {"ecosystem": "PyPI"}
    try:
        pypi = fetch_pypi(name)
        evidence["pypi"] = pypi
        sim = similar_popular(name)
        if sim:
            evidence["similar_to"] = sim

        # --- Hard evidence ---------------------------------------------------
        if not pypi["exists"]:
            reasons = ["Package does not exist on PyPI (404). Possibly an AI-invented name: slopsquatting risk."]
            fix = None
            if sim:
                reasons.append(f"Name is close to popular package '{sim['looks_like']}'.")
                fix = sim["looks_like"]
            return PackageResult(name, version, "Danger", "High", reasons, evidence, fix)

        resolved = pypi["latest_version"] if version == "latest" else version
        evidence["resolved_version"] = resolved
        osv = fetch_osv(name, resolved)
        evidence["osv"] = osv

        if osv["malware_ids"]:
            reasons = [f"OSV malware report(s): {', '.join(osv['malware_ids'][:3])}."]
            fix = sim["looks_like"] if sim else None
            return PackageResult(name, version, "Danger", "High", reasons, evidence, fix)

        # --- Soft signals ----------------------------------------------------
        age, dl, rel = pypi["age_days"], pypi["monthly_downloads"], pypi["release_count"]
        young = age is not None and age < 90
        low_dl = dl is not None and dl < 1000
        few_releases = rel <= 2
        no_repo = pypi["repo_url"] is None

        signals: list[str] = []
        # Similarity only counts when the package is much newer / less used than what it resembles.
        sim_counts = bool(sim) and ((age is not None and age < 365) or (dl is not None and dl < 100_000) or few_releases)
        if sim_counts:
            signals.append(f"Name is close to popular package '{sim['looks_like']}' (edit distance {sim['distance']}).")
        if young:
            signals.append(f"Brand-new package (first upload {age} days ago).")
        if low_dl:
            signals.append(f"Very few downloads last month ({dl}).")
        if few_releases:
            signals.append(f"Only {rel} release(s).")
        if no_repo:
            signals.append("No GitHub/GitLab link in package metadata.")
        evidence["soft_signals"] = signals

        # --- Verdict rules ---------------------------------------------------
        if resolved not in pypi["versions"]:
            return PackageResult(
                name, version, "Caution", "Medium",
                [f"Version {resolved} is not published on PyPI (latest is {pypi['latest_version']})."],
                evidence, f"{normalize(name)}=={pypi['latest_version']}",
            )

        if sim_counts and len(signals) >= 2:
            return PackageResult(
                name, version, "Danger", "Medium",
                ["Likely typosquat of '%s'." % sim["looks_like"]] + signals[1:],
                evidence, sim["looks_like"],
            )

        if osv["vuln_ids"]:
            fixed = pypi["latest_version"]
            reasons = [f"{len(osv['vuln_ids'])} known advisory(ies) for {resolved}: {', '.join(osv['vuln_ids'][:3])}."]
            reasons += [s for s in osv["vuln_summaries"][:1] if s]
            return PackageResult(name, version, "Caution", "High", reasons, evidence, f"{normalize(name)}=={fixed}")

        if sim_counts:  # one soft signal only
            return PackageResult(name, version, "Caution", "Low", signals, evidence, sim["looks_like"])

        if len(signals) >= 2 or (young and age < 30):
            return PackageResult(name, version, "Caution", "Medium" if len(signals) >= 2 else "Low", signals, evidence)

        reasons = ["Established package, no known advisories."] if age and age > 365 else ["No known advisories."]
        return PackageResult(name, version, "Safe", "Medium" if signals else "High", reasons + signals, evidence)

    except NetworkError as err:
        evidence["error"] = str(err)
        return PackageResult(name, version, "Caution", "Low", [f"Could not verify (network problem): {err}"], evidence)


def check_packages(packages: list[tuple[str, str]], on_result=None) -> list[PackageResult]:
    """Check many packages in parallel. on_result(result) fires as each one finishes (live log).

    Network work runs in worker threads, but on_result is called from the calling thread.
    Streamlit UI calls only work in the main thread, so this avoids NoSessionContext.
    Results are returned in the same order as the input.
    """
    results: dict[int, PackageResult] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(check_package, name, version): i
                   for i, (name, version) in enumerate(packages)}
        for future in as_completed(futures):
            res = future.result()
            results[futures[future]] = res
            if on_result:
                on_result(res)
    return [results[i] for i in range(len(packages))]


def overall_risk(results: list[PackageResult]) -> str:
    """Worst verdict wins."""
    verdicts = {r.verdict for r in results}
    return "Danger" if "Danger" in verdicts else "Caution" if "Caution" in verdicts else "Safe"
