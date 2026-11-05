"""Step 1 test: checks your GitHub token and one OSV.dev call.

Run from the project folder:  python scripts/check_setup.py
"""
import os

import requests
from dotenv import load_dotenv

load_dotenv()


def check_github() -> None:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        print("GitHub: FAIL - GITHUB_TOKEN is empty in .env")
        return
    try:
        r = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=15,
        )
    except requests.RequestException as err:
        print(f"GitHub: FAIL - network error: {err}")
        return
    if r.status_code == 200:
        print(f"GitHub: OK - token belongs to '{r.json().get('login')}'")
    else:
        print(f"GitHub: FAIL - HTTP {r.status_code}: {r.text[:150]}")


def check_osv(name: str = "requests", version: str = "2.19.1") -> None:
    body = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=body, timeout=15)
        r.raise_for_status()
    except requests.RequestException as err:
        print(f"OSV: FAIL - {err}")
        return
    vulns = r.json().get("vulns", [])
    print(f"OSV: OK - {name} {version} has {len(vulns)} advisories")
    for v in vulns[:3]:
        print(f"     {v.get('id')}: {v.get('summary', '')[:80]}")
    if not vulns:
        print("     A count of 0 still means the call worked. Try another old version.")


if __name__ == "__main__":
    check_github()
    check_osv()
