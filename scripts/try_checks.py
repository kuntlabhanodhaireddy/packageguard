"""Step 2 live test: run the real checks on the demo file. Needs internet the FIRST time.
Responses are cached in cache/http_cache.json, so later runs (and PG_OFFLINE=1) work without Wi-Fi.

    python scripts/try_checks.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from checks import check_packages, overall_risk, parse_requirements  # noqa: E402

text = (Path(__file__).resolve().parent.parent / "demo" / "requirements.txt").read_text()
t0 = time.time()
results = check_packages(parse_requirements(text))
for r in results:
    print(f"{r.name:34} {r.version:8} {r.verdict:8} {r.confidence:7} {r.reasons[0] if r.reasons else ''}")
    print(f"{'':34} fix -> {r.fix}")
print(f"\nOverall: {overall_risk(results)}   ({time.time() - t0:.1f}s)")
