"""Offline tests: no internet needed. Run from project folder:  python -m unittest tests.test_checks -v"""
import sys, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import checks  # noqa: E402


def pypi(age_days=2000, releases=50, repo="https://github.com/x/y", dl=5_000_000, latest="9.9.9", versions=None):
    return {"exists": True, "latest_version": latest, "versions": versions or [latest, "2.31.0", "1.24.1", "2.32.0"],
            "release_count": releases, "age_days": age_days, "repo_url": repo, "summary": "", "monthly_downloads": dl}


def run(name, version, pypi_data, osv=None):
    osv = osv or {"vuln_ids": [], "vuln_summaries": [], "malware_ids": []}
    with patch.object(checks, "fetch_pypi", return_value=pypi_data), patch.object(checks, "fetch_osv", return_value=osv):
        return checks.check_package(name, version)


class Parse(unittest.TestCase):
    def test_parse(self):
        txt = "requests==2.32.0\nflask>=2.0  # web\n-r other.txt\nPyYAML[extra]==6.0; python_version>'3'\n\nnumpy\n"
        self.assertEqual(checks.parse_requirements(txt),
                         [("requests", "2.32.0"), ("flask", "latest"), ("PyYAML", "6.0"), ("numpy", "latest")])


class Similarity(unittest.TestCase):
    def test_typosquats(self):
        for bad, good in [("reqeusts", "requests"), ("reqests", "requests"), ("numpyy", "numpy"), ("pandsa", "pandas")]:
            self.assertEqual(checks.similar_popular(bad)["looks_like"], good, bad)

    def test_popular_not_flagged(self):
        for ok in ["requests", "numpy", "Flask", "python_dateutil", "boto3"]:
            self.assertIsNone(checks.similar_popular(ok), ok)


class Verdicts(unittest.TestCase):
    def test_missing_is_danger_high(self):
        r = run("pgtools-autofix-helper-9137", "1.0.0", {"exists": False})
        self.assertEqual((r.verdict, r.confidence), ("Danger", "High"))

    def test_malware_is_danger_high(self):
        r = run("evil", "1.0", pypi(), {"vuln_ids": [], "vuln_summaries": [], "malware_ids": ["MAL-2024-1"]})
        self.assertEqual((r.verdict, r.confidence), ("Danger", "High"))

    def test_young_typosquat_is_danger_medium(self):
        r = run("reqeusts", "2.31.0", pypi(age_days=20, releases=1, repo=None, dl=50, versions=["2.31.0"]))
        self.assertEqual((r.verdict, r.confidence, r.fix), ("Danger", "Medium", "requests"))

    def test_cve_is_caution_high(self):
        r = run("urllib3", "1.24.1", pypi(), {"vuln_ids": ["GHSA-1"], "vuln_summaries": ["bad"], "malware_ids": []})
        self.assertEqual((r.verdict, r.confidence), ("Caution", "High"))
        self.assertEqual(r.fix, "urllib3==9.9.9")

    def test_popular_is_safe(self):
        r = run("requests", "2.32.0", pypi(versions=["2.32.0"]))
        self.assertEqual((r.verdict, r.confidence), ("Safe", "High"))

    def test_network_error_is_caution_low(self):
        with patch.object(checks, "fetch_pypi", side_effect=checks.NetworkError("down")):
            r = checks.check_package("requests", "2.32.0")
        self.assertEqual((r.verdict, r.confidence), ("Caution", "Low"))

    def test_overall(self):
        a, b = run("requests", "2.32.0", pypi(versions=["2.32.0"])), run("x", "1", {"exists": False})
        self.assertEqual(checks.overall_risk([a]), "Safe")
        self.assertEqual(checks.overall_risk([a, b]), "Danger")


if __name__ == "__main__":
    unittest.main()
