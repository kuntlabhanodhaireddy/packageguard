"""Offline tests for SBOM and the no-key fallback. Run: python -m unittest tests.test_step3 -v"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from result_format import PackageResult  # noqa: E402
from sbom import build_sbom  # noqa: E402
import agent  # noqa: E402

RESULTS = [
    PackageResult("requests", "2.32.0", "Safe", "High", ["No known advisories."],
                  {"resolved_version": "2.32.0", "osv": {"vuln_ids": [], "malware_ids": []}}),
    PackageResult("urllib3", "1.24.1", "Caution", "High", ["1 advisory"],
                  {"resolved_version": "1.24.1", "osv": {"vuln_ids": ["GHSA-1"], "malware_ids": []}}, "urllib3==2.2.0"),
    PackageResult("reqeusts", "2.31.0", "Danger", "Medium", ["Likely typosquat"], {}, "requests"),
    PackageResult("requests", "2.32.0", "Safe", "High", [], {"resolved_version": "2.32.0"}),
]


class Sbom(unittest.TestCase):
    def test_structure(self):
        bom = build_sbom(RESULTS)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertEqual(len(bom["components"]), 3)

    def test_components_have_purl_and_verdict(self):
        comp = build_sbom(RESULTS)["components"][0]
        self.assertEqual(comp["purl"], "pkg:pypi/requests@2.32.0")
        self.assertIn({"name": "packageguard:verdict", "value": "Safe"}, comp["properties"])

    def test_vulnerabilities_linked_to_component(self):
        vulns = build_sbom(RESULTS)["vulnerabilities"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["id"], "GHSA-1")
        self.assertEqual(vulns[0]["affects"][0]["ref"], "pkg:pypi/urllib3@1.24.1")


class Agent(unittest.TestCase):
    def test_no_key_falls_back_offline(self):
        old = os.environ.get("LLM_API_KEY")
        os.environ["LLM_API_KEY"] = ""
        try:
            expl, source = agent.explain_results(RESULTS)
        finally:
            if old is None:
                os.environ.pop("LLM_API_KEY", None)
            else:
                os.environ["LLM_API_KEY"] = old
        self.assertTrue(source.startswith("offline"))
        self.assertIn("Suggested fix: requests", expl["reqeusts"])
        self.assertEqual(set(expl), {"requests", "urllib3", "reqeusts"})


if __name__ == "__main__":
    unittest.main()