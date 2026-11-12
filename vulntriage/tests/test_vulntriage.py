import csv
import tempfile
import unittest
from pathlib import Path

import vulntriage as vt


class TestScoring(unittest.TestCase):
    def test_exploit_and_exposure_raise_score(self):
        base = vt.calculate_score(7.0, False, False, "medium")
        self.assertGreater(vt.calculate_score(7.0, True, False, "medium"), base)
        self.assertGreater(vt.calculate_score(7.0, False, True, "medium"), base)

    def test_score_bounds(self):
        self.assertEqual(vt.calculate_score(10.0, True, True, "critical"), 100.0)
        self.assertEqual(vt.calculate_score(0.0, False, False, "low"), 0.0)

    def test_criticality_changes_ranking(self):
        self.assertGreater(vt.calculate_score(6.0, False, False, "critical"),
                           vt.calculate_score(6.0, False, False, "low"))

    def test_context_beats_raw_cvss(self):
        """A 7.5 exposed, exploitable vuln must outrank an isolated 9.8 with no exploit."""
        exposed = vt.calculate_score(7.5, True, True, "high")
        isolated = vt.calculate_score(9.8, False, False, "low")
        self.assertGreater(exposed, isolated)

    def test_invalid_cvss(self):
        with self.assertRaises(ValueError):
            vt.calculate_score(11, False, False, "low")

    def test_priority_buckets(self):
        self.assertEqual(vt.assign_priority(95), ("P1", 3))
        self.assertEqual(vt.assign_priority(70), ("P2", 14))
        self.assertEqual(vt.assign_priority(45), ("P3", 30))
        self.assertEqual(vt.assign_priority(10), ("P4", 90))


class TestLoad(unittest.TestCase):
    def _write(self, rows, header):
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
        f.close()
        return Path(f.name)

    def test_sorted_by_score(self):
        p = self._write([["a", "CVE-1", "x", "5.0", "no", "no", "low"],
                         ["b", "CVE-2", "y", "9.0", "yes", "yes", "critical"]],
                        ["host", "cve", "title", "cvss", "exploit_available", "internet_facing", "asset_criticality"])
        v = vt.load(p)
        self.assertEqual(v[0].host, "b")

    def test_missing_columns(self):
        p = self._write([["a"]], ["host"])
        with self.assertRaises(ValueError):
            vt.load(p)

    def test_bad_row_skipped(self):
        p = self._write([["a", "CVE-1", "x", "notanumber", "", "", ""],
                         ["b", "CVE-2", "y", "6.0", "", "", ""]],
                        ["host", "cve", "title", "cvss", "exploit_available", "internet_facing", "asset_criticality"])
        self.assertEqual(len(vt.load(p)), 1)

    def test_sample_file(self):
        sample = Path(__file__).parent.parent / "samples" / "scan.csv"
        vulns = vt.load(sample)
        self.assertGreater(len(vulns), 10)
        self.assertEqual(vulns[0].priority, "P1")
        self.assertGreater(len({v.priority for v in vulns}), 2, "scores should spread across priorities")


if __name__ == "__main__":
    unittest.main()
