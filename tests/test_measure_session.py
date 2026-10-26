"""Memory reports must distinguish commit, working set and lifetime peaks."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("measure_session", Path(__file__).resolve().parent.parent / "scripts/measure-session.py")
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)
MIB = 1048576


class MeasurementReportTests(unittest.TestCase):
    def test_boot_peak_is_retained_without_double_counting_guest_ram(self):
        samples = []
        for seconds, commit, resident, cpu in ((0, 1200, 720, 20), (10, 1100, 700, 20.5)):
            samples.append({"elapsed_seconds": seconds, "private_commit_bytes": commit * MIB,
                            "working_set_bytes": resident * MIB, "peak_private_commit_bytes_lifetime": 1500 * MIB,
                            "peak_working_set_bytes_lifetime": 850 * MIB, "process_cpu_seconds_lifetime": cpu})
        result = measure.summarize({"memory_mib": 1024, "profile": "desktop", "uuid": "fixture"}, samples)
        self.assertEqual(result["peak_private_commit_mib_lifetime"], 1500)
        self.assertEqual(result["max_private_commit_mib_in_window"], 1200)
        self.assertEqual(result["peak_working_set_mib_lifetime"], 850)
        self.assertEqual(result["median_working_set_mib"], 710)
        self.assertEqual(result["median_private_commit_mib"], 1150)
        self.assertEqual(result["process_cpu_percent_one_core"], 5)
        self.assertFalse(result["physical_4gb_host_tested"])

    def test_missing_or_zero_length_sample_window_is_rejected(self):
        state = {"memory_mib": 1024, "uuid": "fixture"}
        with self.assertRaises(ValueError):
            measure.summarize(state, [])
        with self.assertRaises(ValueError):
            measure.summarize(state, [{"elapsed_seconds": 0}, {"elapsed_seconds": 0}])


if __name__ == "__main__":
    unittest.main()
