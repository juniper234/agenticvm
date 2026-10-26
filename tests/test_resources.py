import unittest
from unittest.mock import patch

from agenticvm.errors import AgenticVMError
from agenticvm.resources import check_memory_budget


class MemoryAdmissionTests(unittest.TestCase):
    def test_both_physical_and_commit_headroom_are_required(self):
        for physical, commit in ((767, 2048), (2048, 639)):
            with self.subTest(physical=physical, commit=commit), patch("agenticvm.resources.memory_status", return_value={
                "total_physical_mib": 4096, "available_physical_mib": physical, "available_commit_mib": commit
            }):
                with self.assertRaises(AgenticVMError) as caught:
                    check_memory_budget(256)
                self.assertEqual(caught.exception.code, "insufficient_host_memory")

    def test_a_4gb_host_is_not_rejected_based_on_total_ram_alone(self):
        with patch("agenticvm.resources.memory_status", return_value={
            "total_physical_mib": 4096, "available_physical_mib": 1024, "available_commit_mib": 1024
        }):
            result = check_memory_budget(256)
        self.assertEqual(result["required_available_commit_mib"], 640)
        self.assertEqual(result["required_available_physical_mib"], 768)


if __name__ == "__main__":
    unittest.main()
