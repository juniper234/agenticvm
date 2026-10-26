"""Regression checks for Alpine's conditional desktop loader packages."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("desktop_packages", Path(__file__).resolve().parent.parent /
                                             "scripts/desktop-image-packages.py")
packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages)


class ConditionalPackages(unittest.TestCase):
    def test_loader_install_if_follows_ordinary_dependency(self):
        rows = [{"P": "desktop", "V": "1", "D": "so:libglycin-2.so.0"},
                {"P": "libglycin", "V": "2.1.5-r0", "p": "so:libglycin-2.so.0=0"},
                {"P": "glycin-svg", "V": "2.1.5-r0", "i": "libglycin~2.1.5", "D": "librsvg"},
                {"P": "librsvg", "V": "2.62.3-r0"}]
        self.assertEqual(set(packages.resolve(rows, ["desktop"])),
                         {"desktop", "libglycin", "glycin-svg", "librsvg"})

    def test_optional_documentation_does_not_install_without_feature(self):
        rows = [{"P": "desktop", "V": "1"},
                {"P": "desktop-doc", "V": "1", "i": "docs desktop=1"}]
        self.assertEqual(set(packages.resolve(rows, ["desktop"])), {"desktop"})

    def test_conditional_dependency_can_activate_another_conditional_package(self):
        rows = [{"P": "desktop", "V": "1"},
                {"P": "loader", "V": "1", "i": "desktop"},
                {"P": "loader-data", "V": "1", "i": "loader"}]
        self.assertEqual(set(packages.resolve(rows, ["desktop"])), {"desktop", "loader", "loader-data"})


if __name__ == "__main__":
    unittest.main()
