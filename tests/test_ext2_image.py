"""Filesystem image regressions discovered by independent guest/archive checks."""
from pathlib import Path
import stat
import tempfile
import unittest

from agenticvm.ext2 import Node, build_ext2, read_image_file


class Ext2ImageTests(unittest.TestCase):
    def test_tar_root_dot_cannot_become_a_duplicate_directory_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "root.ext2"
            with self.assertRaises(ValueError):
                build_ext2(output, {".": Node(stat.S_IFDIR | 0o755)})
            self.assertFalse(output.exists())

    def test_nested_dot_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                build_ext2(Path(directory) / "root.ext2",
                           {"usr/./bin": Node(stat.S_IFDIR | 0o755)})

    def test_nested_files_survive_directory_index_optimization(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "root.ext2"
            build_ext2(output, {"a/one.txt": Node(stat.S_IFREG | 0o644, b"one"),
                                "a/nested/two.txt": Node(stat.S_IFREG | 0o644, b"two"),
                                "b/three.txt": Node(stat.S_IFREG | 0o644, b"three")})
            for name, value in (("a/one.txt", b"one"), ("a/nested/two.txt", b"two"),
                                ("b/three.txt", b"three")):
                self.assertEqual(read_image_file(output, name), value)


if __name__ == "__main__":
    unittest.main()
