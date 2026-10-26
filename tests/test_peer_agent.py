"""Confinement of local peer checkpoint and summary output paths."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

from agenticvm import peer_protocol

sys.modules.setdefault("peer_protocol", peer_protocol)
_spec = importlib.util.spec_from_file_location("guest_peer_agent", Path(__file__).resolve().parents[1] / "guest" / "peer_agent.py")
_guest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_guest)


class PeerOutputTests(unittest.TestCase):
    def test_path_must_resolve_below_exact_directory_without_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "peer"
            root.mkdir()
            self.assertEqual(_guest.peer_path(str(root / "summary.json"), root), root.resolve() / "summary.json")
            for path in (root / ".." / "outside.json", Path(directory) / "peer-other" / "summary.json",
                         Path("relative.json"), root, root / "missing" / "summary.json"):
                with self.subTest(path=path), self.assertRaises(peer_protocol.PeerError):
                    _guest.peer_path(str(path), root)

    def test_existing_file_and_parent_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "peer"
            root.mkdir()
            outside = Path(directory) / "outside.json"
            outside.write_text("preserve", encoding="ascii")
            link = root / "evidence.jsonl"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as error:
                self.skipTest("OS does not permit symbolic links: " + str(error))
            with self.assertRaises(peer_protocol.PeerError):
                _guest.peer_path(str(link), root)
            link.unlink()
            target = root / "real"
            target.mkdir()
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(peer_protocol.PeerError):
                _guest.peer_path(str(link / "new.json"), root)
            self.assertEqual(outside.read_text(encoding="ascii"), "preserve")
