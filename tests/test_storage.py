from pathlib import Path
import tempfile
import unittest

from agenticvm.errors import AgenticVMError
from agenticvm.state import StateStore
from agenticvm.storage import ensure_workspace_disk


class WorkspaceStorageTests(unittest.TestCase):
    def test_existing_workspace_is_reused_without_reformatting(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = StateStore(Path(temporary))
            path = ensure_workspace_disk(store, size_mib=128)
            with path.open("r+b") as stream:
                stream.seek(100 * 1024 * 1024)
                stream.write(b"user-data-must-survive")
            self.assertEqual(ensure_workspace_disk(store), path)
            with path.open("rb") as stream:
                stream.seek(100 * 1024 * 1024)
                self.assertEqual(stream.read(22), b"user-data-must-survive")

    def test_unknown_existing_file_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = StateStore(Path(temporary))
            path = store.root / "data/default.ext2"
            path.parent.mkdir()
            path.write_bytes(b"unrelated-file")
            with self.assertRaises(AgenticVMError) as caught:
                ensure_workspace_disk(store)
            self.assertEqual(caught.exception.code, "invalid_storage")
            self.assertEqual(path.read_bytes(), b"unrelated-file")


if __name__ == "__main__":
    unittest.main()
