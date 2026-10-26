"""Managed guest data files; never format or mount a host device."""
from pathlib import Path
import struct

from .errors import AgenticVMError
from .state import StateStore, contained


def ensure_workspace_disk(store: StateStore, size_mib: int = 512) -> Path:
    with store.lock():
        folder = store.root / "data"
        target = folder / f"{store.session}.ext2"
        if folder.is_symlink() or target.is_symlink() or not contained(folder, store.root):
            raise AgenticVMError("Managed data path contains a link outside the workspace.", "invalid_storage")
        folder.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            from .ext2 import create_empty_workspace_disk
            create_empty_workspace_disk(target, size_mib=size_mib)
        if not target.is_file() or target.stat().st_size > 4 * 1024**3:
            raise AgenticVMError("Managed data image is missing or exceeds 4 GiB.", "invalid_storage")
        with target.open("rb") as stream:
            stream.seek(1024)
            header = stream.read(136)
        if len(header) != 136 or struct.unpack_from("<H", header, 56)[0] != 0xEF53 or header[120:136].rstrip(b"\0") != b"AGENTICVM_DATA":
            raise AgenticVMError("Existing data file is not an AgenticVM workspace. It was not modified.", "invalid_storage")
        return target
