"""CLI shim for the packaged pure-Python ext2 writer."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
from agenticvm.ext2 import Node, build_ext2, create_empty_workspace_disk

if __name__ == '__main__':
    import argparse, json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--size-mib', type=int, default=256)
    args = parser.parse_args()
    print(json.dumps(create_empty_workspace_disk(args.workspace, args.size_mib)))
