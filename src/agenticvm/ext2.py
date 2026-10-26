"""Small deterministic ext2 image writer; never mounts or modifies a host disk.

Only regular files, directories and symlinks are supported. All allocations use
4 KiB blocks and standard ext2 direct/single/double indirect pointers. Metadata
is generated independently of Windows filesystem permissions and symlinks.
"""
from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
import stat
import struct
import uuid

BLOCK = 4096
BPG = BLOCK * 8
IPG = 2048
INODE_SIZE = 256


class Node:
    def __init__(self, mode, data=b"", uid=0, gid=0):
        self.mode, self.data, self.uid, self.gid = mode, data, uid, gid
        self.ino = 0
        self.blocks = []

    @property
    def size(self):
        return self.data.stat().st_size if isinstance(self.data, Path) else len(self.data)


def build_ext2(path: Path, nodes: dict[str, Node], *, size_mib=None, label="AGENTICVM_ROOT"):
    path = Path(path)
    if path.exists():
        raise FileExistsError("Refusing to overwrite an existing disk image: " + str(path))
    nodes = dict(nodes)
    nodes.setdefault("", Node(stat.S_IFDIR | 0o755))
    for name in list(nodes):
        if name.startswith("/") or ".." in name.split("/") or "." in name.split("/"):
            raise ValueError("Unsafe image path: " + name)
        for parent in Path(name).parents:
            key = parent.as_posix()
            if key != ".":
                nodes.setdefault(key, Node(stat.S_IFDIR | 0o755))
    estimated = sum(math.ceil(n.size / BLOCK) for n in nodes.values() if not stat.S_ISDIR(n.mode))
    estimated += len(nodes) * 2 + 2048
    groups = max(1, math.ceil(estimated / (BPG - 140)), math.ceil((len(nodes) + 10) / IPG))
    if size_mib is not None:
        groups = max(groups, math.ceil(size_mib / 128))
    total_blocks = groups * BPG
    inodes = groups * IPG
    gdt_blocks = math.ceil(groups * 32 / BLOCK)
    inode_blocks = IPG * INODE_SIZE // BLOCK
    metadata = 1 + gdt_blocks + 2 + inode_blocks
    if groups > BLOCK // 32:
        raise ValueError("Image exceeds the bounded one-block descriptor implementation")
    used_blocks = [set(range(metadata)) for _ in range(groups)]
    used_inodes = [set() for _ in range(groups)]
    for ino in range(1, 11):
        used_inodes[0].add(ino - 1)
    nodes[""].ino = 2
    next_ino = 11
    for name in sorted(nodes):
        if name:
            nodes[name].ino = next_ino
            used_inodes[(next_ino - 1) // IPG].add((next_ino - 1) % IPG)
            next_ino += 1
    children = {}
    for name, node in sorted(nodes.items()):
        if name:
            parent, _, basename = name.rpartition("/")
            children.setdefault(parent, []).append((basename, node))
    allocated = metadata

    def allocate():
        nonlocal allocated
        while allocated < total_blocks:
            group, local = divmod(allocated, BPG)
            if local < metadata:
                allocated = group * BPG + metadata
                continue
            value = allocated
            used_blocks[group].add(local)
            allocated += 1
            return value
        raise ValueError("Image has insufficient blocks")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x+b", buffering=1024 * 1024) as image:
        if os.name == "nt":
            # A sparse regular file avoids physically writing hundreds of MiB of
            # zeros. This acts only on the newly created owned file handle.
            import ctypes
            import msvcrt
            returned = ctypes.c_ulong()
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                              ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                              ctypes.c_void_p, ctypes.c_void_p]
            kernel.DeviceIoControl(msvcrt.get_osfhandle(image.fileno()), 0x000900c4,
                                   None, 0, None, 0, ctypes.byref(returned), None)
        image.truncate(total_blocks * BLOCK)

        def put(block, data):
            if image.tell() != block * BLOCK:
                image.seek(block * BLOCK)
            image.write(data)

        def directory(node_name):
            node = nodes[node_name]
            parent = nodes[node_name.rpartition("/")[0]] if node_name else node
            entries = [(".", node), ("..", parent)]
            entries += children.get(node_name, [])
            blocks, current = [], bytearray()
            previous = None
            for name, child in entries:
                encoded = name.encode("utf-8")
                needed = (8 + len(encoded) + 3) & ~3
                if needed > BLOCK:
                    raise ValueError("Directory filename exceeds block")
                if len(current) + needed > BLOCK:
                    struct.pack_into("<H", current, previous + 4, BLOCK - previous)
                    blocks.append(bytes(current).ljust(BLOCK, b"\0"))
                    current, previous = bytearray(), None
                previous = len(current)
                kind = 2 if stat.S_ISDIR(child.mode) else 7 if stat.S_ISLNK(child.mode) else 1
                current += struct.pack("<IHBB", child.ino, needed, len(encoded), kind) + encoded
                current += b"\0" * (needed - 8 - len(encoded))
            struct.pack_into("<H", current, previous + 4, BLOCK - previous)
            blocks.append(bytes(current).ljust(BLOCK, b"\0"))
            return b"".join(blocks)

        for name, node in sorted(nodes.items()):
            if stat.S_ISDIR(node.mode):
                node.data = directory(name)
            if stat.S_ISLNK(node.mode) and node.size < 60:
                continue
            if not (stat.S_ISREG(node.mode) or stat.S_ISDIR(node.mode) or stat.S_ISLNK(node.mode)):
                raise ValueError("Unsupported inode type: " + name)
            if isinstance(node.data, Path):
                with node.data.open("rb") as source:
                    while data := source.read(BLOCK):
                        block = allocate()
                        put(block, data)
                        node.blocks.append(block)
            else:
                for offset in range(0, len(node.data), BLOCK):
                    block = allocate()
                    put(block, node.data[offset:offset + BLOCK])
                    node.blocks.append(block)

        for name, node in sorted(nodes.items()):
            inode = bytearray(INODE_SIZE)
            links = 2 + sum(stat.S_ISDIR(child.mode) for _, child in children.get(name, [])) if stat.S_ISDIR(node.mode) else 1
            struct.pack_into("<HHIIIIIHHI", inode, 0, node.mode, node.uid, node.size & 0xffffffff,
                             0, 0, 0, 0, node.gid, links, 0)
            pointers = list(node.blocks[:12])
            pointers += [0] * (15 - len(pointers))
            extras = 0
            rest = node.blocks[12:]
            if rest:
                table = allocate(); extras += 1
                put(table, struct.pack("<1024I", *(rest[:1024] + [0] * (1024 - len(rest[:1024])))))
                pointers[12] = table
                rest = rest[1024:]
            if rest:
                outer = []
                for offset in range(0, len(rest), 1024):
                    chunk = rest[offset:offset + 1024]
                    table = allocate(); extras += 1
                    put(table, struct.pack("<1024I", *(chunk + [0] * (1024 - len(chunk)))))
                    outer.append(table)
                if len(outer) > 1024:
                    raise ValueError("File needs unsupported triple indirect blocks")
                table = allocate(); extras += 1
                put(table, struct.pack("<1024I", *(outer + [0] * (1024 - len(outer)))))
                pointers[13] = table
            struct.pack_into("<I", inode, 28, (len(node.blocks) + extras) * (BLOCK // 512))
            if stat.S_ISLNK(node.mode) and node.size < 60:
                inode[40:40 + node.size] = node.data
            else:
                struct.pack_into("<15I", inode, 40, *pointers)
            group, local = divmod(node.ino - 1, IPG)
            start = (group * BPG + 3 + gdt_blocks) * BLOCK + local * INODE_SIZE
            if image.tell() != start:
                image.seek(start)
            image.write(inode)

        descriptors = bytearray(gdt_blocks * BLOCK)
        dirs = [0] * groups
        for node in nodes.values():
            if stat.S_ISDIR(node.mode):
                dirs[(node.ino - 1) // IPG] += 1
        for group in range(groups):
            first = group * BPG
            bb, ib, it = first + 1 + gdt_blocks, first + 2 + gdt_blocks, first + 3 + gdt_blocks
            struct.pack_into("<IIIHHH", descriptors, group * 32, bb, ib, it,
                             BPG - len(used_blocks[group]), IPG - len(used_inodes[group]), dirs[group])
            bitmap = bytearray(BLOCK)
            for bit in used_blocks[group]:
                bitmap[bit // 8] |= 1 << (bit % 8)
            put(bb, bitmap)
            bitmap = bytearray(b"\xff" * BLOCK)
            for bit in range(IPG):
                if bit not in used_inodes[group]:
                    bitmap[bit // 8] &= ~(1 << (bit % 8))
            put(ib, bitmap)
        sb = bytearray(1024)
        struct.pack_into("<13I", sb, 0, inodes, total_blocks, 0,
                         total_blocks - sum(map(len, used_blocks)), inodes - sum(map(len, used_inodes)),
                         0, 2, 2, BPG, BPG, IPG, 0, 0)
        struct.pack_into("<HHHHHH", sb, 52, 0, 0xffff, 0xef53, 1, 1, 0)
        struct.pack_into("<IIII", sb, 64, 0, 0, 0, 1)
        struct.pack_into("<IHHIII", sb, 84, 11, INODE_SIZE, 0, 0, 2, 0)
        sb[104:120] = uuid.UUID("a3f96874-1a64-4af5-bf41-5eb881ca8bc9").bytes
        sb[120:136] = label.encode("ascii")[:16].ljust(16, b"\0")
        for group in range(groups):
            copy = bytearray(sb)
            struct.pack_into("<H", copy, 90, group)
            image.seek(group * BPG * BLOCK + (1024 if group == 0 else 0))
            image.write(copy)
            put(group * BPG + 1, descriptors)
    return {"path": str(path), "bytes": total_blocks * BLOCK, "inodes": len(nodes),
            "groups": groups, "used_blocks": sum(map(len, used_blocks)), "label": label}


def create_empty_workspace_disk(destination: Path, size_mib=256):
    """Create a new disposable-owned file only; existing destinations are refused."""
    if not 64 <= size_mib <= 2048:
        raise ValueError("Workspace size must be 64..2048 MiB")
    return build_ext2(Path(destination), {"": Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)},
                      size_mib=size_mib, label="AGENTICVM_DATA")


def read_image_file(image_path: Path, guest_path: str, maximum=4 * 1024 * 1024):
    """Independently read a bounded regular file from an image for build checks.

    This does not follow symlinks and supports the same standard ext2 pointer
    levels as the writer. It is never used to mount or execute guest content.
    """
    parts = guest_path.strip("/").split("/")
    if not all(part and part not in (".", "..") for part in parts):
        raise ValueError("An explicit safe guest file path is required")
    with Path(image_path).open("rb") as image:
        image.seek(1024); sb = image.read(1024)
        if struct.unpack_from("<H", sb, 56)[0] != 0xef53 or struct.unpack_from("<I", sb, 24)[0] != 2:
            raise ValueError("Expected a 4 KiB ext2 image")
        ipg = struct.unpack_from("<I", sb, 40)[0]
        inode_size = struct.unpack_from("<H", sb, 88)[0]
        def inode(number):
            group, local = divmod(number - 1, ipg)
            image.seek(BLOCK + group * 32 + 8)
            table = struct.unpack("<I", image.read(4))[0]
            image.seek(table * BLOCK + local * inode_size)
            return image.read(inode_size)
        def contents(info):
            length = struct.unpack_from("<I", info, 4)[0]
            if length > maximum:
                raise ValueError("Image file exceeds verification bound")
            pointers = struct.unpack_from("<15I", info, 40)
            blocks = list(pointers[:12])
            if pointers[12]:
                image.seek(pointers[12] * BLOCK)
                blocks += struct.unpack("<1024I", image.read(BLOCK))
            if pointers[13]:
                image.seek(pointers[13] * BLOCK)
                outer = struct.unpack("<1024I", image.read(BLOCK))
                for table in outer:
                    if not table:
                        break
                    image.seek(table * BLOCK)
                    blocks += struct.unpack("<1024I", image.read(BLOCK))
            result = bytearray()
            for block in blocks[:math.ceil(length / BLOCK)]:
                if block:
                    image.seek(block * BLOCK); result += image.read(BLOCK)
                else:
                    result += b"\0" * BLOCK
            return bytes(result[:length])
        current = inode(2)
        for part in parts:
            if not stat.S_ISDIR(struct.unpack_from("<H", current)[0]):
                raise ValueError("Guest path crosses a non-directory")
            data, offset, found = contents(current), 0, None
            while offset + 8 <= len(data):
                number, record, name_length, kind = struct.unpack_from("<IHBB", data, offset)
                if record < 8 or record % 4 or offset + record > len(data):
                    raise ValueError("Malformed ext2 directory record")
                if number and data[offset + 8:offset + 8 + name_length].decode("utf-8") == part:
                    found = number; break
                offset += record
            if found is None:
                raise FileNotFoundError(guest_path)
            current = inode(found)
        if not stat.S_ISREG(struct.unpack_from("<H", current)[0]):
            raise ValueError("Guest verification target is not a regular file")
        return contents(current)


if __name__ == "__main__":
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--size-mib", type=int, default=256)
    args = parser.parse_args()
    print(json.dumps(create_empty_workspace_disk(args.workspace, args.size_mib)))
