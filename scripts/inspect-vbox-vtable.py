"""Bind shipped VMM API pointers to the matched source without executing a target.

This deliberately supports only the verified VirtualBox 7.2.20 x64 build and the
observed LEA-RIP/RET getter encoding. Unexpected bytes/layouts fail explicitly.
Memory is bounded by a 16 MiB input limit; no decompiler or VM is launched.
"""

import hashlib
import json
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "vendor/virtualbox-7.2.20"


def main():
    target = BASE / "windows-amd64/VBoxVMM.dll"
    if target.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Target exceeds byte-inspection budget")
    data = target.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != "e9d7cfbbef6c48d4a6e98c16b81c4c962ab857740079b6146798335a03ea6c57":
        raise ValueError("Target differs from the verified release")

    def read(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError("Field outside file")
        return struct.unpack_from(fmt, data, offset)

    pe = read("<I", 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Not PE")
    if read("<H", pe + 4)[0] != 0x8664:
        raise ValueError("Not x64")
    count = read("<H", pe + 6)[0]
    optional = pe + 24
    if read("<H", optional)[0] != 0x20B:
        raise ValueError("Not PE32+")
    image_base = read("<Q", optional + 24)[0]
    section_start = optional + read("<H", pe + 20)[0]
    sections = []
    for index in range(count):
        offset = section_start + index * 40
        _, rva, size, raw = read("<IIII", offset + 8)
        flags = read("<I", offset + 36)[0]
        sections.append((rva, size, raw, flags))

    def file_offset(rva, size=1):
        candidates = [raw + rva - start for start, length, raw, _ in sections
                      if start <= rva and rva + size <= start + length]
        if len(candidates) != 1 or candidates[0] + size > len(data):
            raise ValueError(f"No unique file-backed mapping for {rva:#x}")
        return candidates[0]

    def ascii_string(rva):
        offset = file_offset(rva)
        end = data.find(b"\0", offset, min(offset + 1024, len(data)))
        if end == -1:
            raise ValueError("Unterminated string")
        file_offset(rva, end - offset + 1)
        return data[offset:end].decode("ascii")

    exports_rva, exports_size = read("<II", optional + 112)
    table = file_offset(exports_rva, 40)
    function_count, name_count, functions, names, ordinals = read("<IIIII", table + 20)
    exported = {}
    if function_count > 65536 or name_count > 65536:
        raise ValueError("Excessive export table")
    for index in range(name_count):
        name_rva = read("<I", file_offset(names + index * 4, 4))[0]
        ordinal = read("<H", file_offset(ordinals + index * 2, 2))[0]
        if ordinal >= function_count:
            raise ValueError("Export ordinal outside table")
        function_rva = read("<I", file_offset(functions + ordinal * 4, 4))[0]
        exported[ascii_string(name_rva)] = function_rva
    getter_rva = exported["VMMR3GetVTable"]
    if exports_rva <= getter_rva < exports_rva + exports_size:
        raise ValueError("Forwarded getter unsupported")
    getter_offset = file_offset(getter_rva, 8)
    code = data[getter_offset:getter_offset + 8]
    if code[:3] != bytes.fromhex("48 8d 05") or code[7] != 0xC3:
        raise ValueError(f"Unexpected getter encoding: {code.hex()}")
    vtable_rva = getter_rva + 7 + struct.unpack_from("<i", code, 3)[0]
    source_file = BASE / "source/include/VBox/vmm/vmmr3vtable-def.h"
    source_digest = hashlib.sha256(source_file.read_bytes()).hexdigest()
    if source_digest != "f4e3b6cdf40faf3e0f1350e736a68daa4695e4448e86e1fcbc570b5d6e0cc2ab":
        raise ValueError("Source table differs from the verified release")
    source = source_file.read_text("utf-8")
    if re.search(r"^\s*#\s*(if|elif|else)", source, re.M):
        raise ValueError("Conditional table layout requires explicit preprocessing")
    definitions = [(match.group(2), match.group(1) == "RESERVED") for match in
                   re.finditer(r"^VTABLE_(ENTRY|RESERVED)\((\w+)\)", source, re.M)]
    vtable_offset = file_offset(vtable_rva, 24 + 8 * len(definitions) + 8)
    magic, flags, description_va = read("<QQQ", vtable_offset)
    expected_magic = (0x00070000 << 32) | 0x19900525
    tail_magic = read("<Q", vtable_offset + 24 + 8 * len(definitions))[0]
    if magic != expected_magic or tail_magic != magic or flags != 1:
        raise ValueError("Source-derived vtable layout not confirmed by binary markers")
    entries = []
    for index, (name, reserved) in enumerate(definitions):
        pointer_offset = vtable_offset + 24 + 8 * index
        address = read("<Q", pointer_offset)[0]
        rva = address - image_base
        offset = file_offset(rva, 16)
        if not any(start <= rva < start + size and attributes & 0x20000000
                   for start, size, _, attributes in sections):
            raise ValueError("Function pointer outside executable section")
        entries.append({"index": index, "source_name": name, "reserved": reserved,
                        "pointer_file_offset": pointer_offset, "address": hex(address),
                        "file_offset": offset, "first_16_bytes": data[offset:offset + 16].hex()})
    revision_code = bytes.fromhex(entries[0]["first_16_bytes"])
    if (entries[0]["source_name"] != "VMMGetSvnRev" or revision_code[0] != 0xB8
            or revision_code[5] != 0xC3 or struct.unpack_from("<I", revision_code, 1)[0] != 175154):
        raise ValueError("Observed revision getter does not confirm release r175154")
    result = {"target": str(target), "sha256": digest, "mode": "static bytes; target never executed",
              "image_base": hex(image_base), "exported_getter": "VMMR3GetVTable",
              "getter_address": hex(image_base + getter_rva), "getter_file_offset": getter_offset,
              "getter_bytes": code.hex(), "vtable_address": hex(image_base + vtable_rva),
              "vtable_file_offset": vtable_offset, "magic": hex(magic), "tail_magic": hex(tail_magic),
              "description": ascii_string(description_va - image_base), "entry_count": len(entries),
              "revision_getter_return": 175154,
              "source_definition": str(source_file),
              "source_definition_sha256": source_digest,
              "entries": entries,
              "limitations": ["Names are assigned from the exact released source's table order; most are not PE exports.",
                              "Marker and pointer checks support this source/binary correspondence, not full behavior equivalence.",
                              "No runtime execution, decompilation, timing or live memory measurement is performed."]}
    destination = ROOT / "research/evidence/vbox-vmm-vtable.json"
    destination.write_text(json.dumps(result, indent=2) + "\n", "utf-8")
    selected = [item for item in entries if item["source_name"] in
                {"VMR3Create", "PGMR3QueryMemoryStats", "PGMR3QueryGlobalMemoryStats", "PGMR3PhysChangeMemBalloon"}]
    print(json.dumps({key: value for key, value in result.items() if key not in {"entries", "limitations"}}, indent=2))
    print(json.dumps({"selected_entries": selected}, indent=2))


if __name__ == "__main__":
    main()
