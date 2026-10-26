"""Read extracted VirtualBox files; never load or execute a target module.

Parses ordinary/delay import tables using the Microsoft PE format specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
This is an on-disk import inventory, not a Windows loader or runtime-closure test.
"""

import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "vendor/virtualbox-7.2.20"


def pe_imports(data):
    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError("PE field outside file")
        return struct.unpack_from(fmt, data, offset)

    if data[:2] != b"MZ":
        raise ValueError("Not MZ")
    pe = unpack("<I", 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Not PE")
    machine, section_count = unpack("<HH", pe + 4)
    optional_size = unpack("<H", pe + 20)[0]
    optional = pe + 24
    magic = unpack("<H", optional)[0]
    if magic == 0x20B:
        bits, directory_offset, count_offset = 64, 112, 108
        image_base = unpack("<Q", optional + 24)[0]
    elif magic == 0x10B:
        bits, directory_offset, count_offset = 32, 96, 92
        image_base = unpack("<I", optional + 28)[0]
    else:
        raise ValueError(f"Unsupported optional header magic {magic:#x}")
    if optional_size < directory_offset or optional + optional_size > len(data):
        raise ValueError("Truncated optional header")
    directory_count = unpack("<I", optional + count_offset)[0]
    header_size = unpack("<I", optional + 60)[0]
    sections = []
    for index in range(section_count):
        section = optional + optional_size + index * 40
        virtual_size, rva, raw_size, raw_offset = unpack("<IIII", section + 8)
        sections.append((rva, virtual_size, raw_size, raw_offset))

    def file_offset(rva, size=1):
        candidates = []
        if 0 <= rva < header_size and rva + size <= min(header_size, len(data)):
            candidates.append(rva)
        for start, virtual_size, raw_size, raw in sections:
            delta = rva - start
            if 0 <= delta and delta + size <= raw_size:
                candidates.append(raw + delta)
        if len(candidates) != 1 or candidates[0] + size > len(data):
            raise ValueError(f"RVA has no unique file-backed mapping: {rva:#x}")
        return candidates[0]

    def string(rva):
        offset = file_offset(rva)
        end = data.find(b"\0", offset, min(len(data), offset + 4096))
        if end < 0:
            raise ValueError("Unterminated or excessive import string")
        file_offset(rva, end - offset + 1)
        return data[offset:end].decode("ascii", errors="strict")

    def directory(index):
        if index >= directory_count:
            return (0, 0)
        if directory_offset + (index + 1) * 8 > optional_size:
            raise ValueError("Data directory outside optional header")
        return unpack("<II", optional + directory_offset + index * 8)

    def symbols(thunk_rva, address_based=False):
        if not thunk_rva:
            return []
        result = []
        width = bits // 8
        for index in range(65536):
            value = unpack("<Q" if bits == 64 else "<I", file_offset(thunk_rva + index * width, width))[0]
            if value == 0:
                return result
            if value & (1 << (bits - 1)):
                result.append({"ordinal": value & 0xFFFF})
            else:
                name_rva = value - image_base if address_based else value
                result.append({"name": string(name_rva + 2)})
        raise ValueError("Excessive or unterminated thunk table")

    def descriptors(index, delay=False):
        table_rva, table_size = directory(index)
        if not table_rva and not table_size:
            return []
        width = 32 if delay else 20
        if not table_rva or table_size < width:
            raise ValueError("Invalid import directory")
        result = []
        for index in range(min(table_size // width, 4096)):
            fields = unpack("<8I" if delay else "<5I", file_offset(table_rva + index * width, width))
            if not any(fields):
                return result
            if delay:
                attributes, name, _, iat, lookup, _, _, timestamp = fields
                if attributes & ~1:
                    raise ValueError("Unknown delay descriptor attributes")
                address_based = not (attributes & 1)
                if address_based:
                    name -= image_base
                    lookup = lookup - image_base if lookup else 0
                    iat -= image_base
            else:
                lookup, timestamp, _, name, iat = fields
                address_based = False
            result.append({
                "dll": string(name),
                "descriptor_rva": table_rva + index * width,
                "timestamp": timestamp,
                "lookup_uses_iat_fallback": not bool(lookup),
                "symbols": symbols(lookup or iat, address_based),
            })
        raise ValueError("Unterminated or excessive import descriptors")

    bound_rva, bound_size = directory(11)
    import_rva, import_size = directory(1)
    delay_rva, delay_size = directory(13)
    return {
        "pe_header_offset": pe,
        "optional_header_offset": optional,
        "machine": f"0x{machine:04x}",
        "bits": bits,
        "size_of_image": unpack("<I", optional + 56)[0],
        "import_directory": {"rva": import_rva, "size": import_size},
        "delay_import_directory": {"rva": delay_rva, "size": delay_size},
        "ordinary_imports": descriptors(1),
        "delay_imports": descriptors(13, delay=True),
        "bound_import_directory": {"rva": bound_rva, "size": bound_size},
    }


def category(relative):
    name = relative.lower()
    if name == "vboxguestadditions.iso":
        return "guest_additions_iso"
    if name.startswith("qt6") or name.startswith(("platforms/", "styles/", "sqldrivers/")):
        return "qt_libraries_and_plugins"
    if name.startswith("nls/"):
        return "localization"
    if name.startswith("doc/") or name.startswith("usermanual.") or name.endswith(".rtf"):
        return "documentation_and_license"
    if name in {"virtualbox.exe", "virtualboxvm.exe", "virtualboxvm.dll", "uicommon.dll", "vboxres.dll"} or name.startswith("virtualbox_") or name == "virtualbox.visualelementsmanifest.xml":
        return "gui_frontends_and_resources"
    if name == "vboxwebsrv.exe":
        return "web_service"
    if name.startswith("drivers/"):
        return "host_drivers_and_install_metadata"
    if name.startswith("unattendedtemplates/"):
        return "unattended_templates"
    if name.startswith("sdk/"):
        return "python_sdk_installer"
    return "other_core_support_and_tools"


def main():
    source = BASE / "windows-packages/windows-amd64-inventory.json"
    inventory = json.loads(source.read_text("utf-8-sig"))
    files = []
    totals = Counter()
    counts = Counter()
    for entry in inventory["files"]:
        relative = entry["relative_path"].replace("\\", "/")
        path = BASE / "windows-amd64" / relative
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != entry["bytes"] or digest != entry["sha256"]:
            raise ValueError(f"Extraction inventory mismatch: {relative}")
        group = category(relative)
        record = {"path": relative, "bytes": len(data), "sha256": digest, "category": group}
        if data[:2] == b"MZ":
            try:
                record["pe"] = pe_imports(data)
            except ValueError as error:
                record["pe_parse_error"] = str(error)
        files.append(record)
        totals[group] += len(data)
        counts[group] += 1
    evidence = {
        "schema": "virtualbox.static-pe-dependencies.v1",
        "input_inventory": str(source),
        "input_inventory_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "method": "Python stdlib on-disk PE ordinary/delay import table parser; no target execution or DLL loading",
        "limitations": [
            "Not a complete runtime dependency closure: explicit loading, COM activation, plugins and driver selection are outside import tables.",
            "DLL names do not resolve API-set forwarding, Windows DLL search rules, manifests or runtime load success.",
            "Bound-import directory presence is reported; bound-import descriptors and forwarded export chains are not resolved.",
            "size_of_image and on-disk bytes are not measured working set, private bytes, commit or guest memory.",
            "Categories are explicit filename/path groupings for package accounting, not a statement that deleting a group is supported.",
        ],
        "file_count": len(files),
        "total_bytes": sum(totals.values()),
        "inventory_hashes_verified": True,
        "categories": [{"category": name, "files": counts[name], "bytes": size} for name, size in sorted(totals.items())],
        "files": files,
    }
    dest = ROOT / "research/evidence/windows-pe-dependencies.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(evidence, indent=2) + "\n", "utf-8")
    print(json.dumps({"files": len(files), "bytes": evidence["total_bytes"], "pe_files": sum("pe" in item for item in files), "parse_errors": [{"path": item["path"], "error": item["pe_parse_error"]} for item in files if "pe_parse_error" in item], "output": str(dest)}))


if __name__ == "__main__":
    main()
