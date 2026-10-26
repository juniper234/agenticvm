"""Portable assembly must validate artifacts and exclude private runtime state."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("package_portable", Path(__file__).resolve().parent.parent / "scripts/package-portable.py")
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.patch = patch.object(portable, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.lock_patch = patch.object(portable, "PYTHON_LOCK", self.root / "tools/python-runtime-lock.json")
        self.lock_patch.start()
        self.addCleanup(self.lock_patch.stop)

    def write(self, relative, data=b"fixture"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def record(self, relative):
        path = self.root / relative
        return {"path": relative, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def json(self, relative, value):
        return self.write(relative, json.dumps(value).encode())

    def fixtures(self):
        lock = {"version": "3.13.16", "sha256": "f" * 64, "max_files": 128, "max_unpacked_bytes": 40 * 1024 * 1024,
                "pth_file": "python313._pth", "stdlib_zip": "python313.zip", "development_source_path": "../../../src",
                "portable_source_path": "../../src", "digest_source": "https://www.python.org/downloads/release/python-31316/"}
        self.json("tools/python-runtime-lock.json", lock)
        python_directory = self.root / "tools/python-runtime/3.13.16"
        python_directory.mkdir(parents=True)
        archive = self.root / "python.zip"
        names = ["python.exe", "pythonw.exe", "python3.dll", "python313.dll", "python313.zip", "python313._pth", "LICENSE.txt"]
        with zipfile.ZipFile(archive, "w") as package:
            for name in names:
                package.writestr(name, b"official ZIP fixture " + name.encode())
                (python_directory / name).write_bytes(b"official ZIP fixture " + name.encode())
        (python_directory / lock["pth_file"]).write_bytes(portable.pth_contents(lock, portable=False))
        self.write("tools/qemu/11.1.0/qemu-system-x86_64.exe")
        qemu_file = self.record("tools/qemu/11.1.0/qemu-system-x86_64.exe")
        qemu_file["path"] = "qemu-system-x86_64.exe"
        self.json("tools/build-tools-lock.json", {"sources": {"qemu": {"version": "11.1.0", "build": "fixture",
                  "url": "https://qemu.weilnetz.de/fixture", "digest": "f" * 128, "destination": "tools/qemu/11.1.0", "files": [qemu_file]}}})
        self.write("runtime/linux-desktop/desktop.iso")
        self.write("runtime/linux-desktop/rootfs.ext2")
        self.write("runtime/linux-agent/agent.iso")
        self.write("runtime/linux-peer/peer.iso")
        self.json("runtime/linux-desktop/build-manifest.json", {"profile": "desktop", "os": "Debian", "release": "13",
                  "output": self.record("runtime/linux-desktop/desktop.iso"), "root_disk": self.record("runtime/linux-desktop/rootfs.ext2")})
        self.json("runtime/linux-agent/build-manifest.json", {"output": self.record("runtime/linux-agent/agent.iso")})
        self.json("runtime/linux-peer/build-manifest.json", {"profile": "agent", "iso": self.record("runtime/linux-peer/peer.iso"),
                  "root_disk": self.record("runtime/linux-desktop/rootfs.ext2")})
        for name in ("README.md", "pyproject.toml", "mcp.example.json", "agenticvm.ps1", "agenticvm-mcp.ps1", "agenticvm-peers.ps1", "Start-AgenticVM.ps1", "Start-AgenticVM.cmd",
                     "tools/desktop-image-lock.json", "src/agenticvm/web/index.html", "src/agenticvm/__init__.py", "guest/agent.c"):
            self.write(name)
        return python_directory, archive

    def test_private_runtime_files_are_not_selected_and_final_payload_is_checksummed(self):
        directory, archive = self.fixtures()
        self.write("runtime/agenticvm/data/default.ext2", b"USER PRIVATE WORKSPACE")
        self.write("runtime/linux-desktop/viewer-token.json", b"SECRET")
        self.write("runtime/linux-agent/boot.log", b"PRIVATE LOG")
        self.write("guest/desktop-app.js", b"guest customization")
        self.write("guest/desktop-app.html", b"guest customization")
        self.write("guest/desktop.conf", b"guest customization")
        self.write("guest/peer_agent.py", b"guest encrypted peer")
        self.write("guest/peer_pki.py", b"guest disposable certificate helper")
        self.write("runtime/peer-runs/private/host.key", b"PRIVATE TEST IDENTITY")
        self.write("research/architecture-research.md", b"readable research")
        self.write("research/evidence/private-binary.dat", b"large research evidence")
        output = self.root / "dist/AgenticVM"
        with patch.object(portable, "smoke_python", return_value={"isolated": 1}):
            result = portable.build_bundle(output, directory, archive, {"version": "3.13.16"})
        self.assertTrue(result["ready"])
        manifest = json.loads((output / "package-manifest.json").read_text())
        paths = {item["path"] for item in manifest["files"]}
        self.assertNotIn("runtime/agenticvm/data/default.ext2", paths)
        self.assertNotIn("runtime/linux-desktop/viewer-token.json", paths)
        self.assertNotIn("runtime/linux-agent/boot.log", paths)
        self.assertIn("runtime/linux-desktop/rootfs.ext2", paths)
        self.assertIn("guest/agent.c", paths)
        self.assertIn("guest/desktop-app.js", paths)
        self.assertIn("guest/desktop-app.html", paths)
        self.assertIn("guest/desktop.conf", paths)
        self.assertIn("guest/peer_agent.py", paths)
        self.assertIn("guest/peer_pki.py", paths)
        self.assertIn("runtime/linux-peer/peer.iso", paths)
        self.assertNotIn("runtime/peer-runs/private/host.key", paths)
        self.assertIn("research/architecture-research.md", paths)
        self.assertIn("mcp.example.json", paths)
        self.assertNotIn("research/evidence/private-binary.dat", paths)
        mcp = json.loads((output / "mcp.example.json").read_text())["mcpServers"]["agenticvm"]
        self.assertEqual(mcp["args"][2], (output / "agenticvm-mcp.ps1").as_posix())
        self.assertEqual(mcp["args"][4], (output / "runtime/desktop").as_posix())
        self.assertEqual(mcp["args"][5:], ["--profile", "desktop", "--persistent", "--network"])
        self.assertIn("tools/python/LICENSE.txt", paths)
        notices = (output / "THIRD-PARTY-NOTICES.txt").read_text()
        self.assertIn("Desktop guest: Debian 13.", notices)
        self.assertNotIn("Alpine Linux guest", notices)
        self.assertEqual((output / "tools/python/python313._pth").read_bytes(), portable.pth_contents(portable.load(portable.PYTHON_LOCK), portable=True))
        self.assertFalse(manifest["user_workspace_files_copied"])
        for item in manifest["files"]:
            self.assertEqual(portable.sha256(output / item["path"]), item["sha256"])

    def test_mutated_image_fails_before_creating_output(self):
        directory, archive = self.fixtures()
        (self.root / "runtime/linux-desktop/rootfs.ext2").write_bytes(b"not the recorded build")
        output = self.root / "dist/AgenticVM"
        with self.assertRaisesRegex(ValueError, "Built image differs"):
            portable.build_bundle(output, directory, archive, {})
        self.assertFalse(output.exists())

    def test_debian_package_lock_is_checked_against_its_build_manifest(self):
        self.fixtures()
        relative = "runtime/linux-desktop/build-manifest.json"
        manifest = portable.load(self.root / relative)
        manifest["package_lock"] = "tools/desktop-image-lock.json"
        manifest["package_lock_sha256"] = portable.sha256(self.root / manifest["package_lock"])
        self.json(relative, manifest)
        verified, _ = portable.verify_image_manifest(relative, desktop=True)
        self.assertEqual(verified["os"], "Debian")
        self.write("tools/desktop-image-lock.json", b"modified package selection")
        with self.assertRaisesRegex(ValueError, "package lock differs"):
            portable.verify_image_manifest(relative, desktop=True)

    def test_existing_bundle_and_escaping_paths_are_preserved(self):
        directory, archive = self.fixtures()
        output = self.root / "dist/AgenticVM"
        output.mkdir(parents=True)
        marker = output / "personal-file.txt"
        marker.write_bytes(b"keep this file")
        with self.assertRaisesRegex(ValueError, "already exists"):
            portable.build_bundle(output, directory, archive, {})
        self.assertEqual(marker.read_bytes(), b"keep this file")
        for name in ("../outside", "C:/outside", "/outside", "tools/../../outside"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                portable.plain(self.root, name)

    def test_python_zip_traversal_and_modified_executable_are_refused(self):
        directory, archive = self.fixtures()
        lock = portable.load(portable.PYTHON_LOCK)
        (directory / "python.exe").write_bytes(b"modified executable")
        with self.assertRaisesRegex(ValueError, "differs from"):
            portable.verify_python_tree(directory, archive, lock)
        malicious = self.root / "malicious.zip"
        with zipfile.ZipFile(malicious, "w") as package:
            package.writestr("../escape.exe", b"outside")
        with self.assertRaisesRegex(ValueError, "unexpected path"):
            portable.zip_entries(malicious, lock)


if __name__ == "__main__":
    unittest.main()
