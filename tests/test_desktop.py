"""Display/input ownership, immutable image and screenshot regression checks."""
from __future__ import annotations

import json
import socket
import struct
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agenticvm.desktop import DesktopController, normalize_keys, png_dimensions
from agenticvm.errors import AgenticVMError
from agenticvm.qemu import QemuBackend, qmp_sequence
from agenticvm.state import StateStore


def png(width=1024, height=768):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    # Validation does not decompress; a tiny valid black scanline fixture is
    # sufficient for the PNG framing/boundary tests in this module.
    pixels = zlib.compress((b"\0" + b"\0\0\0" * width) * height)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ipc_temp = patch("agenticvm.state.tempfile.gettempdir", return_value=str(self.root))
        self.ipc_temp.start()
        self.addCleanup(self.ipc_temp.stop)
        self.store = StateStore(self.root / "private", "desktop-test")
        self.exe = self.root / "qemu-system-x86_64.exe"
        self.exe.write_bytes(b"fixture")
        self.iso = self.root / "linux.iso"
        self.iso.write_bytes(b"fixture")
        self.disk = self.root / "rootfs.ext2"
        self.disk.write_bytes(b"immutable root filesystem fixture")
        self.backend = QemuBackend(self.store, self.exe)
        executable = self.exe

        class Process:
            def __init__(self, pid, **kwargs):
                self.created, self.executable = "123456789", executable
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def alive(self): return True
            def close(self): pass

        self.Process = Process

    def start_fixture(self, *, network=False, workspace_disk=None):
        child = SimpleNamespace(pid=4321, poll=lambda: None)
        with patch.object(self.backend, "doctor", return_value={"version": "QEMU fixture", "sha256": "a" * 64, "whpx": {"available": True}}), \
             patch("agenticvm.qemu.os", SimpleNamespace(name="nt")), \
             patch("agenticvm.qemu.check_memory_budget", return_value={}), \
             patch("agenticvm.qemu.WindowsProcess", self.Process), \
             patch("agenticvm.qemu.qmp_call", return_value={"status": "running"}), \
             patch("agenticvm.qemu.subprocess.CREATE_NO_WINDOW", 0, create=True), \
             patch("agenticvm.qemu.subprocess.CREATE_NEW_PROCESS_GROUP", 0, create=True), \
             patch("agenticvm.qemu.subprocess.Popen", return_value=child) as launch:
            state = self.backend.start(self.iso, 768, profile="desktop", root_disk=self.disk,
                                       workspace_disk=workspace_disk, network=network)
        return state, launch.call_args.args[0]

    def capture_qmp(self, port, command, timeout=3, *, arguments=None):
        self.assertEqual(command, "screendump")
        self.assertEqual(arguments["format"], "png")
        Path(arguments["filename"]).write_bytes(png())
        return {}

    def test_desktop_base_is_read_only_and_network_is_explicit(self):
        state, argv = self.start_fixture()
        self.assertEqual(argv[argv.index("-nic") + 1], "none")
        self.assertIn("readonly=on", argv[argv.index("-drive") + 1])
        self.assertNotIn("snapshot=on", " ".join(argv))
        self.assertIn("usb-tablet,bus=usb.0", argv)
        self.assertIn("VGA,vgamem_mb=16,xres=1024,yres=768", argv)
        self.assertEqual(state["root_disk"], str(self.disk.resolve()))
        state["registered"] = False
        self.store.save(state)
        state, argv = self.start_fixture(network=True)
        self.assertEqual(argv[argv.index("-netdev") + 1], "user,id=desktopnet,ipv6=off")
        self.assertIn("e1000,netdev=desktopnet,romfile=", argv)
        self.assertNotIn("-nic", argv)
        self.assertEqual(state["network"], "nat")
        self.assertEqual(state["host_control_transport"], "unix")
        self.assertNotIn("serial_port", state)
        self.assertNotIn("qmp_port", state)
        self.assertFalse(any("tcp:" in item or "host=127.0.0.1" in item for item in argv))
        self.assertIn("socket,id=agent,path=" + state["serial_socket"] + ",server=on,wait=off", argv)
        self.assertIn("socket,id=qmp,path=" + state["qmp_socket"] + ",server=on,wait=off", argv)
        self.assertFalse(any("hostfwd" in item or "vnc" in item for item in argv))

    def test_persistent_disk_must_be_the_owned_session_data_file(self):
        unrelated = self.root / "personal-disk.ext2"
        unrelated.write_bytes(b"do not open for write")
        with patch("agenticvm.qemu.subprocess.Popen") as launch:
            with self.assertRaises(AgenticVMError) as caught:
                self.backend.start(self.iso, 768, profile="desktop", root_disk=self.disk, workspace_disk=unrelated)
        self.assertEqual(caught.exception.code, "invalid_image")
        launch.assert_not_called()
        managed = self.store.root / "data" / "desktop-test.ext2"
        managed.parent.mkdir(parents=True)
        managed.write_bytes(b"owned persistent workspace")
        state, argv = self.start_fixture(workspace_disk=managed)
        self.assertEqual(state["workspace_disk"], str(managed.resolve()))
        drives = [argv[index + 1] for index, argument in enumerate(argv) if argument == "-drive"]
        self.assertEqual(len(drives), 2)
        self.assertTrue(drives[0].endswith("readonly=on"))
        self.assertNotIn("readonly", drives[1])

    def test_screenshot_poll_cleans_temporary_capture_and_refuses_overwrite(self):
        state, _ = self.start_fixture()
        controller = DesktopController(self.backend)
        with patch("agenticvm.qemu.WindowsProcess", self.Process), \
             patch("agenticvm.desktop.qmp_call", side_effect=self.capture_qmp):
            data, metadata = controller.screenshot_bytes()
            self.assertEqual(png_dimensions(data), (1024, 768))
            self.assertEqual(metadata["width"], 1024)
            self.assertEqual(list(Path(state["run_dir"]).glob(".screen-*")), [])
            output = self.root / "result.png"
            output.write_bytes(b"user data")
            with self.assertRaises(AgenticVMError) as caught:
                controller.screenshot(output)
            self.assertEqual(caught.exception.code, "destination_exists")
            self.assertEqual(output.read_bytes(), b"user data")
            result = controller.screenshot(output, overwrite=True)
            self.assertEqual(png_dimensions(output.read_bytes()), (1024, 768))
            self.assertEqual(result["path"], str(output.absolute()))

    def test_process_identity_mismatch_blocks_capture_and_input(self):
        state, _ = self.start_fixture()
        state["process_created"] = "9"
        self.store.save(state)
        controller = DesktopController(self.backend)
        with patch("agenticvm.qemu.WindowsProcess", self.Process), \
             patch("agenticvm.desktop.qmp_call") as monitor:
            with self.assertRaises(AgenticVMError) as caught:
                controller.key(["ctrl", "l"])
            self.assertEqual(caught.exception.code, "ownership_mismatch")
        monitor.assert_not_called()

    def test_coordinates_follow_actual_frame_and_outside_clicks_are_rejected(self):
        self.start_fixture()
        controller = DesktopController(self.backend)
        with patch("agenticvm.qemu.WindowsProcess", self.Process), \
             patch("agenticvm.desktop.qmp_call", side_effect=self.capture_qmp), \
             patch("agenticvm.desktop.qmp_sequence", return_value=[{}] * 3) as monitor:
            controller.click(1023, 767)
            operations = monitor.call_args.args[1]
            self.assertEqual([event["data"]["value"] for event in operations[0][1]["events"]], [32767, 32767])
            self.assertTrue(operations[1][1]["events"][0]["data"]["down"])
            self.assertFalse(operations[2][1]["events"][0]["data"]["down"])
            self.assertGreaterEqual(monitor.call_args.kwargs.get("interval", 0), 0.02)
            monitor.reset_mock()
            for x, y in ((1024, 0), (-1, 0), (False, 0), (0, 768)):
                with self.subTest(x=x, y=y), self.assertRaises(AgenticVMError):
                    controller.click(x, y)
            monitor.assert_not_called()

    def test_scroll_transitions_are_paced_to_avoid_usb_coalescing(self):
        self.start_fixture()
        controller = DesktopController(self.backend)
        with patch("agenticvm.qemu.WindowsProcess", self.Process), \
             patch("agenticvm.desktop.qmp_sequence", return_value=[{}] * 4) as monitor:
            controller.scroll(2)
        self.assertGreaterEqual(monitor.call_args.kwargs.get("interval", 0), 0.02)
        operations = monitor.call_args.args[1]
        self.assertEqual([arguments["events"][0]["data"]["down"] for _, arguments in operations], [True, False, True, False])

    def test_key_chords_are_literal_and_unsupported_text_is_rejected_before_input(self):
        self.assertEqual(normalize_keys("Control+L"), ["ctrl", "l"])
        self.assertEqual(normalize_keys(["ctrl", "+"]), ["ctrl", "shift", "equal"])
        controller = DesktopController(self.backend)
        with patch("agenticvm.desktop.qmp_sequence") as monitor:
            for text in ("hello\0", "café", "x" * 4097):
                with self.subTest(text=text[:10]), self.assertRaises(AgenticVMError):
                    controller.type_text(text)
        monitor.assert_not_called()

    def test_corrupt_or_overlarge_png_is_rejected(self):
        data = png(8, 8)
        self.assertEqual(png_dimensions(data), (8, 8))
        broken = bytearray(data)
        broken[24] ^= 1
        for value in (bytes(broken), data[:-1], data + b"trailing", png(4097, 1)):
            with self.subTest(size=len(value)), self.assertRaises(AgenticVMError):
                png_dimensions(value)


class QmpSequenceTests(unittest.TestCase):
    def test_single_negotiation_preserves_order_and_correlates_each_reply(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        failures, requests = [], []

        def serve():
            try:
                with server, server.accept()[0] as connection:
                    connection.settimeout(3)
                    stream = connection.makefile("rwb", buffering=0)
                    stream.write(b'{"QMP":{"version":{}}}\r\n')
                    for expected in ("qmp_capabilities", "input-send-event", "input-send-event"):
                        request = json.loads(stream.readline())
                        requests.append(request)
                        self.assertEqual(request["execute"], expected)
                        stream.write(b'{"event":"DISPLAY_UPDATE"}\r\n')
                        stream.write(json.dumps({"id": request["id"], "return": {}}).encode() + b"\r\n")
                    stream.close()
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertEqual(qmp_sequence(port, [("input-send-event", {"events": []}), ("input-send-event", {"events": []})]), [{}, {}])
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len({request["id"] for request in requests}), 3)


if __name__ == "__main__":
    unittest.main()
