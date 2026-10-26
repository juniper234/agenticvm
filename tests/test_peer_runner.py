"""Check evidence integrity and parser failure behavior without a VM."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
from uuid import uuid4

from agenticvm.peers import Journal, inspect_capture, verify_journal


class PeerEvidenceTests(unittest.TestCase):
    def test_checkpoint_chain_detects_modified_or_missing_steps(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            journal = Journal(folder, str(uuid4()))
            journal.add("begin", vm="guest-a")
            journal.add("authenticated", tls="TLSv1.3")
            journal.add("cleanup", passed=True)
            journal.close()
            path = folder / "checkpoints.jsonl"
            self.assertEqual(verify_journal(path)["records"], 3)
            original = path.read_text().splitlines()
            altered = json.loads(original[1])
            altered["tls"] = "plaintext"
            path.write_text("\n".join([original[0], json.dumps(altered), original[2]]) + "\n")
            with self.assertRaises(ValueError):
                verify_journal(path)
            path.write_text("\n".join([original[0], original[2]]) + "\n")
            with self.assertRaises(ValueError):
                verify_journal(path)

    def test_capture_reports_tcp_endpoints_and_rejects_truncation(self):
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65536, 1)
        ethernet = b"\0" * 12 + b"\x08\x00"
        ip = bytearray(20)
        ip[0], ip[9] = 0x45, 6
        ip[12:20] = bytes((192, 0, 2, 1, 192, 0, 2, 2))
        tcp = bytearray(20)
        tcp[:4] = struct.pack("!HH", 40000, 7443)
        tcp[12] = 0x50
        packet = ethernet + ip + tcp + b"\x16\x03\x03\0\x03xyz"
        data = header + struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "peer.pcap"
            path.write_bytes(data)
            observation = inspect_capture(path, b"private-marker")
            self.assertTrue(observation["tls_record_observed"])
            self.assertFalse(observation["marker_visible"])
            self.assertEqual(observation["tcp_endpoints"], [("192.0.2.1", "192.0.2.2", 40000, 7443)])
            path.write_bytes(data[:-2])
            with self.assertRaisesRegex(ValueError, "Truncated"):
                inspect_capture(path)
