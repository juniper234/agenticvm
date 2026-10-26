"""Native packaging boundaries and honest evidence-level validation."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import socket
import struct
import tarfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.enrollment_catalog import validate_receipt
from agenticvm.native_enrollment import native_config, package_agent, ReconnectingSwitch, verify_denial
from agenticvm.lan_lab import mac, FrameDecoder


class EvidenceTests(unittest.TestCase):
    def receipt(self, **kw):
        return {'route': 'cloud-init-local', 'level': 'contract-tested', 'passed': True,
                'source_sha256': {'guest/example.py': 'a' * 64}, 'evidence': ['a receipt'], 'limitations': [], **kw}

    def test_reboot_cannot_be_claimed_by_a_contract_or_single_boot(self):
        for fields in ({}, {'native_os_observed': True}, {'native_os_observed': True, 'native_cold_boots': True}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate_receipt(self.receipt(level='reboot-tested', **fields))
        validate_receipt(self.receipt(level='reboot-tested', native_os_observed=True, native_cold_boots=2))

    def test_source_pins_cannot_escape_or_be_ambiguous(self):
        for source in ('../outside', 'C:/outside', '/outside', 'src/../../outside', 'src\\outside', 'src//outside'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                validate_receipt(self.receipt(source_sha256={source: 'a' * 64}))
        for fields in ({'source_sha256': {}}, {'source_sha256': {'a.py': 'x' * 64}}, {'evidence': []}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate_receipt(self.receipt(**fields))

    def test_expected_error_cannot_hide_partial_agent_activation(self):
        proof = {'error': 'ValueError: Asset integrity verification failed', 'uid': 0,
                 'native_os': 'ID=ubuntu\n', 'boot_id': 'observed-native-boot',
                 'activation_paths': {name: False for name in ('peer/lan_agent.py', 'model.gguf', 'identity.key', 'lan-config.json')},
                 'agent_service_active': False}
        self.assertTrue(verify_denial('bad-hash', proof, 'ubuntu'))
        for path in proof['activation_paths']:
            changed = {**proof, 'activation_paths': {**proof['activation_paths'], path: True}}
            with self.subTest(path=path), self.assertRaises(ValueError):
                verify_denial('bad-hash', changed, 'ubuntu')
        with self.assertRaises(ValueError):
            verify_denial('wrong-grant', proof, 'ubuntu')


class NativePackagingTests(unittest.TestCase):
    def test_archive_stays_inside_reviewed_installers_two_file_allowlist(self):
        with tarfile.open(fileobj=io.BytesIO(package_agent())) as package:
            self.assertEqual(package.getnames(), ['lan_agent.py', 'local_lfm.py'])
            source = package.extractfile('lan_agent.py').read().decode()
            code = compile(source, 'native-agent.py', 'exec')
            self.assertIsNotNone(code)
            self.assertEqual(source.count("if __name__=='__main__':"), 1)
            self.assertNotIn('/workspace', source)
            # Relocation must keep the original RPC admission and durable model
            # ledger paths, rather than substituting fake inference receipts.
            self.assertIn('return value', source)
            self.assertIn("self.model.generate(", source)
            self.assertIn("INSERT INTO calls", source)
            self.assertIn("hmac.compare_digest", source)

    def test_remote_ignition_pin_covers_the_exact_served_bytes(self):
        runtime = {'sha256': 'b' * 64}
        public = {'mother': {'certificate': 'lab-public-certificate'}}
        payload, metadata = native_config('ignition-network', 'owned-run', public, runtime)
        reference = json.loads(payload['config.ign'])['ignition']['config']['replace']
        raw = base64.b64decode(metadata['/ignition/owned-run.json'], validate=True)
        self.assertEqual(reference['verification']['hash'], 'sha512-' + hashlib.sha512(raw).hexdigest())
        self.assertEqual(reference['source'], 'http://192.0.2.1:8080/ignition/owned-run.json')
        self.assertNotIn('passwd', json.loads(raw))


class NativeSwitchTests(unittest.TestCase):
    def test_cold_boot_reconnect_preserves_seed_nic_and_mac_binding(self):
        switch = ReconnectingSwitch()
        mother = target = next_target = None
        try:
            mother = socket.create_connection(('127.0.0.1', switch.listen(1)))
            port = switch.listen(4)
            target = socket.create_connection(('127.0.0.1', port))
            frame = mac(1) + mac(4) + b'\x88\xb5' + b'owned cold boot'
            packet = struct.pack('!I', len(frame)) + frame
            target.sendall(packet)
            mother.settimeout(2)
            self.assertEqual(FrameDecoder().feed(mother.recv(4096)), [frame])
            switch.arm_reboot()
            target.close()
            target = None
            deadline = time.monotonic() + 2
            while 4 in switch.ports and time.monotonic() < deadline:
                time.sleep(.01)
            next_target = socket.create_connection(('127.0.0.1', port))
            next_target.sendall(packet)
            self.assertEqual(FrameDecoder().feed(mother.recv(4096)), [frame])
            self.assertEqual(switch.target_connections, 2)
            self.assertEqual(switch.addresses[4], mac(4))
            self.assertFalse(switch.errors)
        finally:
            switch.close()
            for client in (mother, target, next_target):
                if client:
                    client.close()


if __name__ == '__main__':
    unittest.main()
