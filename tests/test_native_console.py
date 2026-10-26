"""Regression for a real systemd status suffix observed on a denial proof."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_console import json_records
from agenticvm.native_enrollment import verify_denial


class NativeConsoleTests(unittest.TestCase):
    def proof(self):
        return {'native_os': 'NAME="Ubuntu"\nID=ubuntu\n', 'boot_id': 'observed-native-boot', 'uid': 0,
            'error': 'ValueError: Native installer digest failed before execution',
            'activation_paths': {name: False for name in ('peer/lan_agent.py', 'model.gguf', 'identity.key', 'lan-config.json')},
            'agent_service_active': False}

    def test_complete_refusal_json_survives_interleaved_cloud_final_status(self):
        proof = self.proof()
        console = 'NATIVE_DENIAL_PROOF ' + json.dumps(proof) + '[  OK  ] Finished cloud-final.service - Cloud-init: Final Stage.\n'
        records = json_records(console, 'NATIVE_DENIAL_PROOF ')
        self.assertEqual(records, [proof])
        self.assertTrue(verify_denial('bad-bootstrap', records[0], 'ubuntu'))

    def test_partial_oversized_and_nonobject_records_are_not_proofs(self):
        for raw in ('{"unfinished":', '[]', 'false', json.dumps({'oversized': 'x' * 70000})):
            with self.subTest(raw=raw[:30]):
                self.assertEqual(json_records('NATIVE_DENIAL_PROOF ' + raw, 'NATIVE_DENIAL_PROOF '), [])

    def test_tolerant_console_framing_does_not_hide_activation(self):
        proof = self.proof()
        proof['activation_paths']['identity.key'] = True
        records = json_records('NATIVE_DENIAL_PROOF ' + json.dumps(proof) + '[ OK ]\n', 'NATIVE_DENIAL_PROOF ')
        with self.assertRaises(ValueError):
            verify_denial('bad-bootstrap', records[0], 'ubuntu')
