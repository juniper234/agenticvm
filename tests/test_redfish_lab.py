"""Real HTTPS controller contracts, guarded media and bound backend operations."""
import json
from pathlib import Path
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.redfish_lab import Controller, SYSTEM, MEDIA, NativeVM


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        (self.folder / 'private').mkdir()
        target = self.folder / 'target'
        target.mkdir()
        self.vm = SimpleNamespace(folder=target, uuid=str(uuid4()), process=None)
        self.seed = self.folder / 'seed.iso'
        self.seed.write_bytes(b'approved virtual configuration media')
        self.controller = Controller(self.vm, self.seed)
        self.addCleanup(self.controller.close)

    def request(self, method, path, body=None):
        return self.controller.request(method, path, body)

    def test_pinned_https_media_and_one_time_power_control_reach_only_bound_backend(self):
        def start(vm, *, seed):
            self.assertIs(vm, self.vm)
            self.assertEqual(seed, self.seed)
            vm.process = SimpleNamespace(poll=lambda: None)
        def off(vm):
            self.assertIs(vm, self.vm)
            vm.process = None
        with patch.object(NativeVM, 'start', side_effect=start) as started, patch.object(NativeVM, 'poweroff', side_effect=off) as stopped:
            self.assertEqual(self.request('GET', SYSTEM)['UUID'], self.vm.uuid)
            self.request('POST', MEDIA + '/Actions/VirtualMedia.InsertMedia',
                         {'Image': self.controller.media_uri, 'Inserted': True, 'WriteProtected': True})
            self.request('PATCH', SYSTEM, {'Boot': {'BootSourceOverrideEnabled': 'Once', 'BootSourceOverrideTarget': 'Hdd'}})
            self.request('POST', SYSTEM + '/Actions/ComputerSystem.Reset', {'ResetType': 'On'})
            self.assertEqual(self.request('GET', SYSTEM)['Boot']['BootSourceOverrideEnabled'], 'Disabled')
            self.request('POST', SYSTEM + '/Actions/ComputerSystem.Reset', {'ResetType': 'GracefulShutdown'})
            started.assert_called_once()
            stopped.assert_called_once()
        self.assertTrue(all(event['tls'] == 'TLSv1.3' for event in self.controller.events))
        self.assertEqual(list((self.folder / 'private').iterdir()), [])

    def test_changed_media_unapproved_uris_and_out_of_order_power_never_launch(self):
        with patch.object(NativeVM, 'start') as start:
            for operation in (
                ('POST', SYSTEM + '/Actions/ComputerSystem.Reset', {'ResetType': 'On'}),
                ('POST', MEDIA + '/Actions/VirtualMedia.InsertMedia', {'Image': 'https://outside.invalid/evil.iso', 'Inserted': True, 'WriteProtected': True}),
                ('POST', SYSTEM + '/Actions/ComputerSystem.Reset', {'ResetType': 'ForceRestart'})):
                with self.subTest(operation=operation), self.assertRaises(urllib.error.HTTPError):
                    self.request(*operation)
            self.seed.write_bytes(b'changed media')
            with self.assertRaises(urllib.error.HTTPError):
                self.request('POST', MEDIA + '/Actions/VirtualMedia.InsertMedia',
                             {'Image': self.controller.media_uri, 'Inserted': True, 'WriteProtected': True})
            start.assert_not_called()

    def test_wrong_token_stale_etag_and_untrusted_certificate_are_rejected(self):
        context = ssl.create_default_context(cadata=self.controller.certificate)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        with self.assertRaises(urllib.error.HTTPError) as wrong:
            opener.open(self.controller.origin + SYSTEM, timeout=5)
        self.assertEqual(wrong.exception.code, 401)
        request = urllib.request.Request(self.controller.origin + SYSTEM, method='PATCH',
            data=json.dumps({'Boot': {'BootSourceOverrideEnabled': 'Once', 'BootSourceOverrideTarget': 'Hdd'}}).encode(),
            headers={'X-Auth-Token': self.controller.token, 'If-Match': '"stale"'})
        with self.assertRaises(urllib.error.HTTPError):
            opener.open(request, timeout=5)
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(self.controller.origin + SYSTEM, timeout=5)
        self.assertFalse(self.controller.once)
        self.assertEqual(self.controller.events, [])


if __name__ == '__main__':
    unittest.main()
