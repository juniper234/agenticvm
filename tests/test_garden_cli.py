"""JSON garden CLI: init, membership, activate/revoke, policy and receipts."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from agenticvm import cli


class GardenCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'workspace'

    def invoke(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(['--workspace', str(self.workspace), 'garden', *args])
        try:
            return code, json.loads(out.getvalue())
        except json.JSONDecodeError:
            self.fail('Non-JSON CLI output: ' + out.getvalue())

    def init(self):
        code, value = self.invoke('init', '--name', 'lab')
        self.assertEqual(code, 0)
        self.assertTrue(value['ok'])
        return value['result']['status']['garden']['mother']

    def test_init_status_and_policy_show(self):
        self.init()
        code, value = self.invoke('status')
        self.assertEqual(code, 0)
        self.assertEqual(value['result']['garden']['count'], 1)
        code, value = self.invoke('policy', 'show')
        self.assertEqual(code, 0)
        self.assertEqual(value['result']['policy']['scope'], ['10.66.0.0/24'])

    def test_add_activate_revoke_seven_offshoots(self):
        self.init()
        ids = []
        for index in range(1, 8):
            code, value = self.invoke('member', 'add', '--address', '10.66.0.%d' % (20 + index),
                                   '--label', 'sprout-%d' % index)
            self.assertEqual(code, 0, value)
            member = value['result']['member']
            self.assertEqual(member['channel'], index + 1)
            ids.append(member['id'])
            self.assertEqual(self.invoke('member', 'activate', member['id'])[0], 0)
        code, value = self.invoke('member', 'list')
        self.assertEqual(value['result']['count'], 8)
        self.assertEqual(value['result']['active'], 8)
        self.assertEqual(self.invoke('member', 'revoke', ids[0])[0], 0)
        self.assertEqual(self.invoke('member', 'activate', ids[0])[1]['error']['code'], 'garden_invalid')

    def test_limit_scope_and_receipts(self):
        self.init()
        self.assertEqual(self.invoke('member', 'add', '--address', '192.168.1.2')[1]['ok'], False)
        for index in range(1, 8):
            self.assertEqual(self.invoke('member', 'add', '--address', '10.66.0.%d' % (30 + index))[0], 0)
        self.assertEqual(self.invoke('member', 'add', '--address', '10.66.0.90')[1]['error']['code'], 'garden_invalid')
        code, value = self.invoke('receipts')
        self.assertEqual(code, 0)
        self.assertGreaterEqual(len(value['result']['receipts']), 8)
        values = value['result']['receipts']
        for left, right in zip(values, values[1:]):
            self.assertEqual(right['previous'], left['digest'])

    def test_policy_set_and_validation(self):
        self.init()
        code, value = self.invoke('policy', 'set', '--max-active', '3', '--max-depth', '4')
        self.assertEqual(code, 0, value)
        self.assertEqual(value['result']['policy']['max_active'], 3)
        self.assertEqual(self.invoke('policy', 'set', '--max-active', '8')[0], 1)
        self.assertEqual(self.invoke('policy', 'set', '--max-total', '1')[0], 1)
        self.assertEqual(self.invoke('init')[1]['error']['code'], 'garden_invalid')
        self.assertEqual(self.invoke('init', '--force', '--name', 'second')[0], 0)

    def test_explicit_garden_dir(self):
        garden = Path(self.temp.name) / 'explicit'
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(['--garden-dir', str(garden), 'garden', 'init'])
        self.assertEqual(code, 0)
        self.assertTrue((garden / 'garden.json').is_file())
        self.assertFalse((self.workspace / 'garden').exists())
