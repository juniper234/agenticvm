"""Exercise package trust boundaries, interrupted download recheck and receipts."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4
import zipfile

from agenticvm.chain import Checkpoints, child, identifier, reconcile
from agenticvm.peers import verify_journal
from agenticvm.torrent import digest, install_bundle, load_catalog, member_name, read_json, verify_install


class PackageTrust(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, entries=None, *, mode=stat.S_IFREG|0o644):
        entries = entries or {'guest/agent.py': b'print("agent")\n', 'model.gguf': b'fixture weights'}
        archive = self.root/'agent.zip'
        with zipfile.ZipFile(archive, 'w') as package:
            for name, data in entries.items():
                entry = zipfile.ZipInfo(name)
                entry.external_attr = mode << 16
                package.writestr(entry, data)
        catalog = {'schema': 'agenticvm.agent-catalog.v1',
            'payload': {'name': 'agent.zip', 'bytes': archive.stat().st_size, 'sha256': digest(archive)},
            'torrent_sha256': '0'*64,
            'files': [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in entries.items()]}
        return archive, catalog

    def test_complete_package_installs_and_rechecks_cache(self):
        archive, catalog = self.fixture()
        installed = install_bundle(archive, catalog, self.root/'cache')
        self.assertEqual((installed/'guest/agent.py').read_bytes(), b'print("agent")\n')
        self.assertEqual(install_bundle(archive, catalog, self.root/'cache'), installed)
        (installed/'model.gguf').write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            install_bundle(archive, catalog, self.root/'cache')

    def test_archive_pin_is_required_before_extraction(self):
        archive, catalog = self.fixture()
        catalog['payload']['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            install_bundle(archive, catalog, self.root/'cache')
        self.assertFalse((self.root/'cache').exists())

    def test_file_content_pin_is_required_even_with_matching_zip_pin(self):
        archive, catalog = self.fixture()
        catalog['files'][0]['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            install_bundle(archive, catalog, self.root/'cache')
        self.assertFalse((self.root/'cache'/catalog['payload']['sha256']).exists())

    def test_symlink_archive_is_rejected(self):
        archive, catalog = self.fixture({'guest/agent.py': b'../../outside'}, mode=stat.S_IFLNK|0o777)
        with self.assertRaises(ValueError):
            install_bundle(archive, catalog, self.root/'cache')
        self.assertFalse((self.root/'cache').exists())

    def test_traversal_windows_aliases_and_normalization_are_rejected(self):
        for name in ('../outside', '/absolute', 'guest/../../outside', 'C:/outside', 'a\\b',
                     'guest//agent.py', './agent.py', 'CON', 'guest/NUL.txt', 'guest/a.', 'guest/COM1.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                member_name(name)

    def test_official_runtime_library_filename_is_supported(self):
        self.assertEqual(member_name('tools/qemu/11.1.0/libstdc++-6.dll'), 'tools/qemu/11.1.0/libstdc++-6.dll')

    def test_catalog_is_separately_pinned_and_validated(self):
        archive, catalog = self.fixture()
        path = self.root/'catalog.json'
        path.write_text(json.dumps(catalog))
        self.assertEqual(load_catalog(path, digest(path)), catalog)
        with self.assertRaises(ValueError):
            load_catalog(path, '0'*64)
        catalog['files'].append(dict(catalog['files'][0]))
        path.write_text(json.dumps(catalog))
        with self.assertRaises(ValueError):
            load_catalog(path, digest(path))

    def test_duplicate_manifest_keys_are_rejected(self):
        path = self.root/'duplicate.json'
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(ValueError):
            read_json(path)

    def test_unexpected_archive_file_is_rejected(self):
        archive, catalog = self.fixture()
        catalog['files'].pop()
        with self.assertRaises(ValueError):
            install_bundle(archive, catalog, self.root/'cache')
        self.assertFalse((self.root/'cache').exists())

    def test_cache_with_unexpected_file_is_rejected(self):
        archive, catalog = self.fixture()
        installed = install_bundle(archive, catalog, self.root/'cache')
        (installed/'extra.py').write_text('bad')
        with self.assertRaises(ValueError):
            verify_install(installed, catalog)


class ChainEvidence(unittest.TestCase):
    def test_child_pins_bundled_qemu_over_inherited_override(self):
        with patch.dict('os.environ', {'AGENTICVM_QEMU': 'C:/unrelated/qemu.exe'}):
            with patch('agenticvm.chain.subprocess.Popen') as launch:
                launch.return_value.wait.return_value = 0
                self.assertEqual(child(Path('C:/bundle'), ['runner.py']), 0)
        self.assertEqual(launch.call_args.kwargs['env']['AGENTICVM_QEMU'], str(Path('C:/bundle/tools/qemu/11.1.0/qemu-system-x86_64.exe')))

    def test_payload_hash_cannot_replace_checkpoint_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            journal = Checkpoints(folder, str(uuid4()))
            with self.assertRaises(ValueError):
                journal.add('download_verified', sha256='0'*64)
            journal.add('download_verified', payload_sha256='0'*64)
            journal.close()
            self.assertEqual(verify_journal(folder/'checkpoints.jsonl')['records'], 1)

    def test_checkpoints_continue_after_interrupted_download_and_reject_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder, run = Path(temporary), str(uuid4())
            journal = Checkpoints(folder, run)
            journal.add('phase', phase='downloading')
            journal.close()
            resumed = Checkpoints(folder, run, resume=True)
            resumed.add('phase', phase='download_verified')
            resumed.close()
            self.assertEqual(verify_journal(folder/'checkpoints.jsonl')['records'], 2)
            path = folder/'checkpoints.jsonl'
            path.write_text(path.read_text().replace('downloading', 'completed'))
            with self.assertRaises(ValueError):
                Checkpoints(folder, run, resume=True)

    def test_run_ids_cannot_escape_checkpoint_directory(self):
        for value in ('../run', str(uuid4()).upper(), '{'+str(uuid4())+'}'):
            with self.assertRaises(ValueError):
                identifier(value)

    def test_both_directions_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            pairs = [
                [{'event': 'sent', 'message_id': 'task', 'body_sha256': 'abc'},
                 {'event': 'received', 'message_id': 'reply', 'body_sha256': 'def'}],
                [{'event': 'received', 'message_id': 'task', 'body_sha256': 'abc'},
                 {'event': 'sent', 'message_id': 'reply', 'body_sha256': 'def'}]]
            for name, events in zip(('guest-a-serial', 'guest-b-serial'), pairs):
                directory = folder/'evidence'/name
                directory.mkdir(parents=True)
                (directory/'evidence.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
            self.assertEqual(reconcile(folder)['worker_to_orchestrator']['messages'], 1)
            path = folder/'evidence/guest-b-serial/evidence.jsonl'
            path.write_text(path.read_text().replace('def', 'bad'))
            with self.assertRaises(ValueError):
                reconcile(folder)


if __name__ == '__main__':
    unittest.main()
