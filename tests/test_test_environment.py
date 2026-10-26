"""Pinned tool preparation must not turn archives or caches into host writes."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare_test_environment',ROOT/'scripts/prepare-test-environment.py')
prepare=importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name)

    def archive(self,entries):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive:
            for name,value in entries:archive.writestr(name,value)
        return buffer.getvalue()

    def test_archive_traversal_and_windows_special_paths_never_escape(self):
        for name in ('../outside','/outside','C:/outside','a/../../outside','NUL.txt','safe/../outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                prepare.unpack(self.archive([(name,b'no')]),self.root/'tools')
        self.assertFalse((self.root/'outside').exists())

    def test_archive_symbolic_links_are_refused(self):
        link=zipfile.ZipInfo('link')
        link.create_system=3
        link.external_attr=(stat.S_IFLNK|0o777)<<16
        with self.assertRaisesRegex(ValueError,'links'):
            prepare.unpack(self.archive([(link,b'../outside')]),self.root/'tools')

    def test_case_collisions_are_refused(self):
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            prepare.unpack(self.archive([('same.py',b'a'),('SAME.py',b'b')]),self.root/'tools')

    def test_valid_preparation_is_idempotent_but_changed_files_are_preserved(self):
        archive=self.archive([('module.py',b'known source')])
        destination=self.root/'tools'
        prepare.unpack(archive,destination)
        prepare.unpack(archive,destination)
        (destination/'module.py').write_bytes(b'user edit')
        with self.assertRaisesRegex(ValueError,'changed'):
            prepare.unpack(archive,destination)
        self.assertEqual((destination/'module.py').read_bytes(),b'user edit')

    def test_only_expected_interpreter_configuration_is_reused(self):
        archive=self.archive([('python313._pth',b'original')])
        destination=self.root/'python'
        override={'python313._pth':b'known test path'}
        prepare.unpack(archive,destination,override)
        prepare.unpack(archive,destination,override)
        windows_override={'python313._pth':b'known\ntest\npath\n'}
        (destination/'python313._pth').write_bytes(b'known\r\ntest\r\npath\r\n')
        prepare.unpack(archive,destination,windows_override)
        self.assertEqual((destination/'python313._pth').read_bytes(),b'known\r\ntest\r\npath\r\n')
        (destination/'python313._pth').write_bytes(b'unexpected path')
        with self.assertRaisesRegex(ValueError,'changed'):
            prepare.unpack(archive,destination,override)

    def test_bad_download_digest_creates_no_cache_entry(self):
        record={'filename':'fixture.whl','bytes':4,'sha256':'0'*64,'url':'https://files.pythonhosted.org/fixture.whl'}
        response=io.BytesIO(b'bad!')
        response.url=record['url']
        with patch.object(prepare.urllib.request,'urlopen',return_value=response):
            with self.assertRaisesRegex(ValueError,'integrity'):
                prepare.fetch(record,self.root/'cache',True)
        self.assertFalse((self.root/'cache/fixture.whl').exists())

    def test_prepared_asset_import_copies_only_verified_bytes(self):
        project=self.root/'project'
        cache=self.root/'cache'
        relative='runtime/linux-pxe-base-v3/fixture'
        value=b'prepared fixture bytes'
        (project/'tools').mkdir(parents=True)
        (cache/relative).parent.mkdir(parents=True)
        (cache/relative).write_bytes(value)
        lock={'files':[{'path':relative,'kind':'prepared','bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}]}
        (project/'tools/test-assets-lock.json').write_text(json.dumps(lock))
        with patch.object(prepare,'ROOT',project):
            self.assertEqual(prepare.import_assets(cache),1)
            self.assertEqual(prepare.import_assets(cache),0)
            (project/relative).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'changed'):
                prepare.import_assets(cache)
        self.assertEqual((project/relative).read_bytes(),b'changed')

    def test_requirements_and_portable_lock_pin_the_same_distributions(self):
        requirements={line.split('==',1)[0].lower():line.split('==',1)[1]
                      for line in (ROOT/'requirements-test.txt').read_text().splitlines() if line and not line.startswith('#')}
        lock=json.loads((ROOT/'tools/test-dependencies-lock.json').read_text())
        self.assertEqual(requirements,{item['name'].lower():item['version'] for item in lock['wheels']})
        for item in lock['wheels']:
            self.assertRegex(item['sha256'],r'^[a-f0-9]{64}$')
            self.assertTrue(item['url'].startswith('https://files.pythonhosted.org/'))

    def test_source_archive_without_git_still_gets_code_integrity_pins(self):
        spec=importlib.util.spec_from_file_location('host_runner_without_git',ROOT/'scripts/run-host-tests.py')
        runner=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with patch.object(runner.subprocess,'run',side_effect=FileNotFoundError('git unavailable')):
            pins=runner.source_pins()
        self.assertIn('src/agenticvm/control_cli.py',pins)
        self.assertIn('tests/test_test_environment.py',pins)
        self.assertFalse(any(name.startswith(('runtime/','downloads/')) for name in pins))


if __name__=='__main__':unittest.main()
