"""C-017: the specialize selector must stay short enough for SMI."""
import sys
import hashlib
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.windows_inputs import inputs

RUN = '11111111-1111-4111-8111-111111111111'
TARGET = '22222222-2222-4222-8222-222222222222'
NS = {'u': 'urn:schemas-microsoft-com:unattend'}


class UnattendPathLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.root = Path(cls.fixture.name)
        assets = cls.root / 'runtime/enrollment-images'
        (assets/'windows-installer').mkdir(parents=True)
        python = b'unit-test Windows Python archive; never executed'
        (assets/'python.zip').write_bytes(python)
        (assets/'windows-application-runtime.json').write_text(json.dumps({'assets':{'python':{
            'path':'runtime/enrollment-images/python.zip',
            'sha256':hashlib.sha256(python).hexdigest()}}}), encoding='utf-8')
        (assets/'windows-installer/manifest.json').write_text(json.dumps({'selected_image':{
            'installation_type':'Server Core','architecture':'9','index':'1'}}), encoding='utf-8')
        (cls.root/'guest').mkdir()
        for name in ('windows_install.py','windows_bootstrap.py'):
            (cls.root/'guest'/name).write_bytes((ROOT/'guest'/name).read_bytes())
        with patch('agenticvm.windows_inputs.ROOT', cls.root):
            cls.files = inputs(RUN, TARGET, 'certificate', 'Lab1!' + 'a' * 24)
        cls.document = ET.fromstring(cls.files['Autounattend.xml'])
        cls.paths = [item.findtext('u:Path', namespaces=NS)
                     for item in cls.document.findall('.//u:RunSynchronousCommand', NS)]

    def test_selector_is_short(self):
        selectors = [path for path in self.paths if 'G.ps1' in path]
        self.assertEqual(len(selectors), 2)
        for path in selectors:
            self.assertLess(len(path), 260, 'SMI rejected a 624-char value')

    def test_selector_executes_pinned_script_directly(self):
        for path in self.paths:
            if 'G.ps1' not in path:
                continue
            self.assertIn('$PSScriptRoot', self.files['G.ps1'].decode())
            self.assertNotIn('Copy-Item', path)
            self.assertNotIn('-Source', path)
            self.assertIn("$h='", path)

    def test_boot_script_is_returned_once(self):
        self.assertIn('G.ps1', self.files)
        self.assertNotIn('GardenSeed.ps1', self.files)

    def test_tampered_python_dependency_is_still_refused(self):
        archive = self.root/'runtime/enrollment-images/python.zip'
        original = archive.read_bytes()
        try:
            archive.write_bytes(original+b'tamper')
            with patch('agenticvm.windows_inputs.ROOT', self.root):
                with self.assertRaisesRegex(ValueError, 'Pinned Windows Python dependency changed'):
                    inputs(RUN, TARGET, 'certificate', 'Lab1!'+'a'*24)
        finally:
            archive.write_bytes(original)

    def test_unapproved_windows_image_is_still_refused(self):
        manifest = self.root/'runtime/enrollment-images/windows-installer/manifest.json'
        original = manifest.read_bytes()
        try:
            manifest.write_text(json.dumps({'selected_image':{'installation_type':'Client','architecture':'9'}}),encoding='utf-8')
            with patch('agenticvm.windows_inputs.ROOT', self.root):
                with self.assertRaisesRegex(ValueError, 'Server Core'):
                    inputs(RUN, TARGET, 'certificate', 'Lab1!'+'a'*24)
        finally:
            manifest.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
