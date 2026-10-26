"""C-017: the specialize selector must stay short enough for SMI."""
import sys
from pathlib import Path
import unittest
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


if __name__ == '__main__':
    unittest.main()
