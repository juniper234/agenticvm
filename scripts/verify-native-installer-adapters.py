"""Build the actual native-runner inputs without launching or installing an OS."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.debian_installer_lab import DebianInstallerAdapter
from agenticvm.ubuntu_installer_lab import UbuntuInstallerAdapter
from agenticvm.rpm_installer_lab import RPMInstallerAdapter
from agenticvm.native_enrollment import native_config
from agenticvm.lan_lab import certificate, digest, save


def main():
    root = ROOT / 'runtime/native-installer-contracts' / str(uuid4())
    root.mkdir(parents=True)
    receipts = []
    with tempfile.TemporaryDirectory(prefix='garden-installer-input-') as temporary:
        public = {'mother': certificate(Path(temporary), 'mother', '192.0.2.1')}
        for adapter in (DebianInstallerAdapter(), UbuntuInstallerAdapter(),
                        RPMInstallerAdapter('anaconda-kickstart'), RPMInstallerAdapter('autoyast')):
            folder = root / str(uuid4())
            folder.mkdir()
            runtime = json.loads((ROOT / 'runtime/enrollment-images/portable-python.json').read_text())
            payloads, metadata = native_config('cloud-init-local', folder.name, public, runtime)
            _, served = adapter.prepare_inputs(folder, public, runtime, payloads, metadata)
            checks = ['Actual native runner input preparation', 'One explicit blank /dev/vda target in the installer profile',
                      'Digest-pinned first-boot script', 'Installer completion marker separate from installed-OS boots']
            if adapter.route == 'ubuntu-autoinstall':
                level = 'contract-tested'
                checks.append('Upstream Subiquity JSON schema validates the actual offline autoinstall inputs')
            elif adapter.route == 'autoyast':
                level = 'contract-tested'
                checks.append('Distribution AutoYaST RelaxNG validates the actual native profile')
            elif adapter.route == 'anaconda-kickstart':
                level = 'contract-tested'
                checks.append('Upstream pykickstart F44 validates the actual native profile')
            else:
                level = 'adapter-built'
                checks.append('Native installer validation required; local structure is not schema/OS acceptance')
            source_names = ['scripts/verify-native-installer-adapters.py', 'src/agenticvm/native_enrollment.py',
                            'guest/native_bootstrap.py', *adapter.source_paths]
            receipt = {'route': adapter.route, 'level': level, 'passed': True, 'native_os_observed': False,
                'source_sha256': {name: digest(ROOT / name) for name in source_names},
                'evidence': [{'path': path.relative_to(ROOT).as_posix(), 'sha256': digest(path), 'checks': checks}
                    for path in folder.iterdir() if path.is_file()],
                'served_input_pins': {path: hashlib.sha256(__import__('base64').b64decode(raw)).hexdigest()
                    for path, raw in served.items()},
                'limitations': ['No VM launch, installation, model call, reboot or fault acceptance in this check',
                                'Pinned installation media, host memory/storage and real native tests remain necessary']}
            report = folder / 'report.json'
            save(report, receipt)
            receipts.append(report.relative_to(ROOT).as_posix())
            recorded = subprocess.run([sys.executable, '-I', '-B', 'scripts/enrollment-matrix.py', '--record', str(report)],
                cwd=ROOT, capture_output=True, text=True)
            if recorded.returncode:
                raise RuntimeError('Could not record native installer adapter input checks: ' + recorded.stderr[-500:])
    save(root / 'report.json', {'passed': True, 'native_acceptance': False, 'receipts': receipts})
    print(json.dumps({'passed': True, 'native_acceptance': False, 'report': str(root / 'report.json')}, indent=2))


if __name__ == '__main__':
    main()
