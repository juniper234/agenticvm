"""Check native installer adapter inputs; never start an installer on the host."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import urllib.request
from uuid import uuid4
import warnings
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tools/enrollment-validators')]
from agenticvm.installer_profiles import ROUTES, profile
from agenticvm.lan_lab import certificate, digest, save


def main():
    import jsonschema
    from pykickstart.parser import KickstartParser
    from pykickstart.version import makeVersion
    schema_path = ROOT / 'tools/enrollment-validators/autoinstall-schema.json'
    url = 'https://raw.githubusercontent.com/canonical/subiquity/main/autoinstall-schema.json'
    if not schema_path.exists():
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('Installer schema exceeds its bound')
        json.loads(raw)
        schema_path.write_bytes(raw)
        save(schema_path.with_suffix('.provenance.json'), {'url': url, 'sha256': digest(schema_path),
             'trust': 'Upstream HTTPS source; no detached signature verification claimed'})
    provenance = json.loads(schema_path.with_suffix('.provenance.json').read_text())
    if digest(schema_path) != provenance['sha256']:
        raise ValueError('Upstream installer schema changed')
    run_id = str(uuid4())
    folder = ROOT / 'runtime/installer-profile-contracts' / run_id
    folder.mkdir(parents=True)
    runtime = json.loads((ROOT / 'runtime/enrollment-images/portable-python.json').read_text())
    sources = {name: digest(ROOT / name) for name in ('src/agenticvm/installer_profiles.py',
        'src/agenticvm/native_enrollment.py', 'guest/native_bootstrap.py', 'scripts/verify-installer-profiles.py')}
    receipts = []
    with tempfile.TemporaryDirectory(prefix='garden-profile-contract-') as temporary:
        public = {'mother': certificate(Path(temporary), 'mother', '192.0.2.1')}
        for route in ROUTES:
            built = profile(route, run_id, public, runtime)
            directory = folder / route
            directory.mkdir()
            (directory / built['profile_name']).write_bytes(built['profile'])
            (directory / 'firstboot.sh').write_bytes(built['firstboot_script'])
            if hashlib.sha256(built['firstboot_script']).hexdigest() != built['firstboot_sha256']:
                raise ValueError('Installer bootstrap pin mismatch')
            level = 'adapter-built'
            checks = ['Profile generated for one explicit /dev/vda disk', 'Exact immutable first-boot script pin']
            if route == 'ubuntu-autoinstall':
                payload = json.loads(built['profile'].decode().split('\n', 1)[1])['autoinstall']
                jsonschema.validate(payload, json.loads(schema_path.read_text()))
                if payload['storage']['layout']['match'] != {'path': '/dev/vda'} or payload['ssh']['allow-pw']:
                    raise ValueError('Subiquity adapter target/auth policy mismatch')
                checks.append('Independent upstream Subiquity JSON schema via jsonschema 4.25.1')
                level = 'contract-tested'
            elif route == 'anaconda-kickstart':
                with warnings.catch_warnings():
                    warnings.simplefilter('error')
                    parsed = KickstartParser(makeVersion('F44'), followIncludes=False, errorsAreFatal=True)
                    parsed.readKickstartFromString(built['profile'].decode())
                if parsed.handler.ignoredisk.onlyuse != ['vda'] or parsed.handler.clearpart.drives != ['vda']:
                    raise ValueError('Kickstart parser observed an unexpected disk scope')
                checks.append('Independent upstream pykickstart 3.78 F44 parser; warnings are failures')
                level = 'contract-tested'
            elif route == 'autoyast':
                document = ET.fromstring(built['profile'])
                namespace = {'y': 'http://www.suse.com/1.0/yast2ns'}
                disks = document.findall('y:partitioning/y:drive/y:device', namespace)
                if [item.text for item in disks] != ['/dev/vda']:
                    raise ValueError('AutoYaST XML has ambiguous disk selection')
                checks.append('XML well-formedness and explicit disk selector; native YaST validation still required')
            else:
                rows = built['profile'].decode().splitlines()
                if rows.count('d-i partman-auto/disk string /dev/vda') != 1:
                    raise ValueError('Preseed has ambiguous disk selection')
                if not any(row.startswith('d-i preseed/late_command string ') and built['firstboot_sha256'] in row for row in rows):
                    raise ValueError('Preseed lost its pinned late hook')
                checks.append('Preseed debconf field structure; real Debian Installer validation still required')
            receipt = {'route': route, 'level': level, 'passed': True, 'source_sha256': sources,
                'evidence': [{'path': (directory / built['profile_name']).relative_to(ROOT).as_posix(),
                              'sha256': digest(directory / built['profile_name']), 'checks': checks}],
                'limitations': ['No OS installation, enrollment, model execution, reboot or fault acceptance is claimed',
                    'Installer must have a publisher-pinned local package source before native testing'],
                'native_os_observed': False, 'kernel_parameters': built['kernel_parameters']}
            save(directory / 'report.json', receipt)
            receipts.append((directory / 'report.json').relative_to(ROOT).as_posix())
    save(folder / 'report.json', {'passed': True, 'native_acceptance': False, 'receipts': receipts,
         'validator_schema_sha256': digest(schema_path), 'source_sha256': sources})
    print(json.dumps({'passed': True, 'native_acceptance': False, 'report': str(folder / 'report.json'),
                      'receipts': receipts}, indent=2))


if __name__ == '__main__':
    main()
