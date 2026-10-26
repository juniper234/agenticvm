"""Check Windows input scope and native PowerShell syntax without executing it."""
import json
import os
from pathlib import Path
import base64
import hashlib
import re
import secrets
import subprocess
import sys
import tempfile
from uuid import uuid4
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.windows_inputs import inputs
from agenticvm.lan_lab import certificate, digest, save


def main():
    folder = ROOT / 'runtime/windows-input-contracts' / str(uuid4())
    folder.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='garden-windows-input-') as temporary:
        private = Path(temporary)
        public = certificate(private, 'mother', '192.0.2.1')
        target = str(uuid4())
        # Fixture-only password exists in memory and the temporary XML; it is
        # neither a host credential nor retained in the public evidence.
        files = inputs(folder.name, target, public['certificate'], 'Lab1!' + secrets.token_urlsafe(20))
        document = ET.fromstring(files['Autounattend.xml'])
        ns = {'u': 'urn:schemas-microsoft-com:unattend'}
        disks = document.findall('.//u:DiskConfiguration/u:Disk/u:DiskID', ns)
        if [item.text for item in disks] != ['0']:
            raise ValueError('The Windows fixture disk selector changed')
        autologons = document.findall('.//u:AutoLogon', ns)
        if len(autologons) != 1:
            raise ValueError('Exactly one AutoLogon is required')
        autologon = autologons[0]
        for field, value in {'Username': 'Administrator', 'Enabled': 'true', 'LogonCount': '1'}.items():
            node = autologon.find('u:' + field, ns)
            if node is None or node.text != value:
                raise ValueError('AutoLogon field changed: ' + field)
        if not (autologon.findtext('u:Password', namespaces=ns) or '').startswith('Lab1!'):
            raise ValueError('AutoLogon password missing')
        commands = document.findall('.//u:RunSynchronous/u:RunSynchronousCommand', ns)
        copies = [item for item in commands if item.findtext('u:Order', namespaces=ns) == '1']
        if len(commands) != 3 or len(copies) != 2:
            raise ValueError('Expected two copy commands and one privacy command')
        want = None
        seed_hash = hashlib.sha256(files['G.ps1']).hexdigest()
        for copy_path in copies:
            command_text = copy_path.findtext('u:Path', namespaces=ns)
            if len(command_text) >= 260:
                raise ValueError('Selector command still too long: ' + str(len(command_text)))
            if 'Copy-Item' in command_text:
                raise ValueError('Selector should execute directly from media')
            match = re.search(r"\$h='([0-9A-F]{64})'", command_text)
            if not match or match.group(1) != seed_hash.upper():
                raise ValueError('G.ps1 hash missing from selector')
            if 'G.ps1' not in command_text or '-Source' in command_text:
                raise ValueError('Selector does not execute the pinned seed script')
        seed_text = files['G.ps1'].decode('utf-8')
        match = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", seed_text)
        if not match:
            raise ValueError('Asset allowlist missing from G.ps1')
        want = json.loads(base64.b64decode(match.group(1)))
        if set(want) | {'G.ps1', 'Autounattend.xml'} != set(files):
            raise ValueError('Seed allowlist names differ from returned assets')
        if want != {name: hashlib.sha256(files[name]).hexdigest() for name in want}:
            raise ValueError('Setup asset hash allowlist mismatch')
        setup_text = files['GardenSetup.cmd'].decode('ascii')
        if 'for %%D' in setup_text or '%~dp0GardenPrep.cmd' not in setup_text:
            raise ValueError('GardenSetup still re-scans drives')
        trust_doc = json.loads(files['trust.json'])
        token = trust_doc.get('install_token', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,64}', token):
            raise ValueError('Provisioning token missing or unbounded')
        for name, raw in (('windows_bootstrap.py', files['windows_bootstrap.py']),
                          ('windows_install.py', (ROOT / 'guest/windows_install.py').read_bytes())):
            if "'Authorization': 'Bearer '" not in raw.decode('utf-8'):
                raise ValueError('Provisioning Authorization missing from ' + name)
        installer = (ROOT / 'guest/windows_install.py').read_text()
        agent = (ROOT / 'guest/windows_agent.py').read_text()
        lfm = (ROOT / 'guest/windows_lfm.py').read_text()
        if "state': 'failed'" not in installer or 'def cleanup_failed' not in installer:
            raise ValueError('Failed-state cleanup missing')
        if installer.index('Remove-NetFirewallRule') > installer.index('Register-ScheduledTask'):
            raise ValueError('Firewall rule is created after task registration')
        if "identity['created']" not in agent or "value['created'] != created" not in installer:
            raise ValueError('Process creation binding missing')
        if 'Windows inference executable is not the installed llama-server' not in lfm:
            raise ValueError('Inference image path check missing')
        if 'Unblock-File' not in files['GardenPrep.ps1'].decode() or 'attempt -le 5' not in files['GardenActivate.ps1'].decode():
            raise ValueError('Python execution retry/unblock missing')
        if 'C:\\Program Files\\GardenControl' not in files['GardenPrep.ps1'].decode() or 'GARDEN_CONTROL' not in files['GardenActivate.ps1'].decode():
            raise ValueError('Activation control path override missing')
            raise ValueError('Python execution retry/unblock missing')
            raise ValueError('Inference image path check missing')
        checks = []
        for name in ('GardenPrep.ps1', 'GardenActivate.ps1', 'G.ps1'):
            path = private / name
            path.write_bytes(files[name])
            quoted = str(path).replace("'", "''")
            code = "$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + quoted + "',[ref]$tokens,[ref]$errors); @($errors | ForEach-Object {$_.Message}) | ConvertTo-Json -Compress; if($errors.Count){exit 1}"
            child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', code],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW,
                env={**os.environ, 'PSModulePath': str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')})
            if child.returncode or child.stdout.strip() not in ('', '[]'):
                raise ValueError('Native PowerShell syntax check failed for ' + name + ': ' + child.stdout[-1000:] + child.stderr[-1000:])
            checks.append({'file': name, 'native_powershell_parser_passed': True, 'executed': False})
        pins = {name: __import__('hashlib').sha256(raw).hexdigest() for name, raw in files.items()}
    proof = {'target_uuid': target, 'input_sha256': pins, 'powershell_checks': checks,
        'single_virtual_disk_selector': '0', 'fixture_administrator_password_retained': False,
        'autologon': True, 'hash_allowlisted_setup_assets': sorted(want),
        'installed_os_observed': False, 'native_model_observed': False, 'windows_sim_schema_validation': False}
    save(folder / 'input-checks.json', proof)
    source_names = ['src/agenticvm/windows_inputs.py', 'scripts/verify-windows-inputs.py',
        'guest/windows_bootstrap.py', 'guest/windows_install.py', 'guest/windows_agent.py', 'guest/windows_lfm.py']
    report = {'route': 'windows-unattend', 'level': 'adapter-built', 'passed': True, 'native_os_observed': False,
        'source_sha256': {name: digest(ROOT / name) for name in source_names},
        'evidence': [{'path': (folder / 'input-checks.json').relative_to(ROOT).as_posix(), 'sha256': digest(folder / 'input-checks.json')}],
        'limitations': ['Input generation, XML structure and actual PowerShell parser checks only; scripts were not executed',
            'No Windows SIM schema, native Setup, task/account/model, reboot or fault acceptance yet',
            'A future runner must attach exactly one fresh disposable virtual disk; never use this fixture on a physical machine']}
    save(folder / 'report.json', report)
    child = subprocess.run([sys.executable, '-I', '-B', 'scripts/enrollment-matrix.py', '--record', str(folder / 'report.json')],
        cwd=ROOT, capture_output=True, text=True)
    if child.returncode:
        raise RuntimeError('Windows input check could not be recorded: ' + child.stderr[-500:])
    print(json.dumps({'passed': True, 'native_acceptance': False, 'report': str(folder / 'report.json')}, indent=2))


if __name__ == '__main__':
    main()
