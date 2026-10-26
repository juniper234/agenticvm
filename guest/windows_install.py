"""Reviewed Windows guest installer for one prepared disposable lab target.

Only fixed, hashed application assets are admitted. The persistent agent runs
under Local Service via Task Scheduler. No arbitrary administrative action is
accepted from model output or a network request.
"""
from __future__ import annotations
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import time
import urllib.request
from uuid import UUID
import zipfile

CONTROL = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'GardenControl'
HOME = CONTROL.with_name('Garden')
ORIGIN = 'https://192.0.2.1:8443'


def save(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def powershell(script):
    child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, text=True, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW,
        env={**os.environ, 'PSModulePath': str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')})
    if child.returncode:
        raise RuntimeError('Native Windows activation/observation failed: ' + child.stderr[-1500:])
    return json.loads(child.stdout) if child.stdout.strip() else None


def observation():
    return powershell("$os=Get-CimInstance Win32_OperatingSystem; @{sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
        "uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower(); os=$os.Caption; build=$os.BuildNumber; "
        "boot=$os.LastBootUpTime.ToUniversalTime().Ticks.ToString(); "
        "default_route=@(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'})} | ConvertTo-Json -Depth 4 -Compress")


def opener(certificate):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('Provisioning redirects are outside the fixed owned endpoint')
    context = ssl.create_default_context(cadata=certificate)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())


def request(client, path, body=None, limit=32768, *, token):
    if path not in ('/native/config', '/admission', '/native/receipt', '/manifest'):
        raise ValueError('Unapproved provisioning operation')
    data = json.dumps(body).encode() if body is not None else None
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    query = urllib.request.Request(ORIGIN + path, data=data, headers=headers)
    with client.open(query, timeout=30) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Oversized provisioning response')
    return json.loads(raw), raw


def download(client, name, entry, folder, *, token):
    path = folder / (name + '.partial')
    expected = entry['bytes']
    if type(expected) is not int or not 1 <= expected <= 300 * 1024**2:
        raise ValueError('Bounded native application asset size required')
    resumed = False
    for attempt in range(4):
        offset = path.stat().st_size if path.exists() else 0
        if offset > expected:
            raise ValueError('Partial asset exceeds the admitted size')
        if offset == expected:
            break
        headers = {'Range': 'bytes=' + str(offset) + '-'} if offset else {}
        headers['Authorization'] = 'Bearer ' + token
        try:
            with client.open(urllib.request.Request(ORIGIN + '/assets/' + name, headers=headers), timeout=30) as response:
                if response.status != (206 if offset else 200):
                    raise ValueError('Unexpected bounded asset response')
                if offset and response.headers.get('Content-Range') != f'bytes {offset}-{expected - 1}/{expected}':
                    raise ValueError('Asset resume range mismatch')
                resumed = resumed or bool(offset)
                with path.open('ab' if offset else 'wb') as output:
                    count = offset
                    while raw := response.read(256 * 1024):
                        count += len(raw)
                        if count > expected:
                            raise ValueError('Asset exceeded its admitted size')
                        output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
        except (OSError, http.client.IncompleteRead):
            if attempt == 3:
                raise
            time.sleep(.5)
    if not path.exists() or path.stat().st_size != expected:
        raise ValueError('Application asset transfer is incomplete')
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != entry['sha256']:
        raise ValueError('Application asset SHA256 mismatch before activation')
    return path, {'name': name, 'bytes': expected, 'sha256': actual, 'resumed': resumed}


def unpack(source, destination, *, allowed=None):
    with zipfile.ZipFile(source) as archive:
        entries, total = archive.infolist(), 0
        if not 1 <= len(entries) <= 128 or len({entry.filename.lower() for entry in entries}) != len(entries):
            raise ValueError('Unexpected application ZIP inventory')
        names = set()
        for entry in entries:
            name = entry.filename
            if (entry.is_dir() or '/' in name or '\\' in name or ':' in name or name in ('', '.', '..')
                    or name.endswith(('.', ' ')) or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.file_size > 64 * 1024**2):
                raise ValueError('Unexpected application ZIP member')
            total += entry.file_size
            if total > 256 * 1024**2:
                raise ValueError('Application ZIP expansion exceeded its bound')
            names.add(name)
        if allowed is not None and names != allowed:
            raise ValueError('Agent ZIP has an unexpected module set')
        destination.mkdir(exist_ok=False)
        for entry in entries:
            (destination / entry.filename).write_bytes(archive.read(entry))


def task_process():
    path = HOME / 'agent-process.json'
    if not path.exists():
        return None
    identity = json.loads(path.read_text())
    pid, created = identity.get('pid'), identity.get('created')
    if type(pid) is not int or pid <= 0 or not isinstance(created, str) or not created.isdigit():
        raise ValueError('Invalid Windows task process identity')
    value = powershell('$p=Get-CimInstance Win32_Process -Filter "ProcessId=' + str(pid) + '"; '
        "if ($null -eq $p) { @{} | ConvertTo-Json -Compress; exit }; "
        "$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid; $t=Get-ScheduledTask -TaskName GardenNative; "
        "@{pid=$p.ProcessId; created=$p.CreationDate.ToUniversalTime().Ticks.ToString(); executable=$p.ExecutablePath; "
        "command_line=$p.CommandLine; sid=$o.Sid; task_state=$t.State.ToString()} | ConvertTo-Json -Compress")
    if not value:
        return None
    expected = str(CONTROL / 'python/python.exe')
    if (value['sid'] != 'S-1-5-19' or value['created'] != created
            or value['executable'].lower() != expected.lower()
            or str(HOME / 'peer/windows_agent.py').lower() not in value['command_line'].lower()
            or value['task_state'] != 'Running'):
        raise ValueError('Native Windows task process differs from its prepared activation')
    return value


def cleanup_failed():
    if HOME.exists():
        shutil.rmtree(HOME, ignore_errors=True)
    incoming = CONTROL / 'incoming'
    if incoming.exists():
        shutil.rmtree(incoming, ignore_errors=True)
    powershell("$ErrorActionPreference='SilentlyContinue'; "
        "Unregister-ScheduledTask -TaskName GardenNative -Confirm:$false; "
        "Remove-NetFirewallRule -DisplayName GardenNativeIsolated")


def main(config, trust):
    native = observation()
    if (os.name != 'nt' or native['sid'] != 'S-1-5-18' or native['uuid'] != trust['target_uuid']
            or native['default_route'] or config['garden'] != trust['garden'] or config['identity'] != 'sprout-4'
            or str(UUID(config['garden'])) != config['garden']):
        raise ValueError('Owned Windows target, SYSTEM installer identity or isolated network scope mismatch')
    ledger = CONTROL / 'activation.json'
    if ledger.exists():
        previous = json.loads(ledger.read_text())
        if previous.get('state') == 'failed' and previous.get('garden') == config['garden']:
            cleanup_failed()
            ledger.unlink()
        elif previous.get('state') != 'completed' or previous['garden'] != config['garden']:
            raise ValueError('Uncertain Windows activation is not automatically replayed')
        else:
            process = task_process()
            if not process:
                raise ValueError('Completed Windows activation has no live native task')
            return previous['receipt'] | {'duplicate': True, 'process': process}
    absence = {name: (HOME / name).exists() for name in ('peer/windows_agent.py', 'model.gguf', 'identity.key', 'lan-config.json')}
    if any(absence.values()) or HOME.exists() and any(HOME.iterdir()):
        raise ValueError('Windows enrollment target already has garden state')
    save(ledger, {'state': 'executing', 'garden': config['garden']})
    try:
        token = trust['install_token']
        client = opener(config['mother_certificate'])
        request(client, '/admission', {key: config[key] for key in ('request_id', 'identity', 'grant')}, token=token)
        manifest, raw = request(client, '/manifest', token=token)
        if hashlib.sha256(raw).hexdigest() != config['manifest_sha256'] or set(manifest['files']) != {'model.gguf', 'llama.zip', 'agent.zip'}:
            raise ValueError('Windows asset manifest scope or digest mismatch')
        incoming = CONTROL / 'incoming'
        incoming.mkdir(exist_ok=False)
        downloads, files = [], {}
        for name in ('model.gguf', 'llama.zip', 'agent.zip'):
            files[name], proof = download(client, name, manifest['files'][name], incoming, token=token)
            downloads.append(proof)
        HOME.mkdir(exist_ok=True)
        unpack(files['agent.zip'], HOME / 'peer', allowed={'lan_agent.py', 'local_lfm.py', 'lfm_protocol.py', 'windows_agent.py'})
        unpack(files['llama.zip'], HOME / 'llama')
        files['model.gguf'].replace(HOME / 'model.gguf')
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID
        key = Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'sprout-4')])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('urn:agenticvm:lan:sprout-4'),
                x509.IPAddress(ipaddress.ip_address('192.0.2.4'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, algorithm=None))
        (HOME / 'identity.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (HOME / 'identity.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        save(HOME / 'lan-config.json', config | {'target_uuid': trust['target_uuid']})
        powershell("$ErrorActionPreference='Stop'; $base='C:\\ProgramData\\Garden'; "
            "& icacls.exe $base /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' /T /Q | Out-Null; "
            "if ($LASTEXITCODE -ne 0) {throw 'Garden task ACL failed'}; "
            "Remove-NetFirewallRule -DisplayName GardenNativeIsolated -ErrorAction SilentlyContinue; "
            "New-NetFirewallRule -DisplayName GardenNativeIsolated -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9443 "
            "-RemoteAddress 192.0.2.0/24 -Profile Any | Out-Null")
        powershell("$ErrorActionPreference='Stop'; $base='C:\\ProgramData\\Garden'; "
            f"$action=New-ScheduledTaskAction -Execute '{CONTROL}\\python\\python.exe' "
            "-Argument '-I -B \"C:\\ProgramData\\Garden\\peer\\windows_agent.py\"' -WorkingDirectory $base; "
            "$trigger=New-ScheduledTaskTrigger -AtStartup; $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount -RunLevel Limited; "
            "$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable; "
            "Register-ScheduledTask -TaskName GardenNative -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null; "
            "Start-ScheduledTask -TaskName GardenNative")
        deadline, process = time.monotonic() + 120, None
        while time.monotonic() < deadline:
            process = task_process()
            if process:
                break
            error = HOME / 'windows-agent-error.json'
            if error.exists():
                raise RuntimeError('Native Windows task failed: ' + error.read_text()[:1800])
            time.sleep(.5)
        if not process:
            raise TimeoutError('Native Windows task process was not observed')
        receipt = {'ok': True, 'duplicate': False, 'garden': config['garden'], 'target_uuid': trust['target_uuid'],
            'initial_absence': absence, 'native_windows': native, 'activation': 'Windows Task Scheduler',
            'agent_account_sid': 'S-1-5-19', 'process': process, 'downloads': downloads}
        save(ledger, {'state': 'completed', 'garden': config['garden'], 'receipt': receipt})
        return receipt
    except Exception as error:
        save(ledger, {'state': 'failed', 'garden': config['garden'],
                      'error': type(error).__name__ + ': ' + str(error)[:500]})
        raise
