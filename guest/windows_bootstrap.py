"""Prepared Windows native entry: pin the reviewed installer before execution."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import types
import urllib.request

def _control():
    override = os.environ.get('GARDEN_CONTROL')
    return Path(override) if override else Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'GardenControl'


CONTROL = _control()
HOME = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'Garden'


def powershell(script):
    child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW,
        env={**os.environ, 'PSModulePath': str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')})
    if child.returncode:
        raise RuntimeError('Native Windows prerequisite observation failed: ' + child.stderr[-1200:])
    return json.loads(child.stdout)


def emit(marker, value):
    raw = (marker + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\r\n').encode()
    if len(raw) > 65536:
        raise ValueError('Oversized Windows serial evidence')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    api.WriteFile.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    handle = api.CreateFileW('\\\\.\\COM1', 0x40000000, 0, None, 3, 0, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        count = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(raw)
        if not api.WriteFile(handle, buffer, len(raw), ctypes.byref(count), None) or count.value != len(raw):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        api.CloseHandle(handle)


def observe():
    return powershell("$o=Get-CimInstance Win32_OperatingSystem; $t=Get-ScheduledTask -TaskName GardenNative -ErrorAction SilentlyContinue; "
        "@{sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
        "uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower(); os=$o.Caption; build=$o.BuildNumber; "
        "boot=$o.LastBootUpTime.ToUniversalTime().Ticks.ToString(); task_state=$(if($null -eq $t){'absent'}else{$t.State.ToString()}); "
        "default_route=@(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'})} | ConvertTo-Json -Depth 5 -Compress")


def main():
    native, owned = None, False
    try:
        trust = json.loads((CONTROL / 'trust.json').read_text())
        native = observe()
        owned = os.name == 'nt' and native['sid'] == 'S-1-5-18' and native['uuid'] == trust['target_uuid']
        if (os.name != 'nt' or native['sid'] != 'S-1-5-18' or native['uuid'] != trust['target_uuid']
                or native['default_route']):
            raise ValueError('Prepared Windows entry does not match its owned VM and SYSTEM scope')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('Bootstrap redirects are outside the owner-prepared endpoint')
        context = ssl.create_default_context(cadata=trust['mother_certificate'])
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
        auth = {'Authorization': 'Bearer ' + trust['install_token']}
        with client.open(urllib.request.Request('https://192.0.2.1:8443/native/config', headers=auth), timeout=30) as response:
            raw = response.read(32769)
        if len(raw) > 32768:
            raise ValueError('Oversized Windows bootstrap configuration')
        config = json.loads(raw)
        if config['garden'] != trust['garden'] or config['mother_certificate'] != trust['mother_certificate']:
            raise ValueError('Windows bootstrap garden or trust changed')
        with client.open(urllib.request.Request('https://192.0.2.1:8443/windows/installer', headers=auth), timeout=30) as response:
            raw = response.read(65537)
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != trust['installer_sha256']:
            raise ValueError('Windows reviewed bootstrap installer SHA256 mismatch')
        module = types.ModuleType('reviewed_windows_install')
        exec(compile(raw, '<reviewed-owned-windows-installer>', 'exec'), module.__dict__)
        installed = module.main(config, trust)
        duplicate = module.main(config, trust)
        if not duplicate['duplicate'] or installed['process'] != duplicate['process']:
            raise ValueError('Duplicate Windows enrollment created another native task process')
        receipt = {'ok': True, 'initial_absence': installed['initial_absence'],
            'installed': installed, 'duplicate': duplicate, 'native_windows': native,
            'agent_account_sid': installed['agent_account_sid'], 'activation': installed['activation']}
        body = {'request_id': config['request_id'], 'identity': config['identity'], 'grant': config['grant'], 'receipt': receipt}
        query = urllib.request.Request('https://192.0.2.1:8443/native/receipt', data=json.dumps(body).encode(),
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + trust['install_token']})
        with client.open(query, timeout=30) as response:
            accepted = json.loads(response.read(32769))
        if accepted != {'ok': True}:
            raise ValueError('Mother did not acknowledge the native Windows receipt')
        emit('WINDOWS_INSTALL_COMPLETE', {'target_uuid': trust['target_uuid'], 'boot': native['boot'],
            'process': installed['process'], 'agent_account_sid': installed['agent_account_sid']})
        return 0
    except Exception as error:
        if not owned:
            print('Windows bootstrap refused outside its bound target: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
            return 1
        proof = {'error': type(error).__name__ + ': ' + str(error), 'native_windows': native,
            'activation_paths': {name: (HOME / name).exists() for name in ('peer/windows_agent.py', 'model.gguf', 'identity.key', 'lan-config.json')}}
        try:
            proof['native_windows'] = observe()
        except Exception as observation_error:
            proof['observation_error'] = str(observation_error)
        emit('WINDOWS_DENIAL_PROOF', proof)
        emit('WINDOWS_INSTALL_FAILED', {'error': proof['error']})
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
