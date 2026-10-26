"""Local Windows guest tools over COM2. Runs inside the VM, never the host."""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(r'C:\ProgramData\AgenticVM')
WORKSPACE = Path(r'C:\workspace')
MAX_FILE = 1024 * 1024
MAX_FRAME = 2 * MAX_FILE
UUID = json.loads((ROOT / 'guest.json').read_text())['uuid']
API = ctypes.WinDLL('kernel32', use_last_error=True)
API.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
API.CreateFileW.restype = wintypes.HANDLE


def workspace_path(value):
    if not isinstance(value, str) or len(value) > 4096 or '\x00' in value:
        raise ValueError('Choose a path inside C:\\workspace.')
    value = value.replace('/', '\\')
    if value.lower().startswith('\\workspace\\'):
        value = 'C:' + value
    path = Path(value)
    if not path.is_absolute():
        path = WORKSPACE / path
    path = path.resolve()
    if not path.is_relative_to(WORKSPACE.resolve()) or path == WORKSPACE:
        raise ValueError('Choose a file inside C:\\workspace.')
    for parent in (path, *path.parents):
        if parent == WORKSPACE.parent:
            break
        if parent.is_symlink() or getattr(parent, 'is_junction', lambda: False)():
            raise ValueError('File paths must not redirect outside the workspace.')
    return path


def clipboard(value):
    if not isinstance(value, str) or len(value.encode('utf-8')) > 4096 or '\x00' in value:
        raise ValueError('Text is limited to 4096 UTF-8 bytes.')
    user = ctypes.WinDLL('user32', use_last_error=True)
    API.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    API.GlobalAlloc.restype = wintypes.HGLOBAL
    API.GlobalLock.argtypes = [wintypes.HGLOBAL]
    API.GlobalLock.restype = ctypes.c_void_p
    API.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    API.GlobalFree.argtypes = [wintypes.HGLOBAL]
    user.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user.SetClipboardData.restype = wintypes.HANDLE
    payload = (value + '\x00').encode('utf-16-le')
    handle = API.GlobalAlloc(0x0042, len(payload))
    if not handle:
        raise OSError('Clipboard allocation failed.')
    pointer = API.GlobalLock(handle)
    if not pointer:
        API.GlobalFree(handle)
        raise OSError('Clipboard allocation failed.')
    ctypes.memmove(pointer, payload, len(payload))
    API.GlobalUnlock(handle)
    opened = False
    try:
        for _ in range(10):
            if user.OpenClipboard(None):
                opened = True
                break
            time.sleep(.05)
        if not opened or not user.EmptyClipboard() or not user.SetClipboardData(13, handle):
            raise OSError('Clipboard is busy.')
        handle = None  # Windows owns the allocation after SetClipboardData.
    finally:
        if opened:
            user.CloseClipboard()
        if handle:
            API.GlobalFree(handle)
    return {'characters': len(value), 'method': 'guest-clipboard'}


def execute(command):
    if not isinstance(command, str) or len(command.encode('utf-8')) > 16384 or '\x00' in command:
        raise ValueError('Command is too long.')
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
            '[Console]::OutputEncoding=[Text.UTF8Encoding]::new();' + command], cwd=WORKSPACE,
            stdin=subprocess.DEVNULL, stdout=out, stderr=err, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            code = child.wait(30)
        except subprocess.TimeoutExpired:
            subprocess.run(['taskkill.exe', '/PID', str(child.pid), '/T', '/F'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            child.wait(5)
            raise ValueError('Command exceeded 30 seconds.') from None
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(65537), err.read(65537)
        return {'exit_code': code, 'stdout': stdout[:65536].decode('utf-8', 'replace'),
            'stderr': stderr[:65536].decode('utf-8', 'replace'),
            'truncated': len(stdout) > 65536 or len(stderr) > 65536}


def dispatch(request):
    op = request.get('op')
    if op == 'ping':
        # A console process alone is insufficient evidence of a working desktop.
        result = subprocess.run(['tasklist.exe', '/FI', 'IMAGENAME eq explorer.exe', '/FO', 'CSV', '/NH'],
            capture_output=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
        return {'desktop_ready': b'explorer.exe' in result.stdout.lower(),
            'os': 'Windows Server 2025 Evaluation', 'workspace': str(WORKSPACE), 'agent': 2, 'serial_baud': 115200}
    if op == 'exec':
        return execute(request['command'])
    if op == 'type':
        return clipboard(request['text'])
    if op == 'open-url':
        url = request['url']
        parts = urlsplit(url)
        if parts.scheme not in {'https', 'http'} or not parts.hostname or '\x00' in url or len(url) > 4096:
            raise ValueError('Use an HTTP or HTTPS URL.')
        os.startfile(url)
        return {'opened': True}
    if op == 'upload':
        data = base64.b64decode(request['data_b64'], validate=True)
        if len(data) > MAX_FILE:
            raise ValueError('Files are limited to 1 MiB.')
        path = workspace_path(request['path'])
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name('.upload-' + request['id'])
        try:
            temporary.write_bytes(data)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return {'bytes': len(data), 'path': str(path)}
    if op == 'download':
        path = workspace_path(request['path'])
        with path.open('rb') as source:
            data = source.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ValueError('Files are limited to 1 MiB.')
        return {'data_b64': base64.b64encode(data).decode('ascii')}
    if op == 'shutdown':
        subprocess.Popen(['shutdown.exe', '/s', '/t', '2'], creationflags=subprocess.CREATE_NO_WINDOW)
        return {'stopping': True}
    raise ValueError('Unknown guest action.')


class CommTimeouts(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in ('interval', 'read_multiplier', 'read_constant', 'write_multiplier', 'write_constant')]


class DCB(ctypes.Structure):
    _fields_ = [('length',wintypes.DWORD),('baud',wintypes.DWORD),('flags',wintypes.DWORD),
        ('reserved',wintypes.WORD),('xon_limit',wintypes.WORD),('xoff_limit',wintypes.WORD),
        ('byte_size',ctypes.c_ubyte),('parity',ctypes.c_ubyte),('stop_bits',ctypes.c_ubyte),
        ('xon',ctypes.c_char),('xoff',ctypes.c_char),('error_char',ctypes.c_char),
        ('eof_char',ctypes.c_char),('event_char',ctypes.c_char),('reserved1',wintypes.WORD)]


def configure_serial(handle):
    # Windows otherwise retains the port's previous/default baud and queues.
    # A large JSON file frame needs explicit speed and bounded receive buffers.
    settings = DCB(length=ctypes.sizeof(DCB))
    API.GetCommState.argtypes = [wintypes.HANDLE,ctypes.POINTER(DCB)]
    API.SetCommState.argtypes = [wintypes.HANDLE,ctypes.POINTER(DCB)]
    API.BuildCommDCBW.argtypes = [wintypes.LPCWSTR,ctypes.POINTER(DCB)]
    API.SetupComm.argtypes = [wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD]
    if not API.GetCommState(handle,ctypes.byref(settings)):
        raise ctypes.WinError(ctypes.get_last_error())
    previous_baud = settings.baud
    if not API.BuildCommDCBW('baud=115200 parity=n data=8 stop=1 xon=off odsr=off octs=off dtr=on rts=on',ctypes.byref(settings)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not API.SetCommState(handle,ctypes.byref(settings)) or not API.SetupComm(handle,MAX_FRAME,MAX_FRAME):
        raise ctypes.WinError(ctypes.get_last_error())
    (ROOT/'serial-config.json').write_text(json.dumps({'previous_baud':previous_baud,
        'baud':settings.baud,'buffer_bytes':MAX_FRAME,'agent':2}),encoding='utf-8')


def main():
    WORKSPACE.mkdir(exist_ok=True)
    handle = API.CreateFileW(r'\\.\COM2', 0xC0000000, 0, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    configure_serial(handle)
    # Return as soon as a byte arrives, instead of waiting to fill 4096 bytes.
    timeouts = CommTimeouts(0xffffffff, 0xffffffff, 1000, 0, 5000)
    API.SetCommTimeouts.argtypes = [wintypes.HANDLE, ctypes.POINTER(CommTimeouts)]
    if not API.SetCommTimeouts(handle, ctypes.byref(timeouts)):
        raise ctypes.WinError(ctypes.get_last_error())
    with os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY), 'r+b', buffering=0) as serial:
        pending = bytearray()
        while True:
            block = serial.read(4096)
            if not block:
                continue
            pending.extend(block)
            if len(pending) > MAX_FRAME:
                pending.clear()
                continue
            while b'\n' in pending:
                line, _, rest = pending.partition(b'\n')
                pending[:] = rest
                request = {}
                try:
                    request = json.loads(line)
                    if not isinstance(request, dict) or request.get('uuid') != UUID or not isinstance(request.get('id'), str) or not re_id(request['id']):
                        raise ValueError('Invalid guest request identity.')
                    response = {'ok': True, 'result': dispatch(request)}
                except Exception as error:
                    response = {'ok': False, 'error': str(error)[:1024]}
                response.update(id=request.get('id') if isinstance(request, dict) else None, uuid=UUID)
                payload = json.dumps(response, ensure_ascii=True).encode() + b'\n'
                if len(payload) <= MAX_FRAME:
                    view = memoryview(payload)
                    while view:
                        written = serial.write(view)
                        if not written:
                            raise OSError('Guest serial write failed.')
                        view = view[written:]


def re_id(value):
    return len(value) == 32 and all(character in '0123456789abcdef' for character in value)


if __name__ == '__main__':
    while True:
        try:
            main()
        except Exception as error:
            (ROOT / 'agent-error.log').write_text(str(error)[:2048], encoding='utf-8')
            time.sleep(3)
