"""Temporary HTTPS access to the running DeepSeek companion. No browser automation.

--check is read-only and needs no credential. --start explicitly exposes the
already enabled companion through Cloudflare; it never starts a model turn.
Keep this process running. --stop asks this exact worker to close its own tunnel.
Secrets are used in memory and the owner's connection file, never stdout/logs.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
HOME = Path(os.environ.get('DSH_HOME', str(Path.home() / '.dsh')))
PRIVATE = HOME / 'remote-control'
STATE = PRIVATE / 'internet-access-state.json'
STOP = PRIVATE / 'internet-access.stop'
LINK = PRIVATE / 'Connect-from-another-PC.txt'
PIN = '4d2490e74082c5d48dbfedaf92576fa5bd1702379ab88eb7faa0cfbe8dc891b6'
EXE = ROOT / 'tools/cloudflared/2026.10.1/cloudflared.exe'


def own_child(child):
    """Close the tunnel even if the launcher crashes or its window is closed."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    class Limits(ctypes.Structure):
        _fields_ = [('time1', ctypes.c_longlong), ('time2', ctypes.c_longlong),
                    ('flags', wintypes.DWORD), ('min', ctypes.c_size_t), ('max', ctypes.c_size_t),
                    ('active', wintypes.DWORD), ('affinity', ctypes.c_size_t),
                    ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]
    class Extended(ctypes.Structure):
        _fields_ = [('basic', Limits), ('io', ctypes.c_ulonglong * 6),
                    ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                    ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
    handle = kernel.CreateJobObjectW(None, None)
    limits = Extended()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not handle or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        if handle:
            kernel.CloseHandle(handle)
        raise RuntimeError('Could not establish automatic tunnel cleanup.')
    if not kernel.AssignProcessToJobObject(handle, wintypes.HANDLE(int(child._handle))):
        kernel.CloseHandle(handle)
        raise RuntimeError('Could not bind the tunnel to its launcher lifetime.')
    return lambda: kernel.CloseHandle(handle)


def save(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temp.replace(path)


def local_request(port, path, token=None, body=None):
    """Direct loopback socket; never inherit a system HTTP proxy or redirects."""
    headers = {}
    if token:
        headers['x-companion-token'] = token
    if body is not None:
        headers.update({'content-type': 'application/json', 'x-dsh-remote-control': '1',
                        'origin': f'http://127.0.0.1:{port}'})
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    try:
        connection.request('POST' if body is not None else 'GET', path,
                           json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read(16 * 1024 * 1024)
    finally:
        connection.close()


def action(port, token, body):
    status, _, raw = local_request(port, '/api/remote-control', token, body)
    if status != 200:
        raise RuntimeError('Companion control API rejected the request.')
    result = json.loads(raw)
    if result.get('ok') is not True:
        raise RuntimeError('Companion control operation failed; no request was replayed.')
    return result['value']


def cloudflare_origin(text):
    match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com(?![a-z0-9.-])', text)
    return match.group(0) if match else None


def check(port):
    if hashlib.sha256(EXE.read_bytes()).hexdigest() != PIN:
        raise RuntimeError('The prepared Cloudflare executable does not match its verified hash.')
    status, _, _ = local_request(port, '/companion/health')
    if status != 401:
        raise RuntimeError('Expected the running companion to refuse unauthenticated access.')
    return {'passed': True, 'companion_port': port, 'unauthenticated_status': status,
            'cloudflared_sha256': PIN, 'credentials_used': False,
            'tunnel_started': False, 'firewall_changes': False}


def start(port):
    import msvcrt
    check(port)
    # Exclusive Windows lock: a second launcher must never replace a live worker.
    with (PRIVATE / 'internet-access.lock').open('a+b') as lock:
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b'0'); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError('An internet-access worker is already running. Use --status.')
        settings = json.loads((PRIVATE / 'companion.json').read_text(encoding='utf-8'))
        if not settings.get('enabled') or settings.get('port') != port:
            raise RuntimeError('Enable Device sharing in DeepSeek and use its current local port.')
        token = settings.get('token')
        if not isinstance(token, str) or len(token) < 32:
            raise RuntimeError('The existing companion credential is unavailable.')
        code, _, raw = local_request(port, '/companion/health', token)
        health = json.loads(raw) if code == 200 else {}
        if health.get('app') != 'desktop' or not health.get('capabilities', {}).get('sessions'):
            raise RuntimeError('The running endpoint is not a healthy DeepSeek companion.')
        code, _, shell = local_request(port, '/', token)
        if code != 200 or b'<html' not in shell.lower():
            raise RuntimeError('The companion cannot serve the browser interface.')
        STOP.unlink(missing_ok=True)
        # A fresh empty config avoids inheriting a named tunnel or account config.
        config = PRIVATE / 'internet-access-cloudflared.yml'
        config.write_text('{}\n', encoding='utf-8')
        worker = {'state': 'starting', 'worker_pid': os.getpid(), 'companion_port': port,
                  'connection_file': str(LINK), 'desktop_enabled': health.get('capabilities', {}).get('desktop'),
                  'cloudflared_sha256': PIN, 'model_calls_made': 0, 'firewall_changes': False}
        save(STATE, worker)
        origin = None
        child = None
        close_job = None
        old_origin = settings.get('publicOrigin')
        lines = []
        try:
            child = subprocess.Popen([str(EXE), 'tunnel', '--config', str(config),
                '--no-autoupdate', '--protocol', 'http2', '--url', f'http://127.0.0.1:{port}'],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace', creationflags=subprocess.CREATE_NO_WINDOW)
            close_job = own_child(child)
            worker['tunnel_pid'] = child.pid
            save(STATE, worker)
            def read_lines():
                for line in child.stdout:
                    # No raw provider logs or authentication URLs are retained.
                    lines.append(line.strip())
                    if len(lines) > 100:
                        del lines[:50]
            threading.Thread(target=read_lines, daemon=True).start()
            deadline = time.monotonic() + 75
            while time.monotonic() < deadline:
                if STOP.exists():
                    return
                if child.poll() is not None:
                    raise RuntimeError('Cloudflare exited before the tunnel became ready.')
                output = '\n'.join(lines)
                origin = cloudflare_origin(output)
                if origin and 'Registered tunnel connection' in output:
                    break
                time.sleep(.5)
            else:
                raise RuntimeError('Cloudflare did not establish a connection within 75 seconds.')
            paired = action(port, token, {'action': 'sharing.pairing', 'publicUrl': origin})
            link = paired.get('url', '')
            parsed = urlsplit(link)
            if f'{parsed.scheme}://{parsed.netloc}' != origin or not parsed.query.startswith('k='):
                raise RuntimeError('The companion returned an unexpected pairing address.')
            LINK.write_text('DEEPSEEK REMOTE ACCESS — PRIVATE\n\n'
                'On the other PC, open this complete link in Chrome, Edge or Firefox:\n\n'
                + link + '\n\nKeep this link private: it grants the existing DeepSeek sharing permissions.\n'
                'Keep this PC and DeepSeek running. Stop-DeepSeek-Remote.cmd ends internet access.\n'
                'The temporary address changes after restarting the tunnel.\n', encoding='utf-8')
            worker.update(state='ready', origin=origin, local_authenticated_shell=True,
                          local_authenticated_health=True, external_browser_verified=False)
            save(STATE, worker)
            print(json.dumps({'state': 'ready', 'connection_file': str(LINK)}, indent=2), flush=True)
            while child.poll() is None and not STOP.exists():
                time.sleep(1)
            if child.poll() is not None:
                raise RuntimeError('The HTTPS tunnel exited. Start it again to get a fresh link.')
        finally:
            # Popen retains this child's OS handle. No process-name/PID-based killing.
            if child and child.poll() is None:
                child.terminate()
                try:
                    child.wait(10)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(5)
            if close_job:
                close_job()
            restored = False
            try:
                current = json.loads((PRIVATE / 'companion.json').read_text(encoding='utf-8'))
                if origin and current.get('publicOrigin') == origin:
                    action(port, token, {'action': 'sharing.pairing',
                           'publicUrl': old_origin or f'http://127.0.0.1:{port}'})
                    restored = True
            except Exception:
                pass
            LINK.unlink(missing_ok=True)
            worker.update(state='stopped', previous_origin_restored=restored)
            save(STATE, worker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--start', action='store_true')
    group.add_argument('--stop', action='store_true')
    group.add_argument('--status', action='store_true')
    group.add_argument('--check', action='store_true')
    parser.add_argument('--port', type=int, default=8099)
    args = parser.parse_args()
    if args.start:
        start(args.port)
    elif args.stop:
        if not STATE.exists() or json.loads(STATE.read_text(encoding='utf-8')).get('state') not in ('starting', 'ready'):
            print('No managed internet-access tunnel is running.'); return
        STOP.touch()
        print('Stop requested. The tunnel worker will close its own connection.')
    elif args.status:
        print(STATE.read_text(encoding='utf-8') if STATE.exists() else '{"state":"not-started"}')
    else:
        print(json.dumps(check(args.port), indent=2))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Remote access closed.')
    except Exception as error:
        # Never emit exception data from HTTP, providers, settings, or pairing.
        safe = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print('Remote access failed: ' + safe, file=sys.stderr)
        raise SystemExit(1)
