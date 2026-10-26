"""Resume the project's official DeepSeek session, with durable local progress.

Default: start a hidden worker and return its status/log paths. --status is
read-only; --check-only validates prerequisites without making a model call.
The child uses the existing harness account, never a copied API key.
Run this host application launcher with the installed host Python, as the CMD
wrapper does. The isolated guest-tool Python runs with a low Windows integrity
token here and cannot maintain the harness's user-profile files.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / 'runtime/deepseek-development'
ACTIVE = PARENT / 'active.json'
SESSION_FILE = PARENT / 'session.json'


def now():
    return datetime.now(timezone.utc).isoformat()


def process_creation(pid):
    """Read a Windows process creation identity; never infer ownership from PID."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            return None
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    finally:
        kernel.CloseHandle(handle)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temp.replace(path)


def prerequisites():
    shim, node = shutil.which('dsh.cmd'), shutil.which('node.exe')
    if not shim or not node:
        raise RuntimeError('Official DeepSeek Harness and Node.js are required')
    package = Path(shim).parent / 'node_modules/@deepseek-ai/dsh'
    manifest = json.loads((package / 'package.json').read_text())
    if manifest['name'] != '@deepseek-ai/dsh':
        raise ValueError('Unexpected harness package')
    paths = [package / 'lib/bin.js',
        ROOT / 'AGENTS.md', ROOT / 'docs/handover/deepseek-account.patch.yml',
        ROOT / 'docs/handover/deepseek-tools.patch.yml',
        ROOT / 'docs/handover/DEEPSEEK-DEVELOPMENT-TASK.txt',
        ROOT / 'agenticvm-mcp.ps1',
        ROOT / 'tools/rea/node_modules/rea-agents/scripts/rea.mjs',
        ROOT / 'tools/python-runtime/3.13.16/python.exe',
        ROOT / 'docs/handover/deepseek-development-permissions.patch.yml',
        Path.home() / '.dsh/profiles/agenticvm/package.json',
        Path.home() / '.dsh/profiles/agenticvm/cordis.patch.yml']
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise FileNotFoundError('Missing prerequisites: ' + ', '.join(missing))
    expected = '\n'.join((ROOT / 'docs/handover' / name).read_text(encoding='utf-8')
        for name in ('deepseek-account.patch.yml', 'deepseek-tools.patch.yml', 'deepseek-development-permissions.patch.yml'))
    actual = (Path.home() / '.dsh/profiles/agenticvm/cordis.patch.yml').read_text(encoding='utf-8')
    if actual != expected:
        raise ValueError('Dedicated profile differs from project setup files; reconcile it before starting another turn')
    return node, paths[0], manifest['version']


def worker(folder, session_id, task_file):
    import msvcrt
    node, launcher, version = prerequisites()
    # Hold a real OS lock for this whole development turn. Never run two workers.
    with (PARENT / 'controller.lock').open('a+b') as lock:
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b'0')
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            save(folder / 'status.json', {'state': 'rejected', 'reason': 'Another project DeepSeek worker owns the lock', 'updated_at': now()})
            return 2
        state = {'state': 'starting', 'updated_at': now(), 'started_at': now(),
            'worker_pid': os.getpid(), 'session_id': session_id, 'workspace': str(ROOT),
            'worker_created_filetime': process_creation(os.getpid()),
            'harness_version': version, 'profile': 'agenticvm',
            'task_file': str(task_file), 'tool_calls': 0, 'completed_tool_results': 0,
            'log': str(folder / 'events.jsonl'), 'report': str(folder / 'status.json')}
        save(folder / 'status.json', state)
        save(ACTIVE, {'run': str(folder), 'status': str(folder / 'status.json')})
        command = [node, str(launcher), '--profile', 'agenticvm', '--json']
        if session_id:
            command += ['--session-id', session_id]
        command += ['-']
        try:
            child = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding='utf-8', errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW)
            state.update(state='running', harness_pid=child.pid, harness_created_filetime=process_creation(child.pid))
            save(folder / 'status.json', state)
            child.stdin.write(task_file.read_text(encoding='utf-8'))
            child.stdin.close()
            with (folder / 'events.jsonl').open('w', encoding='utf-8', buffering=1) as log:
                for line in child.stdout:
                    log.write(line)
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    kind = event.get('type')
                    state['last_event'] = kind
                    state['updated_at'] = now()
                    if kind == 'session':
                        state['session_id'] = event['sessionId']
                        save(SESSION_FILE, {'session_id': event['sessionId'], 'workspace': str(ROOT)})
                    elif kind == 'tool_call':
                        state['tool_calls'] += 1
                        state['last_tool'] = event.get('name') or event.get('toolName') or event.get('tool')
                    elif kind == 'tool_result':
                        state['completed_tool_results'] += 1
                    elif kind == 'final':
                        answer = event.get('text', '')
                        (folder / 'result.txt').write_text(answer, encoding='utf-8')
                        state['result'] = str(folder / 'result.txt')
                    elif kind == 'error':
                        state['error'] = event.get('message', 'Harness error')
                    save(folder / 'status.json', state)
            code = child.wait()
            state.update(state='completed' if code == 0 else 'failed', exit_code=code, finished_at=now(), updated_at=now())
            save(folder / 'status.json', state)
            return code
        except Exception as error:
            # The harness owns any jobs it started; do not kill arbitrary VM PIDs.
            state.update(state='failed', error=type(error).__name__ + ': ' + str(error), updated_at=now())
            save(folder / 'status.json', state)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--foreground', action='store_true')
    parser.add_argument('--session-id')
    parser.add_argument('--new-session', action='store_true')
    parser.add_argument('--task-file', type=Path, default=ROOT / 'docs/handover/DEEPSEEK-DEVELOPMENT-TASK.txt')
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.session_id and not args.new_session and SESSION_FILE.is_file():
        args.session_id = json.loads(SESSION_FILE.read_text(encoding='utf-8'))['session_id']
    if args.status:
        if not ACTIVE.is_file():
            print(json.dumps({'state': 'not-started'}))
        else:
            active = json.loads(ACTIVE.read_text())
            state = json.loads(Path(active['status']).read_text(encoding='utf-8'))
            if state.get('state') in ('starting', 'running') and state.get('worker_created_filetime'):
                observed = process_creation(state['worker_pid'])
                state['worker_identity_matches'] = observed == state['worker_created_filetime']
                if not state['worker_identity_matches']:
                    state.update(state='interrupted', note='Worker identity is absent or changed. This is not a completed campaign; inspect receipts before resuming.')
            print(json.dumps(state, indent=2))
        return 0
    node, launcher, version = prerequisites()
    if args.check_only:
        print(json.dumps({'passed': True, 'workspace': str(ROOT), 'version': version,
            'profile': 'agenticvm', 'session_id': args.session_id,
            'mcp_servers': ['agenticvm', 'rea'], 'model_calls_made': 0,
            'credentials_read_or_changed': False}, indent=2))
        return 0
    if args.worker:
        return worker(args.worker, args.session_id, args.task_file.resolve())
    folder = PARENT / str(uuid4())
    folder.mkdir(parents=True)
    if args.foreground:
        return worker(folder, args.session_id, args.task_file.resolve())
    with (folder / 'worker.log').open('wb') as output:
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
            '--worker', str(folder), '--task-file', str(args.task_file.resolve())]
        if args.session_id:
            command += ['--session-id', args.session_id]
        elif args.new_session:
            command += ['--new-session']
        child = subprocess.Popen(command, cwd=ROOT,
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True)
    print(json.dumps({'state': 'dispatched', 'worker_pid': child.pid,
        'session_id': args.session_id, 'status': str(folder / 'status.json'),
        'log': str(folder / 'events.jsonl'), 'scope': 'Local management acceptance campaign'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
