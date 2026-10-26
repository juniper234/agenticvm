"""Restart only this owned Windows VM on QMP's explicit guest-reset event.

QEMU exits on guest reboot instead of exercising WHPX's broken warm reset.
A second private monitor leaves the interactive monitor available to the UI.
This process survives closing the viewer and exits on shutdown or Stop.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
os.environ.setdefault('AGENTICVM_SOCKET_ROOT', str(ROOT / 'runtime/ipc'))

from agenticvm.errors import AgenticVMError
from agenticvm.transport import SocketTransport
from agenticvm.windows_desktop import WindowsDesktopBackend, WindowsDesktopStore


@contextmanager
def lifecycle_lock(store, timeout=30):
    """Wait for observation/Stop to release the lock, before any mutation."""
    deadline = time.monotonic()+timeout
    while True:
        guard = store.lock()
        try:
            guard.__enter__()
            break
        except AgenticVMError as error:
            if error.code != 'session_busy' or time.monotonic() >= deadline:
                raise
            time.sleep(.1)
    try:
        yield
    finally:
        guard.__exit__(None,None,None)


def watch(backend, state):
    with backend._process(state) as process:
        if not process.alive():
            return None
    with SocketTransport(state['watch_socket'], 3) as monitor:
        greeting = json.loads(monitor.readline(5, 65536))
        if 'QMP' not in greeting:
            raise ValueError('Owned reboot monitor greeting mismatch')
        identifier = uuid4().hex
        monitor.write(json.dumps({'execute': 'qmp_capabilities', 'id': identifier}).encode() + b'\n', 3)
        for _ in range(64):
            result = json.loads(monitor.readline(5, 65536))
            if result.get('id') == identifier:
                if 'return' not in result:
                    raise ValueError('Reboot monitor negotiation failed')
                break
        else:
            raise ValueError('Reboot monitor negotiation limit')
        while True:
            try:
                event = json.loads(monitor.readline(2, 65536))
                if event.get('event') == 'SHUTDOWN':
                    reason = event.get('data', {}).get('reason')
                    with backend._process(state) as process:
                        if not process.wait(10):
                            raise ValueError('Owned Windows reset did not exit')
                    return reason
            except AgenticVMError as error:
                if error.code != 'guest_timeout':
                    return None
            with backend._process(state) as process:
                if not process.alive():
                    return None
            current = backend.store.load()
            if current['pid'] != state['pid'] or current['process_created'] != state['process_created']:
                return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--created', required=True)
    args = parser.parse_args()
    store = WindowsDesktopStore(args.workspace, args.session)
    backend = WindowsDesktopBackend(store)
    state = store.load()
    if state['pid'] != args.pid or state['process_created'] != args.created:
        raise ValueError('Reboot supervisor identity mismatch')
    resets = []
    while True:
        reason = watch(backend, state)
        with lifecycle_lock(store):
            current = store.load()
            if current['pid'] != state['pid'] or current['process_created'] != state['process_created']:
                return
            event = {'reason': reason, 'at': time.time(), 'pid': state['pid'], 'uuid': state['uuid']}
            with (Path(state['run_dir']) / 'reboot-events.jsonl').open('a', encoding='utf-8') as log:
                log.write(json.dumps(event) + '\n')
            if reason != 'guest-reset' or current.get('desired_state') != 'running':
                with backend._process(current) as process:
                    if process.alive():
                        raise ValueError('Reboot monitor disconnected; live VM ownership retained')
                current.update(status='stopped', registered=False)
                store.save(current)
                return
            resets = [at for at in resets if time.time() - at < 600]
            resets.append(time.time())
            if len(resets) > 12:
                current.update(status='failed', registered=False)
                store.save(current)
                raise ValueError('Windows reboot limit reached; inspect setup')
        # start() acquires the normal campaign and lifecycle locks itself.
        deadline = time.monotonic()+30
        while True:
            try:
                # start is idempotent for an already-live owned process, and
                # checks desired_state under its own lock before launching.
                backend.start(current['memory_mib'], network=current['network'] == 'nat', _supervised=True, cpus=current.get('cpus', 2), width=current.get('display_width', 1024), height=current.get('display_height', 768))
                break
            except AgenticVMError as error:
                if error.code != 'session_busy' or time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
        state = store.load()


if __name__ == '__main__':
    main()
