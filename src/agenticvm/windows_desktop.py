"""Owned Windows desktop guest, private QMP/serial sockets, WHPX only.

This adapter is independent of the historical Garden enrollment experiments.
Only a prepared local evaluation image is attached; no host disk is exposed.
"""
from __future__ import annotations

from contextlib import contextmanager
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from uuid import UUID, uuid4

from .desktop import DesktopController
from .errors import AgenticVMError
from .qemu import QemuBackend, WindowsProcess, binary_sha256, find_qemu, qmp_call, _prepare_socket_directory
from .resources import check_memory_budget, whpx_status
from .state import StateStore, contained, qemu_socket_directory
from .transport import SocketTransport

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'runtime/windows-desktop'
MAX_FILE = 1024 * 1024


def fail(message, code='windows_error'):
    raise AgenticVMError(message, code)


@contextmanager
def start_lock(store):
    """Wait for an exiting reboot supervisor before the first start mutation."""
    deadline = time.monotonic() + 5
    while True:
        guard = store.lock()
        try:
            guard.__enter__()
            break
        except AgenticVMError as error:
            if error.code != 'session_busy' or time.monotonic() >= deadline:
                raise
            time.sleep(.05)
    try:
        yield
    finally:
        guard.__exit__(None, None, None)


def disk_tool(*arguments):
    folder = ROOT / 'tools/disk-tools'
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    executable = folder / 'qemu-img.exe'
    if binary_sha256(executable) != manifest['sha256']:
        fail('The virtual disk tool changed.', 'windows_integrity')
    environment = {**os.environ, 'PATH': str(find_qemu().parent) + os.pathsep + os.environ.get('PATH', '')}
    result = subprocess.run([str(executable), *map(str, arguments)], env=environment,
        check=True, capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    return result.stdout


class WindowsDesktopStore(StateStore):
    def validate(self, data):
        try:
            identifier = str(UUID(data['uuid']))
            folder = self.root / 'vms' / ('AgenticVM-' + identifier)
            sockets = qemu_socket_directory(identifier)
            good = (type(data['schema']) is int and data['schema'] == 1 and data['uuid'] == identifier
                and data['session'] == self.session and data['workspace'] == str(self.root)
                and data['name'] == 'AgenticVM-' + identifier and data['run_dir'] == str(folder)
                and data['backend'] == 'windows' and data['profile'] == 'windows'
                and data['disk'] == str(self.root / 'windows-data' / self.session / 'system.qcow2')
                and data['socket_dir'] == str(sockets) and data['qmp_socket'] == str(sockets / 'q')
                and data['serial_socket'] == str(sockets / 's') and data['host_control_transport'] == 'unix'
                and data.get('watch_socket', str(sockets / 'w')) == str(sockets / 'w')
                and data.get('desired_state', 'running') in {'running', 'stopped'}
                and data['executable'] == str(find_qemu())
                and re.fullmatch(r'[0-9a-f]{64}', data['backend_sha256']) is not None
                and type(data['pid']) is int and data['pid'] >= 0
                and re.fullmatch(r'[0-9]+', data['process_created']) is not None
                and type(data['registered']) is bool and (not data['registered'] or data['pid'] > 0)
                and data['status'] in {'creating', 'running', 'stopped', 'failed'}
                and type(data['memory_mib']) is int and 2048 <= data['memory_mib'] <= 16384
                and type(data.get('cpus', 2)) is int and 1 <= data.get('cpus', 2) <= 8
                and data['network'] in {'none', 'nat'} and data['persistent'] is True)
            for path in (folder, Path(data['disk']).parent, sockets):
                for parent in (path, *path.parents):
                    if parent == path.anchor:
                        break
                    good = good and not parent.is_symlink() and not getattr(parent, 'is_junction', lambda: False)()
            if not good or not contained(folder, self.root) or not contained(Path(data['disk']), self.root):
                raise ValueError()
        except (KeyError, TypeError, ValueError, OSError, AgenticVMError):
            fail('Windows ownership or paths are invalid; control refused.', 'invalid_state')


class WindowsDesktopBackend(QemuBackend):
    def __init__(self, store):
        super().__init__(store, find_qemu())

    def _process(self, state, *, terminate=False):
        self.store.validate(state)
        process = WindowsProcess(state['pid'], terminate=terminate)
        if process.alive() and (process.created != state['process_created'] or process.executable != self.executable):
            process.close()
            fail('Windows process identity changed; control refused.', 'ownership_mismatch')
        return process

    @contextmanager
    def owned(self):
        with self.store.lock():
            state = self.store.load()
            if not state['registered']:
                fail('Windows is stopped.', 'vm_not_running')
            with self._process(state) as process:
                if not process.alive():
                    fail('Windows has exited.', 'vm_not_running')
                yield state

    def rpc(self, operation, *, timeout=35, **arguments):
        if operation in {'upload','download'}:
            timeout = max(timeout,240)  # 1 MiB, base64, bounded 115200-baud UART.
        with self.owned() as state:
            identifier = uuid4().hex
            with SocketTransport(state['serial_socket'], min(timeout, 3)) as stream:
                request = {'id': identifier, 'uuid': state['uuid'], 'op': operation, **arguments}
                # A blank boundary and correlated replies recover from an
                # interrupted UART frame or an earlier readiness probe.
                deadline = time.monotonic() + timeout
                stream.write(b'\n' + json.dumps(request, ensure_ascii=True).encode() + b'\n', timeout)
                for _ in range(128):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        fail('Windows guest response timed out.', 'guest_timeout')
                    try:
                        result = json.loads(stream.readline(remaining, 2 * MAX_FILE))
                    except ValueError:
                        continue
                    if not isinstance(result, dict) or result.get('id') != identifier:
                        continue
                    if result.get('uuid') != state['uuid']:
                        fail('Windows guest identity mismatch.', 'protocol_error')
                    if result.get('ok') is not True:
                        fail(str(result.get('error', 'Windows action failed.'))[:1024], 'guest_error')
                    if not isinstance(result.get('result'), dict):
                        fail('Invalid Windows guest response.', 'protocol_error')
                    return result['result']
                fail('Windows guest response limit reached.', 'protocol_error')

    def start(self, memory_mib=2048, *, network=False, _supervised=False, cpus=2, width=1024, height=768):
        from .configuration import RESOLUTIONS
        if type(width) is not int or type(height) is not int or (width, height) not in RESOLUTIONS:
            fail('Choose a supported display size.', 'invalid_display')
        if type(memory_mib) is not int or not 2048 <= memory_mib <= 16384 or type(cpus) is not int or not 1 <= cpus <= min(8, os.cpu_count() or 1) or type(network) is not bool:
            fail('Choose 2048–16384 MiB and 1–8 CPUs for Windows.', 'invalid_memory')
        check_memory_budget(memory_mib)
        if not whpx_status()['available']:
            fail('Windows Hypervisor Platform is unavailable.', 'accelerator_unavailable')
        from .android import campaign_idle
        with campaign_idle(), start_lock(self.store):
            previous = self.store.load(required=False)
            if _supervised and previous and previous.get('desired_state') != 'running':
                return {'status': 'stopped', 'registered': False, 'profile': 'windows'}
            if previous and previous['registered']:
                with self._process(previous) as process:
                    if process.alive():
                        return self.status()
            preparation = ASSETS / 'prepared.json'
            if not preparation.is_file():
                fail('Windows setup is not prepared yet.', 'windows_not_prepared')
            assets = json.loads(preparation.read_text(encoding='utf-8'))
            # Recheck install media before its first use, then retain the pin in
            # the session. The prepared receipt is produced after consent.
            for name in ('install.iso', 'seed.iso'):
                path = ASSETS / name
                if not path.is_file() or path.is_symlink() or binary_sha256(path) != assets['files'][name]['sha256']:
                    fail('Windows setup file changed: ' + name, 'windows_integrity')
            identifier = previous['uuid'] if previous else assets['uuid']
            if str(UUID(identifier)) != identifier:
                fail('Invalid Windows guest identifier.', 'invalid_state')
            folder = self.store.root / 'vms' / ('AgenticVM-' + identifier)
            disk = self.store.root / 'windows-data' / self.store.session / 'system.qcow2'
            for path in (folder, disk.parent):
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                    fail('Windows folders must not redirect paths.', 'invalid_state')
            if not disk.exists():
                if shutil.disk_usage(disk.parent).free < 18 * 1024**3:
                    fail('Windows setup needs 18 GiB of free disk space.', 'insufficient_disk')
                disk_tool('create', '-f', 'qcow2', disk, '48G')
            if disk.is_symlink() or getattr(disk, 'is_junction', lambda: False)():
                fail('Windows disk must not redirect paths.', 'invalid_state')
            inventory = json.loads(disk_tool('info', '--output=json', disk))
            detail = inventory.get('format-specific', {}).get('data', {})
            if inventory.get('format') != 'qcow2' or inventory.get('virtual-size') != 48 * 1024**3 or inventory.get('backing-filename') or detail.get('data-file'):
                fail('Windows needs its independent owned virtual disk.', 'invalid_state')
            sockets = qemu_socket_directory(identifier)
            if sockets.exists():
                # Only exact leaves belonging to an exited, validated session.
                if not previous:
                    fail('Windows socket directory already exists.', 'invalid_state')
                for leaf in ('q', 's', 'w'):
                    (sockets / leaf).unlink(missing_ok=True)
                sockets.rmdir()
            sockets = _prepare_socket_directory(identifier)
            installed = (disk.parent / 'installed.json').is_file()
            first_boot = not previous or not previous.get('pid')
            argv = [str(self.executable), '-L', str(self.executable.parent / 'share'),
                '-name', 'AgenticVM-' + identifier, '-uuid', identifier,
                '-machine', 'q35', '-accel', 'whpx', '-cpu', 'max', '-m', str(memory_mib), '-smp', str(cpus),
                '-nodefaults', '-display', 'none', '-monitor', 'none', '-no-reboot', '-device', f'VGA,vgamem_mb=32,xres={width},yres={height}',
                '-device', 'qemu-xhci,id=usb', '-device', 'usb-kbd,bus=usb.0', '-device', 'usb-tablet,bus=usb.0',
                '-qmp', 'unix:' + str(sockets / 'q') + ',server=on,wait=off',
                '-qmp', 'unix:' + str(sockets / 'w') + ',server=on,wait=off',
                '-serial', 'file:' + str(folder / 'console.log'),
                '-chardev', 'socket,id=rpc,path=' + str(sockets / 's') + ',server=on,wait=off', '-serial', 'chardev:rpc',
                '-rtc', 'base=localtime', '-device', 'ich9-ahci,id=sata',
                '-drive', 'file=' + str(disk).replace(',', ',,') + ',if=none,id=os,format=qcow2',
                '-device', 'ide-hd,drive=os,bus=sata.0', '-boot', 'order=c,menu=off']
            if not installed:
                for drive, name, bus in (('installer', 'install.iso', 1), ('seed', 'seed.iso', 2)):
                    argv += ['-drive', 'file=' + str(ASSETS / name).replace(',', ',,') + ',if=none,id=' + drive + ',format=raw,media=cdrom,readonly=on',
                        '-device', 'ide-cd,drive=' + drive + ',bus=sata.' + str(bus)]
                if first_boot:
                    argv += ['-boot', 'order=c,once=d,menu=off']
            if network:
                argv += ['-netdev', 'user,id=net,ipv6=off', '-device', 'e1000,netdev=net,romfile=']
            else:
                argv += ['-nic', 'none']
            state = {'schema': 1, 'uuid': identifier, 'session': self.store.session, 'workspace': str(self.store.root),
                'name': 'AgenticVM-' + identifier, 'backend': 'windows', 'profile': 'windows', 'run_dir': str(folder),
                'disk': str(disk), 'socket_dir': str(sockets), 'qmp_socket': str(sockets / 'q'),
                'serial_socket': str(sockets / 's'), 'host_control_transport': 'unix',
                'watch_socket': str(sockets / 'w'), 'desired_state': 'running',
                'executable': str(self.executable), 'backend_sha256': binary_sha256(self.executable),
                'pid': 0, 'process_created': '0', 'registered': False, 'status': 'creating', 'memory_mib': memory_mib, 'cpus': cpus, 'display_width': width, 'display_height': height,
                'network': 'nat' if network else 'none', 'persistent': True, 'installer_attached': not installed}
            self.store.save(state)
            launch = json.dumps({'argv': argv, 'host_disks_attached': False, 'first_install_boot': first_boot,
                'reboot_strategy': 'owned-process-restart'}, indent=2)
            (folder / 'launch.json').write_text(launch, encoding='utf-8')
            (folder / ('launch-' + uuid4().hex + '.json')).write_text(launch, encoding='utf-8')
            with (folder / 'stdout.log').open('ab') as out, (folder / 'stderr.log').open('ab') as err:
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
            with WindowsProcess(child.pid) as process:
                if not process.alive() or process.executable != self.executable:
                    fail('Windows could not start. See its VM log.', 'windows_exited')
                state.update(pid=child.pid, process_created=process.created, registered=True, status='running')
            self.store.save(state)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    state.update(registered=False, status='failed')
                    self.store.save(state)
                    fail('Windows could not start: ' + (folder / 'stderr.log').read_text(errors='replace')[-1200:], 'windows_exited')
                try:
                    qmp_call(sockets / 'q', 'query-status', timeout=1)
                    if not _supervised:
                        self._supervise(state)
                    return self.status()
                except AgenticVMError:
                    time.sleep(.3)
            fail('Windows monitor did not become ready.', 'windows_timeout')

    def _supervise(self, state):
        import sys
        argv = [sys.executable, '-I', '-B', str(ROOT / 'scripts/windows-desktop-supervisor.py'),
            '--workspace', str(self.store.root), '--session', self.store.session,
            '--pid', str(state['pid']), '--created', state['process_created']]
        folder = Path(state['run_dir'])
        with (folder / 'supervisor.log').open('ab') as log:
            child = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(child.pid) as process:
            if not process.alive():
                fail('Windows reboot supervisor could not start.', 'windows_supervisor_failed')
            (folder / 'supervisor-owner.json').write_text(json.dumps({'pid': child.pid,
                'created': process.created, 'executable': str(process.executable), 'guest_uuid': state['uuid']}), encoding='utf-8')

    def status(self):
        with self.store.lock():
            state = self.store.load(required=False)
            if not state:
                return {'status': 'stopped', 'registered': False, 'profile': 'windows'}
            result = {key: state[key] for key in ('status', 'registered', 'profile', 'memory_mib', 'network', 'uuid', 'pid')}
            result.update(cpus=state.get('cpus', 2), guest_ready=False, desktop_ready=False)
            if state['registered']:
                with self._process(state) as process:
                    if not process.alive():
                        result.update(status='stopped', registered=False)
                        return result
                result['status'] = qmp_call(state['qmp_socket'], 'query-status')['status']
                try:
                    guest = self.rpc('ping', timeout=2)
                    result.update(guest_ready=guest.get('desktop_ready') is True, desktop_ready=guest.get('desktop_ready') is True,
                        os=guest.get('os'),guest_agent=guest.get('agent'),serial_baud=guest.get('serial_baud'))
                    if result['guest_ready']:
                        marker = Path(state['disk']).parent / 'installed.json'
                        if not marker.exists():
                            marker.write_text(json.dumps({'uuid': state['uuid'], 'os': guest.get('os'), 'verified_at': time.time()}), encoding='utf-8')
                except (AgenticVMError, OSError, ValueError):
                    pass
            return result

    def stop(self):
        with self.store.lock():
            state = self.store.load()
            state['desired_state'] = 'stopped'
            self.store.save(state)
            if state['registered']:
                with self._process(state, terminate=True) as process:
                    if process.alive():
                        try:
                            self.rpc('shutdown', timeout=2)
                            process.wait(25)
                        except AgenticVMError:
                            pass
                        if process.alive():
                            try:
                                qmp_call(state['qmp_socket'], 'quit')
                            except AgenticVMError:
                                pass
                            if not process.wait(5):
                                process.terminate()
                                if not process.wait(5):
                                    fail('Windows did not stop.', 'windows_timeout')
            state.update(status='stopped', registered=False)
            self.store.save(state)
            return {'status': 'stopped', 'profile': 'windows', 'registered': False}

    def reset(self):
        state = self.store.load()
        self.stop()
        return self.start(state['memory_mib'], network=state['network'] == 'nat', cpus=state.get('cpus', 2), width=state.get('display_width', 1024), height=state.get('display_height', 768))

    def action(self, request):
        name = request['action']
        if name == 'start':
            return self.start(request.get('memory', 2048), network=request.get('network', False), cpus=request.get('cpus', 2), width=request.get('width', 1024), height=request.get('height', 768))
        if name in {'stop', 'reset', 'status'}:
            return getattr(self, name)()
        display = DesktopController(self)
        if name in {'click', 'move'}:
            return display.click(request['x'], request['y'], request.get('button', 'left')) if name == 'click' else display.mouse_move(request['x'], request['y'])
        if name == 'key':
            return display.key(request['keys'])
        if name == 'scroll':
            return display.scroll(request['steps'])
        if name in {'type', 'exec', 'upload', 'open-url'}:
            result = self.rpc(name, **{key: value for key, value in request.items() if key not in {'action', 'profile'}})
            if name == 'type':
                display.key('ctrl+v')
            return result
        fail('Unsupported Windows action.', 'invalid_request')

    def download(self, path):
        result = self.rpc('download', path=path)
        data = base64.b64decode(result['data_b64'], validate=True)
        if len(data) > MAX_FILE:
            fail('Choose a file no larger than 1 MiB.', 'file_too_large')
        return data, str(path).replace('\\', '/').rsplit('/', 1)[-1]
