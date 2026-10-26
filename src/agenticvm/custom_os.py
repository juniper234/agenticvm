"""Owned QEMU screen-control adapter for user-supplied x86-64 OS media."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from uuid import UUID, uuid4

from .configuration import Configuration, digest, fail, validate_settings
from .control_store import checked
from .desktop import DesktopController
from .qemu import QemuBackend, WindowsProcess, _prepare_socket_directory, _cleanup_socket_directory, find_qemu, qmp_call
from .resources import check_memory_budget, whpx_status
from .state import StateStore, qemu_socket_directory


class CustomStore(StateStore):
    def validate(self, data):
        try:
            identifier = str(UUID(data['uuid']))
            folder = checked(self.root / 'vms' / ('AgenticVM-' + identifier), self.root)
            sockets = qemu_socket_directory(identifier)
            valid = (data['schema'] == 1 and type(data['schema']) is int and data['uuid'] == identifier
                and data['session'] == self.session and data['workspace'] == str(self.root)
                and data['name'] == 'AgenticVM-' + identifier and data['run_dir'] == str(folder)
                and data['backend'] == 'qemu' and data['profile'] == 'custom'
                and isinstance(data['os_id'], str) and re.fullmatch(r'[0-9a-f]{12}', data['os_id']) is not None
                and data['host_control_transport'] == 'unix' and data['socket_dir'] == str(sockets)
                and data['qmp_socket'] == str(sockets / 'q') and data['serial_socket'] == str(sockets / 's')
                and not any(key in data for key in ('qmp_port', 'serial_port', 'serial_host'))
                and data['network'] in {'none', 'nat'} and type(data['pid']) is int and data['pid'] >= 0
                and isinstance(data['process_created'], str) and data['process_created'].isdigit()
                and isinstance(data['executable'], str) and Path(data['executable']).is_absolute()
                and isinstance(data['backend_sha256'], str) and re.fullmatch('[0-9a-f]{64}', data['backend_sha256']) is not None
                and type(data['registered']) is bool and (not data['registered'] or data['pid'] > 0)
                and data['status'] in {'creating', 'running', 'stopped', 'failed'})
            values = validate_settings('custom', data['settings'])
            expected_disk = self.root / 'custom-data' / data['os_id'] / 'system.qcow2' if values['persistent'] else folder / 'system.qcow2'
            valid = valid and data['disk'] == str(expected_disk) and data['memory_mib'] == values['memory'] and data['cpus'] == values['cpus']
            checked(expected_disk, self.root)
            checked(sockets, sockets.parent)
            if not valid:
                raise ValueError()
        except (KeyError, ValueError, TypeError, OSError):
            fail('Custom VM ownership or paths are invalid; refusing control.', 'invalid_state')


class CustomBackend(QemuBackend):
    def __init__(self, store, root, os_id):
        super().__init__(store, find_qemu(None))
        self.root, self.os_id = Path(root), os_id
        self.config = Configuration(store.root.parent if store.root.name == os_id else store.root, root)

    def image_tool(self, *args):
        folder = self.root / 'tools/disk-tools'
        manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
        executable = folder / 'qemu-img.exe'
        if digest(executable) != manifest['sha256']:
            fail('The virtual disk tool changed.', 'disk_integrity')
        child = subprocess.run([str(executable), *args], capture_output=True,
            text=True, timeout=600, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            env={**os.environ, 'PATH':str(self.executable.parent) + os.pathsep + os.environ.get('PATH','')})
        if child.returncode:
            fail('The managed disk operation failed: ' + child.stderr[-1000:], 'disk_error')
        return child.stdout

    def start(self, settings, media, entry):
        values = validate_settings('custom', settings)
        # Shared campaign exclusion also covers the historical native runners.
        from .android import campaign_idle
        with campaign_idle(), self.store.lock():
            previous = self.store.load(required=False)
            if previous and previous['registered']:
                fail('Stop this OS before starting it again.', 'session_exists')
            if not whpx_status().get('available'):
                fail('Windows Hypervisor Platform is unavailable.', 'whpx_unavailable')
            preflight = check_memory_budget(values['memory'])
            if shutil.disk_usage(self.store.root).free < 1024**3:
                fail('At least 1 GiB free disk is required.', 'insufficient_disk')
            identifier = str(uuid4())
            folder = checked(self.store.root / 'vms' / ('AgenticVM-' + identifier), self.store.root)
            folder.mkdir(parents=True, mode=0o700)
            disk = checked(self.store.root / 'custom-data' / self.os_id / 'system.qcow2' if values['persistent'] else folder / 'system.qcow2', self.store.root)
            disk.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not disk.exists():
                if entry['format'] == 'iso':
                    self.image_tool('create', '-f', 'qcow2', str(disk), str(values['disk_gib']) + 'G')
                else:
                    if shutil.disk_usage(disk.parent).free < entry['bytes'] + 1024**3:
                        fail('Free space is too low to make the private disk copy.', 'insufficient_disk')
                    self.image_tool('convert', '-f', entry['format'], '-O', 'qcow2', str(media), str(disk))
            from .configuration import inspect_media
            inspect_media(disk, 'qcow2')
            # An existing system disk is never silently resized.
            info = json.loads(self.image_tool('info', '-f', 'qcow2', '--output=json', str(disk)))
            if entry['format'] == 'iso' and info['virtual-size'] != values['disk_gib'] * 1024**3:
                fail('Disk capacity differs from this existing disk. Keep its original capacity; use a new OS entry for another disk.', 'disk_size_conflict')
            sockets = _prepare_socket_directory(identifier)
            state = {'schema': 1, 'backend': 'qemu', 'profile': 'custom', 'os_id': self.os_id,
                'session': self.store.session, 'workspace': str(self.store.root), 'uuid': identifier,
                'name': 'AgenticVM-' + identifier, 'run_dir': str(folder), 'disk': str(disk),
                'host_control_transport': 'unix', 'socket_dir': str(sockets), 'serial_socket': str(sockets / 's'),
                'qmp_socket': str(sockets / 'q'), 'network': 'nat' if values['network'] else 'none',
                'memory_mib': values['memory'], 'cpus': values['cpus'], 'settings': values,
                'pid': 0, 'process_created': '0', 'executable': str(self.executable), 'backend_sha256': digest(self.executable),
                'registered': False, 'status': 'creating', 'memory_preflight': preflight}
            argv = self.command(state, media, entry)
            child = None
            try:
                self.store.save(state)
                (folder / 'launch.json').write_text(json.dumps({'argv': argv}), encoding='utf-8')
                with (folder / 'stdout.log').open('wb') as out, (folder / 'stderr.log').open('wb') as err:
                    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, close_fds=True,
                        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
                with WindowsProcess(child.pid) as process:
                    if not process.alive() or process.executable != self.executable:
                        fail('QEMU exited before its ownership could be recorded.', 'backend_start_failed')
                    state.update(pid=child.pid, process_created=process.created, registered=True)
                self.store.save(state)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        fail('QEMU exited; inspect the owned stderr.log.', 'backend_start_failed')
                    try:
                        if qmp_call(sockets / 'q', 'query-status', timeout=1).get('status') == 'running':
                            break
                    except Exception:
                        pass
                    time.sleep(.1)
                else:
                    fail('QEMU monitor did not become ready.', 'backend_start_failed')
                state['status'] = 'running'
                self.store.save(state)
            except BaseException:
                if child is not None and child.poll() is None:
                    child.terminate()  # Exact Popen handle created by this operation.
                    child.wait(timeout=10)
                state.update(status='failed', registered=False)
                _cleanup_socket_directory(state)
                self.store.save(state)
                raise
        return self.status()

    def command(self, state, media, entry):
        values = state['settings']
        quote = lambda path: str(path).replace(',', ',,')
        argv = [str(self.executable), '-L', str(self.executable.parent / 'share'), '-name', state['name'],
            '-uuid', state['uuid'], '-machine', 'q35', '-accel', 'whpx', '-cpu', 'max',
            '-m', str(values['memory']), '-smp', str(values['cpus']), '-display', 'none', '-monitor', 'none', '-nodefaults', '-no-reboot',
            '-device', f"VGA,vgamem_mb=32,xres={values['width']},yres={values['height']}",
            '-device', 'qemu-xhci,id=usb', '-device', 'usb-kbd,bus=usb.0', '-device', 'usb-tablet,bus=usb.0',
            '-chardev', 'socket,id=qmp,path=' + quote(state['qmp_socket']) + ',server=on,wait=off', '-qmp', 'chardev:qmp',
            '-serial', 'none', '-boot', 'order=' + ('dc' if values['boot'] == 'media' and entry['format'] == 'iso' else 'c')]
        if values['firmware'] == 'uefi':
            share = self.root / 'tools/ovmf-debian'
            code, variables = share / 'OVMF_CODE_4M.fd', share / 'OVMF_VARS_4M.fd'
            if not code.is_file() or not variables.is_file():
                fail('This QEMU bundle lacks UEFI firmware.', 'firmware_missing')
            manifest = json.loads((share / 'manifest.json').read_text(encoding='utf-8'))
            if any(digest(path) != manifest['files'][path.name] for path in (code, variables)):
                fail('UEFI firmware differs from its pinned manifest.', 'firmware_integrity')
            target = checked(Path(state['disk']).parent / 'uefi-vars.fd', self.store.root)
            if not target.exists():
                with variables.open('rb') as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
            argv += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + quote(code), '-drive', 'if=pflash,format=raw,file=' + quote(target)]
        if values['disk_bus'] == 'sata' or (entry['format'] == 'iso' and values['boot'] == 'media'):
            argv += ['-device', 'ich9-ahci,id=sata']
        argv += ['-drive', 'file=' + quote(state['disk']) + ',format=qcow2,if=none,id=osdisk', '-device',
                 'ide-hd,drive=osdisk,bus=sata.0' if values['disk_bus'] == 'sata' else 'virtio-blk-pci,drive=osdisk']
        if entry['format'] == 'iso' and values['boot'] == 'media':
            argv += ['-drive', 'file=' + quote(media) + ',format=raw,if=none,id=installer,media=cdrom,readonly=on',
                     '-device', 'ide-cd,drive=installer,bus=sata.1']
        argv += ['-netdev', 'user,id=net,restrict=off', '-device', 'e1000,netdev=net,romfile='] if values['network'] else ['-nic', 'none']
        return argv

    def status(self):
        state = self.store.load(required=False)
        if not state:
            return {'status': 'stopped', 'registered': False, 'profile': 'custom', 'os_id': self.os_id}
        result = {key: state[key] for key in ('status', 'registered', 'profile', 'os_id', 'uuid', 'pid', 'memory_mib', 'cpus', 'network', 'disk')}
        result.update(guest_ready=False, desktop_ready=False, screen_ready=False, persistent=state['settings']['persistent'])
        if state['registered']:
            with self._process(state) as process:
                if process.alive():
                    result['status'] = qmp_call(state['qmp_socket'], 'query-status').get('status', 'unknown')
                    result['screen_ready'] = result['status'] == 'running'
                    result['desktop_ready'] = result['screen_ready']
                else:
                    result['status'] = 'exited'
        return result

    def action(self, request):
        name = request['action']
        desktop = DesktopController(self)
        if name == 'stop':
            return self.stop() if self.store.load(required=False) else self.status()
        functions = {'click': lambda: desktop.click(request.get('x'), request.get('y'), request.get('button', 'left')),
            'move': lambda: desktop.mouse_move(request.get('x'), request.get('y')),
            'key': lambda: desktop.key(request.get('keys')), 'type': lambda: desktop.type_text(request.get('text')),
            'scroll': lambda: desktop.scroll(request.get('steps'))}
        if name not in functions:
            fail('This imported OS has screen and keyboard control. Commands and files need compatible guest tools.', 'capability_unavailable')
        return functions[name]()
