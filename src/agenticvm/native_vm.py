"""Owned disk-booting Linux guests; explicit disks, private QMP and recovery."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

from .lan_lab import ROOT, digest, save
from .qemu import WindowsProcess, find_qemu
from .state import qemu_socket_directory
from .transport import SocketTransport


def image_tool(*args):
    folder = ROOT / 'tools/enrollment-image-tools'
    entry = json.loads((folder / 'manifest.json').read_text())
    tool = folder / 'qemu-img.exe'
    if digest(tool) != entry['sha256']:
        raise ValueError('Disk utility changed')
    env = {**os.environ, 'PATH': str(find_qemu().parent) + os.pathsep + os.environ['PATH']}
    child = subprocess.run([str(tool), *map(str, args)], env=env, capture_output=True, text=True, timeout=60)
    if child.returncode:
        raise RuntimeError('Disk utility failed: ' + child.stderr[-1000:])
    return child.stdout


def pinned_image(kind):
    if kind not in ('ubuntu', 'coreos'):
        raise ValueError('Only the two declared native OS images are permitted')
    lock = json.loads((ROOT / 'tools/enrollment-assets-lock.json').read_text())
    entry = next(row for row in lock['assets'] if ('Ubuntu' in row['name']) == (kind == 'ubuntu'))
    path = ROOT / entry.get('uncompressed_path', entry['path'])
    expected = entry.get('uncompressed_sha256', entry['sha256'])
    if digest(path) != expected:
        raise ValueError('Official guest image changed')
    return path, expected


def seed_iso(path, files):
    sys.path.insert(0, str(ROOT / 'tools/python/iso'))
    import io
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge='1.09', vol_ident='cidata')
    try:
        for index, (name, data) in enumerate(files.items()):
            iso.add_fp(io.BytesIO(data), len(data), iso_path=f'/CONFIG{index}.;1',
                       rr_name=name, joliet_path='/' + name)
        iso.write(str(path))
    finally:
        iso.close()


class NativeVM:
    def __init__(self, folder, kind, *, memory=1024, switch=None, guest_agent=False):
        if type(guest_agent) is not bool:
            raise ValueError('Explicit guest-agent channel selection required')
        self.folder = Path(folder)
        self.folder.mkdir()
        self.uuid, self.kind, self.memory = str(uuid4()), kind, memory
        self.process = self.binding = None
        self.disk = self.folder / 'system.qcow2'
        self.base, self.base_sha256 = pinned_image(kind)
        image_tool('create', '-f', 'qcow2', '-F', 'qcow2', '-b', self.base, self.disk)
        self.ipc = qemu_socket_directory(self.uuid)
        self.ipc.mkdir(parents=True, exist_ok=False)
        self.qmp = self.ipc / 'q'
        self.guest_agent = guest_agent
        self.qga = self.ipc / 'g'
        self.port = switch.listen(4) if switch else None
        self.boot = 0

    def start(self, *, seed=None, ignition=None, smbios=None):
        if self.process and self.process.poll() is None:
            raise RuntimeError('Owned guest is already running')
        if digest(self.base) != self.base_sha256:
            raise ValueError('Native backing image changed between cold boots')
        self.boot += 1
        log = self.folder / f'boot-{self.boot}.log'
        qemu = find_qemu()
        argv = [str(qemu), '-L', str(qemu.parent / 'share'), '-name', 'Garden-Native-' + self.uuid,
                '-uuid', self.uuid, '-machine', 'q35', '-accel', 'whpx', '-cpu', 'max',
                '-m', str(self.memory), '-smp', '1', '-nodefaults', '-display', 'none', '-monitor', 'none',
                '-no-reboot', '-serial', 'file:' + str(log),
                '-qmp', 'unix:' + str(self.qmp) + ',server=on,wait=off',
                '-drive', 'file=' + str(self.disk).replace(',', ',,') + ',format=qcow2,if=virtio',
                '-object', 'rng-builtin,id=entropy', '-device', 'virtio-rng-pci,rng=entropy']
        if self.port:
            argv += ['-netdev', f'socket,id=lan,connect=127.0.0.1:{self.port}',
                     '-device', 'e1000,netdev=lan,romfile=,mac=52:54:00:4c:41:04']
        else:
            # Provide normal DHCP carrier for stock cloud images while QEMU's
            # restricted user network blocks connections to external networks.
            argv += ['-netdev', 'user,id=isolated,restrict=on', '-device', 'virtio-net-pci,netdev=isolated,romfile=']
        if self.guest_agent:
            argv += ['-device', 'virtio-serial-pci', '-chardev', 'socket,id=qga,path=' + str(self.qga) + ',server=on,wait=off',
                     '-device', 'virtserialport,chardev=qga,name=org.qemu.guest_agent.0']
        if seed:
            argv += ['-cdrom', str(seed)]
        if ignition:
            argv += ['-fw_cfg', 'name=opt/com.coreos/config,file=' + str(ignition)]
        if smbios:
            argv += ['-smbios', 'type=1,serial=' + smbios]
        save(self.folder / f'launch-{self.boot}.json', {'argv': argv, 'uuid': self.uuid,
             'base_sha256': self.base_sha256, 'guest_control_exec_channel': self.guest_agent})
        with (self.folder / f'stdout-{self.boot}.log').open('wb') as out, (self.folder / f'stderr-{self.boot}.log').open('wb') as err:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as owner:
            if not owner.alive() or owner.executable != qemu:
                raise RuntimeError('Native VM failed to start')
            self.binding = {'pid': self.process.pid, 'created': owner.created,
                            'executable': str(owner.executable), 'uuid': self.uuid}
        save(self.folder / f'ownership-{self.boot}.json', self.binding)
        return log

    def poweroff(self):
        # ACPI is a power signal, not an injected guest command.
        for _ in range(3):
            if self.process.poll() is not None:
                return
            self.control('system_powerdown')
            try:
                self.process.wait(10)
                return
            except subprocess.TimeoutExpired:
                pass
        self.process.wait(60)

    def control(self, command):
        if command not in ('system_powerdown', 'query-status', 'quit'):
            raise ValueError('Unapproved native lab monitor operation')
        with WindowsProcess(self.binding['pid']) as owner:
            if (not owner.alive() or owner.created != self.binding['created']
                    or str(owner.executable) != self.binding['executable']):
                raise RuntimeError('Native monitor process ownership changed')
        with SocketTransport(self.qmp, 5) as connection:
            def read():
                return json.loads(connection.readline(5, 65536))
            if 'QMP' not in read():
                raise ValueError('Native monitor greeting mismatch')
            for operation in ('qmp_capabilities', command):
                ident = uuid4().hex
                connection.write(json.dumps({'execute': operation, 'id': ident}).encode() + b'\n', 5)
                for _ in range(64):
                    response = read()
                    if response.get('id') == ident:
                        if 'error' in response or 'return' not in response:
                            raise ValueError('Native monitor operation failed')
                        break
                else:
                    raise ValueError('Native monitor response limit')
            return response['return']

    def stop(self):
        if self.process and self.process.poll() is None:
            with WindowsProcess(self.binding['pid'], terminate=True) as owner:
                if owner.alive():
                    if owner.created != self.binding['created'] or str(owner.executable) != self.binding['executable']:
                        raise RuntimeError('Native VM ownership changed')
                    owner.terminate()
                    owner.wait(10)
            self.process.wait(10)

    def clean(self):
        self.stop()
        if self.disk.exists():
            self.disk.unlink()
        if self.qmp.exists():
            self.qmp.unlink()
        if self.qga.exists():
            self.qga.unlink()
        if self.ipc.exists():
            self.ipc.rmdir()
