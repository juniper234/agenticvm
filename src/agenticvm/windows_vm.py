"""One fresh Windows evaluation VM, explicit SATA devices and private QMP."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
from uuid import uuid4

from .lan_lab import ROOT, digest, save
from .native_vm import NativeVM, image_tool
from .qemu import WindowsProcess, find_qemu
from .state import qemu_socket_directory
from .transport import SocketTransport


class WindowsVM(NativeVM):
    def __init__(self, folder, *, switch, memory=3072, target_uuid=None):
        self.folder = Path(folder)
        from uuid import UUID
        if (self.folder.name != 'target' or self.folder.parent.parent.resolve() != (ROOT / 'runtime/windows-enrollment-runs').resolve()
                or str(UUID(self.folder.parent.name)) != self.folder.parent.name):
            raise ValueError('Windows target disk must be inside its canonical owned lab run')
        self.folder.mkdir()
        self.uuid = str(uuid4()) if target_uuid is None else target_uuid
        if str(UUID(self.uuid)) != self.uuid or type(memory) is not int or not 2048 <= memory <= 4096:
            raise ValueError('Canonical owned Windows UUID and bounded RAM allocation required')
        self.kind, self.memory, self.boot = 'windows', memory, 0
        self.process = self.binding = None
        self.disk = self.folder / 'system.qcow2'
        self.manifest = json.loads((ROOT / 'runtime/enrollment-images/windows-installer/manifest.json').read_text())
        self.base = ROOT / self.manifest['iso']['path']
        self.base_sha256 = self.manifest['iso']['sha256']
        if digest(self.base) != self.base_sha256:
            raise ValueError('The locally pinned official Windows evaluation medium changed')
        image_tool('create', '-f', 'qcow2', self.disk, '40G')
        inventory = json.loads(image_tool('info', '--output=json', self.disk))
        if inventory['format'] != 'qcow2' or inventory['virtual-size'] != 40 * 1024**3 or inventory.get('backing-filename'):
            raise ValueError('Windows fixture must start as one independent blank virtual disk')
        save(self.folder / 'initial-inventory.json', {'blank_virtual_disk': True, 'image_info': inventory,
            'initial_disk_sha256': digest(self.disk), 'host_disk_attached': False, 'target_uuid': self.uuid})
        self.ipc = qemu_socket_directory(self.uuid)
        self.ipc.mkdir(parents=True, exist_ok=False)
        self.qmp, self.qga = self.ipc / 'q', self.ipc / 'g'
        self.port = switch.listen(4)
        self.guest_agent = False

    def start(self, *, seed=None, ignition=None, smbios=None):
        if ignition or smbios or self.process and self.process.poll() is None:
            raise ValueError('Windows fixture does not accept unrelated provisioning channels or duplicate launches')
        if not self.boot and (seed is None or not Path(seed).is_file()):
            raise ValueError('Windows first boot requires the explicit owner-prepared private configuration CD')
        if seed is not None and Path(seed).resolve() != (self.folder.parent / 'private/seed.iso').resolve():
            raise ValueError('Windows fixture media must belong to this exact owned run')
        if self.boot and seed is not None:
            raise ValueError('Windows cold-reboot acceptance detaches all provisioning media')
        qemu = find_qemu()
        self.boot += 1
        log = self.folder / f'boot-{self.boot}.log'
        argv = [str(qemu), '-L', str(qemu.parent / 'share'), '-name', 'Garden-Windows-' + self.uuid,
            '-uuid', self.uuid, '-machine', 'q35', '-accel', 'tcg', '-cpu', 'max', '-m', str(self.memory), '-smp', '2',
            '-nodefaults', '-display', 'none', '-device', 'VGA,vgamem_mb=16',
            '-device', 'qemu-xhci,id=garden-usb',
            '-device', 'usb-kbd,bus=garden-usb.0',
            '-device', 'usb-tablet,bus=garden-usb.0', '-monitor', 'none',
            '-serial', 'file:' + str(log), '-qmp', 'unix:' + str(self.qmp) + ',server=on,wait=off',
            '-rtc', 'base=utc', '-device', 'ich9-ahci,id=garden-sata',
            '-drive', 'file=' + str(self.disk).replace(',', ',,') + ',if=none,id=os,format=qcow2',
            '-device', 'ide-hd,drive=os,bus=garden-sata.0',
            '-netdev', f'socket,id=lan,connect=127.0.0.1:{self.port}',
            '-device', 'e1000,netdev=lan,romfile=,mac=52:54:00:4c:41:04']
        if self.boot == 1:
            argv += ['-drive', 'file=' + str(self.base).replace(',', ',,') + ',if=none,id=installer,format=raw,media=cdrom,readonly=on',
                '-device', 'ide-cd,drive=installer,bus=garden-sata.1',
                '-drive', 'file=' + str(seed).replace(',', ',,') + ',if=none,id=config,format=raw,media=cdrom,readonly=on',
                '-device', 'ide-cd,drive=config,bus=garden-sata.2', '-boot', 'order=c,once=d,menu=off']
        else:
            argv += ['-boot', 'order=c,menu=off']
        # Setup's internal warm resets stay inside the same owned QEMU process.
        # Only explicit process termination + start is counted as a cold boot.
        save(self.folder / f'launch-{self.boot}.json', {'argv': argv, 'uuid': self.uuid,
            'guest_control_exec_channel': False, 'fresh_disposable_sata_disk_only': True,
            'installer_media_attached': self.boot == 1, 'base_sha256': self.base_sha256,
            'warm_setup_resets_are_not_counted_as_cold_boots': True})
        with (self.folder / f'stdout-{self.boot}.log').open('wb') as out, (self.folder / f'stderr-{self.boot}.log').open('wb') as err:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as owner:
            if not owner.alive() or owner.executable != qemu:
                raise RuntimeError('Owned Windows evaluation VM failed to launch')
            self.binding = {'pid': self.process.pid, 'created': owner.created, 'executable': str(owner.executable), 'uuid': self.uuid}
        save(self.folder / f'ownership-{self.boot}.json', self.binding)
        return log

    def capture(self):
        """Read only the owned VM's display into its own diagnostics directory."""
        path = self.folder / ('display-' + uuid4().hex + '.ppm')
        with WindowsProcess(self.binding['pid']) as owner:
            if (not owner.alive() or owner.created != self.binding['created']
                    or str(owner.executable) != self.binding['executable']):
                raise ValueError('Windows diagnostic display ownership changed')
        with SocketTransport(self.qmp, 5) as connection:
            def read():
                return json.loads(connection.readline(5, 65536))
            if 'QMP' not in read():
                raise ValueError('Windows diagnostic monitor greeting mismatch')
            for command in ({'execute': 'qmp_capabilities'}, {'execute': 'screendump', 'arguments': {'filename': str(path)}}):
                ident = uuid4().hex
                connection.write(json.dumps(command | {'id': ident}).encode() + b'\n', 5)
                for _ in range(64):
                    result = read()
                    if result.get('id') == ident:
                        if 'return' not in result:
                            raise ValueError('Windows diagnostic monitor capture failed')
                        break
                else:
                    raise ValueError('Windows diagnostic monitor response limit')
        return path
