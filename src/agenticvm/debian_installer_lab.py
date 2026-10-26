"""Boot the actual Debian Installer into a blank owned disk, then enroll/reboot."""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from .installer_profiles import profile
from .lan_lab import ROOT, digest, save
from .native_vm import NativeVM, image_tool
from .qemu import WindowsProcess, find_qemu
from .state import qemu_socket_directory


class InstalledVM(NativeVM):
    manifest_relative = 'runtime/enrollment-images/debian-installer/manifest.json'
    disk_capacity = '8G'
    def __init__(self, folder, kind, *, memory, switch):
        self.folder = Path(folder)
        self.folder.mkdir()
        self.uuid, self.kind, self.memory = str(uuid4()), kind, memory
        self.process = self.binding = None
        self.boot = 0
        self.guest_agent = False
        self.manifest = json.loads((ROOT / self.manifest_relative).read_text())
        self.base, self.base_sha256 = ROOT / self.manifest['iso']['path'], self.manifest['iso']['sha256']
        if digest(self.base) != self.base_sha256:
            raise ValueError('Pinned installation source changed')
        for entry in self.manifest['boot'].values():
            if digest(ROOT / entry['path']) != entry['sha256']:
                raise ValueError('Pinned installer kernel/initrd changed')
        self.disk = self.folder / 'system.qcow2'
        image_tool('create', '-f', 'qcow2', self.disk, self.disk_capacity)
        self.ipc = qemu_socket_directory(self.uuid)
        self.ipc.mkdir(parents=True, exist_ok=False)
        self.qmp, self.qga = self.ipc / 'q', self.ipc / 'g'
        self.port = switch.listen(4)
        self.switch = switch
        switch.arm_reboot()

    def kernel_parameters(self):
        return ('auto=true priority=critical DEBIAN_FRONTEND=text console=ttyS0,115200n8 '
                'preseed/url=http://192.0.2.1:8080/installer/' + self.folder.parent.name + '/preseed.cfg '
                'netcfg/choose_interface=auto netcfg/get_hostname=garden-installed netcfg/get_domain=garden.invalid '
                'netcfg/get_gateway=none netcfg/get_nameservers= netcfg/no_default_route=true')

    def start(self, *, seed=None, ignition=None, smbios=None):
        if self.boot:
            return super().start()
        if ignition or smbios:
            raise ValueError('The installer uses its explicit pinned native boot input')
        self.boot = 1
        qemu = find_qemu()
        log = self.folder / 'boot-1.log'
        parameters = self.kernel_parameters()
        argv = [str(qemu), '-L', str(qemu.parent / 'share'), '-name', 'Garden-Installer-' + self.uuid,
            '-uuid', self.uuid, '-machine', 'q35', '-accel', 'whpx', '-cpu', 'max', '-m', str(self.memory), '-smp', '1',
            '-nodefaults', '-display', 'none', '-monitor', 'none', '-no-reboot', '-serial', 'file:' + str(log),
            '-qmp', 'unix:' + str(self.qmp) + ',server=on,wait=off',
            '-drive', 'file=' + str(self.disk).replace(',', ',,') + ',format=qcow2,if=virtio',
            '-cdrom', str(self.base), '-kernel', str(ROOT / self.manifest['boot']['vmlinuz']['path']),
            '-initrd', str(ROOT / self.manifest['boot']['initrd.gz']['path']), '-append', parameters,
            '-object', 'rng-builtin,id=entropy', '-device', 'virtio-rng-pci,rng=entropy',
            '-netdev', f'socket,id=lan,connect=127.0.0.1:{self.port}',
            '-device', 'e1000,netdev=lan,romfile=,mac=52:54:00:4c:41:04']
        save(self.folder / 'launch-1.json', {'argv': argv, 'uuid': self.uuid, 'guest_control_exec_channel': False,
             'blank_target_disk': True, 'installer_iso_sha256': self.base_sha256,
             'installer_boot_artifacts': self.manifest['boot']})
        with (self.folder / 'stdout-1.log').open('wb') as out, (self.folder / 'stderr-1.log').open('wb') as err:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as owner:
            if not owner.alive() or owner.executable != qemu:
                raise RuntimeError('Owned native installer failed to launch')
            self.binding = {'pid': self.process.pid, 'created': owner.created, 'executable': str(owner.executable), 'uuid': self.uuid}
        save(self.folder / 'ownership-1.json', self.binding)
        return log


class DebianInstallerAdapter:
    route, kind, seed_route = 'debian-preseed', 'debian', 'cloud-init-local'
    memory = 1536
    expected_connections = 3
    install_marker = 'DEBIAN_INSTALL_PREPARED'
    source_paths = ['src/agenticvm/debian_installer_lab.py', 'src/agenticvm/installer_profiles.py']
    limitations = ['Actual Debian Installer on one blank 8 GiB virtual disk with publisher-pinned local CD packages',
                   'Installer preseed is delivered over the isolated trusted LAN; the late bootstrap has an explicit digest pin',
                   'Installer boot is separate from the two installed-OS boots; no existing host disk is attached']
    def __init__(self):
        self.installed = False
    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        manifest = json.loads((ROOT / 'runtime/enrollment-images/debian-installer/manifest.json').read_text())
        required = {'python3', 'python3.13', 'libpython3.13-stdlib', 'openssl'}
        if not required <= manifest['offline_packages'].keys():
            raise ValueError('Debian installation CD lacks required offline Python/OpenSSL packages')
        built = profile(self.route, folder.name, public, runtime)
        raw = built['profile'].decode()
        marker = 'DEBIAN_INSTALL_PREPARED ' + folder.name
        rows = raw.splitlines()
        rows = [row + (' && echo ' + marker + ' > /dev/ttyS0') if row.startswith('d-i preseed/late_command ') else row for row in rows]
        preseed = ('\n'.join(rows) + '\n').encode()
        (folder / 'preseed.cfg').write_bytes(preseed)
        (folder / 'installer-firstboot.sh').write_bytes(built['firstboot_script'])
        prefix = '/installer/' + folder.name + '/'
        return payloads, {**metadata, prefix + 'preseed.cfg': base64.b64encode(preseed).decode(),
                          prefix + 'firstboot.sh': base64.b64encode(built['firstboot_script']).decode()}
    def create_vm(self, *args, **kwargs):
        self.vm = InstalledVM(*args, **kwargs)
        return self.vm
    def tick(self, target, folder):
        if target.boot != 1 or target.process.poll() is None:
            return
        serial = (target.folder / 'boot-1.log').read_text(errors='replace')
        if target.process.returncode != 0 or self.install_marker + ' ' + folder.name not in serial:
            raise ValueError('Native installer exited without a completed verified late hook')
        save(folder / 'installer-transition.json', {'installer_exit_code': target.process.returncode,
            'installer_console_sha256': digest(target.folder / 'boot-1.log'), 'target_uuid': target.uuid,
            'installation_media_detached_for_installed_os_boot': True})
        target.memory = 1024
        target.start()
        self.installed = True
        print('Native installation completed; booting installed OS without installation media', flush=True)
    def finish(self, folder):
        if (folder / 'guest-report.json').exists() and (not self.installed or self.vm.boot != 3):
            raise ValueError('Native installer and two installed-OS boots were not all observed')
        return {'native_installer_completed': self.installed, 'installer_boots': 1,
                'installed_os_boots': max(0, getattr(getattr(self, 'vm', None), 'boot', 0) - 1),
                'transition_sha256': digest(folder / 'installer-transition.json') if self.installed else None}
