"""Upstream authenticated IPMI 2.0 controller emulator for one owned QEMU VM."""
from __future__ import annotations
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
from uuid import UUID

from .ipmi_protocol import LoopbackBMC
from .lan_lab import ROOT, digest, save
from .native_vm import NativeVM
from pyghmi.ipmi.private.session import Session


class OwnedBMC(LoopbackBMC):
    def __init__(self, vm, seed):
        self.vm, self.seed = vm, Path(seed)
        self.seed_sha256 = digest(self.seed)
        self.password = secrets.token_hex(10)
        self.events, self.errors = [], []
        self.pending = None
        self.once = False
        self.guard = threading.Lock()
        self.stopping = threading.Event()
        super().__init__({'gardenlab': self.password}, bmcuuid=UUID(vm.uuid))
        self.listener = threading.Thread(target=self.listen_owned, daemon=True)
        self.listener.start()
    def listen_owned(self):
        try:
            while not self.stopping.is_set():
                Session.wait_for_rsp(.1)
        except Exception as error:
            self.errors.append(type(error).__name__ + ': ' + str(error))
    def get_system_guid(self):
        return UUID(self.vm.uuid)
    def get_power_state(self):
        return 'on' if self.vm.process is not None and self.vm.process.poll() is None else 'off'
    def get_boot_device(self):
        return 'hd'
    def set_boot_device(self, value):
        if value != 'hd' or self.get_power_state() != 'off':
            raise NotImplementedError()
        self.once = True
    def queue(self, action):
        with self.guard:
            if self.pending and self.pending.is_alive():
                return
            def work():
                try:
                    action()
                except Exception as error:
                    self.errors.append(type(error).__name__ + ': ' + str(error))
            self.pending = threading.Thread(target=work, daemon=True)
            self.pending.start()
    def power_on(self):
        if self.get_power_state() == 'on':
            return
        if not self.once or self.vm.boot >= 2 or digest(self.seed) != self.seed_sha256:
            raise NotImplementedError()
        self.once = False
        self.queue(lambda: NativeVM.start(self.vm, seed=self.seed if self.vm.boot == 0 else None))
    def power_shutdown(self):
        if self.get_power_state() == 'off':
            return
        self.queue(lambda: NativeVM.poweroff(self.vm))
    def request(self, operation):
        payload = {'port': self.port, 'password': self.password, 'uuid': self.vm.uuid, 'operation': operation}
        child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/ipmi-owned-client.py')],
            input=json.dumps(payload), text=True, capture_output=True, timeout=135)
        if child.returncode:
            raise RuntimeError('Owned IPMI request failed: ' + child.stderr[-1200:])
        result = json.loads(child.stdout)
        if (not result['ok'] or result['target_uuid'] != self.vm.uuid or result['ipmi_version'] != 2.0
                or result['authentication_type'] != 6 or result['integrity'] != 1 or result['privacy'] != 'aes'):
            raise ValueError('IPMI 2.0 authentication/integrity/privacy proof missing')
        if self.pending:
            self.pending.join(10)
        if self.errors:
            raise RuntimeError('Owned IPMI backend failed: ' + str(self.errors))
        self.events.append(result)
        return result
    def close(self):
        self.stopping.set()
        self.listener.join(3)
        self.authdata.clear()
        if self.pending:
            self.pending.join(5)
        if self.listener.is_alive() or self.pending and self.pending.is_alive():
            raise RuntimeError('Owned IPMI controller worker did not stop')


class IPMIVM(NativeVM):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bmc = None
    def start(self, *, seed=None, ignition=None, smbios=None):
        if ignition or smbios:
            raise ValueError('IPMI profile uses owner-prepared configuration media')
        if self.bmc is None:
            if seed is None:
                raise ValueError('Owned first power-on needs approved configuration media')
            self.bmc = OwnedBMC(self, seed)
            self.bmc.request('status')
        self.bmc.request('boot-disk')
        self.bmc.request('on')
        return self.folder / f'boot-{self.boot}.log'
    def poweroff(self):
        self.bmc.request('softoff')


class IPMIAdapter:
    route, kind, seed_route = 'ipmi', 'ubuntu', 'cloud-init-local'
    source_paths = ['src/agenticvm/ipmi_lab.py', 'src/agenticvm/ipmi_protocol.py', 'scripts/ipmi-owned-client.py',
                    'tools/enrollment-management/pyghmi/ipmi/bmc.py', 'tools/enrollment-management/pyghmi/ipmi/private/serversession.py',
                    'tools/enrollment-management/pyghmi/ipmi/private/session.py']
    limitations = ['Upstream IPMI 2.0 protocol emulator on IPv6 loopback with a real owned QEMU backend; no physical BMC certification',
                   'The upstream server supports cipher suite 3 (HMAC-SHA1/AES128); the client explicitly selects it',
                   'NoCloud media is prepared by the owner before IPMI power-on; IPMI virtual-media extensions are not implemented',
                   'SDK sockets live only for the controller process and close when it exits']
    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        return payloads, metadata
    def create_vm(self, *args, **kwargs):
        self.vm = IPMIVM(*args, **kwargs)
        return self.vm
    def tick(self, target, folder):
        if target.bmc and target.bmc.errors:
            raise RuntimeError('Native IPMI worker failed: ' + str(target.bmc.errors))
    def finish(self, folder):
        bmc = getattr(getattr(self, 'vm', None), 'bmc', None)
        if not bmc:
            return {'started': False}
        bmc.close()
        if (folder / 'guest-report.json').exists() and [row['operation'] for row in bmc.events] != ['status', 'boot-disk', 'on', 'softoff', 'boot-disk', 'on']:
            raise ValueError('Native IPMI boot/reboot operation sequence is incomplete')
        path = folder / 'ipmi-operations.json'
        save(path, {'events': bmc.events, 'errors': bmc.errors, 'bind_address': '::1', 'port': bmc.port,
                    'target_uuid': self.vm.uuid, 'configuration_media_sha256': bmc.seed_sha256,
                    'physical_bmc_tested': False})
        return {'path': path.relative_to(folder).as_posix(), 'sha256': digest(path)}
