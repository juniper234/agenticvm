"""Use an explicitly prepared native QEMU guest agent on one owned VM."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time

from .errors import AgenticVMError
from .lan_lab import ROOT, digest, save
from .native_vm import NativeVM
from .qemu import WindowsProcess
from .transport import SocketTransport


class GuestAgentAdapter:
    route, kind, seed_route = 'guest-agent', 'ubuntu', 'cloud-init-local'
    source_paths = ['src/agenticvm/guest_agent_lab.py']
    limitations = ['The owner explicitly prepares upstream QEMU guest-agent and a private hypervisor management channel',
                   'Unlike the four first-boot routes, this profile intentionally uses one post-launch management RPC to invoke the pinned installer']
    def __init__(self):
        self.fired = False
        self.complete = False
        self.events = []
        self.next_try = 0

    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        config = json.loads(payloads['user-data'].decode().split('\n', 1)[1])
        config['write_files'] = [item for item in config['write_files'] if not item['path'].endswith('garden-native-install.service')]
        manifest = json.loads((ROOT / 'runtime/enrollment-images/qemu-ga-ubuntu.json').read_text())
        binary = ROOT / manifest['path']
        if digest(binary) != manifest['sha256']:
            raise ValueError('Pinned upstream guest agent changed')
        config['write_files'].append({'path': '/usr/local/sbin/qemu-ga-owned', 'permissions': '0755',
            'encoding': 'b64', 'content': base64.b64encode(binary.read_bytes()).decode()})
        for entry in json.loads((ROOT / 'runtime/enrollment-images/qemu-ga-ubuntu-libraries.json').read_text())['files']:
            path = ROOT / entry['path']
            if entry['name'] != 'liburing.so.2' or digest(path) != entry['sha256']:
                raise ValueError('Pinned guest-agent dependency changed')
            config['write_files'].append({'path': '/etc/garden/qga-libs/liburing.so.2', 'permissions': '0644',
                'encoding': 'b64', 'content': base64.b64encode(path.read_bytes()).decode()})
        unit = '''[Unit]
Description=Owner-prepared native QEMU management agent
After=network-online.target
Wants=network-online.target
[Service]
Environment=LD_LIBRARY_PATH=/etc/garden/qga-libs
ExecStart=/usr/local/sbin/qemu-ga-owned --method=virtio-serial --path=/dev/virtio-ports/org.qemu.guest_agent.0 --allow-rpcs=guest-sync-delimited,guest-ping,guest-info,guest-exec,guest-exec-status
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
'''
        config['write_files'].append({'path': '/etc/systemd/system/garden-qga.service', 'permissions': '0644', 'content': unit})
        config['runcmd'] = [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'garden-qga.service']]
        payloads = {**payloads, 'user-data': ('#cloud-config\n' + json.dumps(config)).encode()}
        self.bootstrap_sha256 = next(hashlib.sha256(item['content'].encode()).hexdigest() for item in config['write_files']
                                     if item['path'] == '/etc/garden/bootstrap.py')
        self.agent_sha256 = manifest['sha256']
        return payloads, metadata

    def create_vm(self, *args, **kwargs):
        return NativeVM(*args, **kwargs, guest_agent=True)

    def rpc(self, target, command, arguments=None):
        if command not in ('guest-ping', 'guest-info', 'guest-exec', 'guest-exec-status'):
            raise ValueError('Unapproved local guest-agent RPC')
        with WindowsProcess(target.binding['pid']) as owner:
            if (not owner.alive() or owner.created != target.binding['created']
                    or str(owner.executable) != target.binding['executable']):
                raise ValueError('Native guest-agent process binding changed')
        with SocketTransport(str(target.qga), 3) as connection:
            nonce = secrets.randbits(62)
            connection.write(b'\xff' + json.dumps({'execute': 'guest-sync-delimited', 'arguments': {'id': nonce}}).encode() + b'\n', 3)
            for _ in range(32):
                raw = connection.readline(3, 65536)
                try:
                    value = json.loads(raw.lstrip(b'\xff'))
                except (ValueError, UnicodeError):
                    continue
                if value.get('return') == nonce:
                    break
            else:
                raise ValueError('Native guest-agent stream did not synchronize')
            request = {'execute': command}
            if arguments is not None:
                request['arguments'] = arguments
            connection.write(json.dumps(request).encode() + b'\n', 3)
            value = json.loads(connection.readline(5, 65536).lstrip(b'\xff'))
            if 'error' in value or 'return' not in value:
                raise ValueError('Native guest-agent RPC failed: ' + str(value))
            return value['return']

    def tick(self, target, folder):
        if target.boot != 1 or self.complete or time.monotonic() < self.next_try:
            return
        self.next_try = time.monotonic() + 1
        if not self.fired:
            try:
                self.rpc(target, 'guest-ping')
                info = self.rpc(target, 'guest-info')
            except AgenticVMError:
                return
            program = ("import hashlib,pathlib,runpy; p=pathlib.Path('/etc/garden/bootstrap.py'); "
                       "assert hashlib.sha256(p.read_bytes()).hexdigest()==" + repr(self.bootstrap_sha256) + "; "
                       "runpy.run_path(str(p),run_name='__main__')")
            # There is exactly one launch. An uncertain response is not retried.
            self.fired = True
            result = self.rpc(target, 'guest-exec', {'path': '/usr/bin/python3', 'arg': ['-I', '-B', '-c', program], 'capture-output': True})
            if type(result.get('pid')) is not int or result['pid'] <= 0:
                raise ValueError('Native guest-agent returned no process identity')
            self.pid = result['pid']
            self.events.append({'command': 'guest-exec', 'pid': self.pid, 'bootstrap_sha256': self.bootstrap_sha256,
                                'guest_agent_version': info['version'], 'target_uuid': target.uuid})
        result = self.rpc(target, 'guest-exec-status', {'pid': self.pid})
        if result['exited']:
            self.complete = True
            self.events.append({'command': 'guest-exec-status', 'result': result})

    def finish(self, folder):
        if (folder / 'guest-report.json').exists() and (not self.fired or not self.complete or self.events[-1]['result'].get('exitcode') != 0):
            raise ValueError('Native guest-agent did not complete its one authorized bootstrap invocation')
        path = folder / 'guest-agent-operations.json'
        save(path, {'fired_once': self.fired, 'process_completed': self.complete,
                    'upstream_agent_sha256': getattr(self, 'agent_sha256', None), 'events': self.events})
        return {'path': path.relative_to(folder).as_posix(), 'sha256': digest(path)}
