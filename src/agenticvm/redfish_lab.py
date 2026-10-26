"""Narrow Redfish HTTPS controller emulator bound to one owned native VM.

This is a local protocol/backend adapter, not physical BMC certification. The
virtual media is a preapproved NoCloud configuration CD, not an OS installer.
"""
from __future__ import annotations
import hashlib
import hmac
import http.server
import json
from pathlib import Path
import secrets
import ssl
import threading
import time
import urllib.request

from .lan_lab import certificate, digest, save
from .native_vm import NativeVM

SYSTEM = '/redfish/v1/Systems/Garden'
MEDIA = '/redfish/v1/Managers/Garden/VirtualMedia/Config'


class Controller:
    def __init__(self, vm, seed):
        self.vm, self.seed = vm, Path(seed)
        self.seed_sha256 = digest(self.seed)
        self.media_uri = 'https://media.garden.invalid/' + vm.uuid + '/configuration.iso'
        self.token = secrets.token_urlsafe(32)
        self.deadline = time.monotonic() + 1200
        self.inserted, self.once, self.revision = False, False, 0
        self.events = []
        self.lock = threading.Lock()
        private = vm.folder.parent / 'private'
        identity = None
        try:
            identity = certificate(private, 'bmc', '127.0.0.1')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(private / 'bmc.pem', private / 'bmc.key')
        finally:
            for name in ('bmc.pem', 'bmc.key'):
                path = private / name
                if path.exists():
                    path.unlink()
        self.certificate = identity['certificate']
        controller = self
        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            def get_request(self):
                raw, address = self.socket.accept()
                raw.settimeout(120)
                try:
                    return context.wrap_socket(raw, server_side=True), address
                except BaseException:
                    raw.close()
                    raise
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.operation(None)
            def do_PATCH(self):
                self.body()
            def do_POST(self):
                self.body()
            def body(self):
                try:
                    size = int(self.headers.get('Content-Length', '0'))
                    if not 1 <= size <= 4096:
                        raise ValueError('Bounded JSON body required')
                    self.operation(json.loads(self.rfile.read(size)))
                except Exception as error:
                    self.output({'error': {'code': 'Base.1.0.GeneralError', 'message': str(error)}}, 400)
            def operation(self, body):
                try:
                    if (self.client_address[0] != '127.0.0.1' or time.monotonic() > controller.deadline
                            or not hmac.compare_digest(self.headers.get('X-Auth-Token', ''), controller.token)):
                        return self.output({'error': {'code': 'Base.1.0.NoValidSession'}}, 401)
                    with controller.lock:
                        if len(controller.events) >= 128:
                            raise ValueError('Local controller request limit')
                        result = controller.apply(self.command, self.path, body, self.headers.get('If-Match'))
                        controller.events.append({'method': self.command, 'path': self.path, 'body': body,
                                                  'revision': controller.revision, 'tls': self.connection.version()})
                    self.output(result, 200)
                except Exception as error:
                    self.output({'error': {'code': 'Base.1.0.GeneralError', 'message': str(error)}}, 400)
            def output(self, value, status):
                raw = json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('ETag', '"' + str(controller.revision) + '"')
                self.end_headers()
                self.wfile.write(raw)
        self.server = Server(('127.0.0.1', 0), Handler)
        self.origin = 'https://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def apply(self, method, path, body, etag):
        alive = self.vm.process is not None and self.vm.process.poll() is None
        if method == 'GET' and path == SYSTEM and body is None:
            return {'@odata.id': SYSTEM, '@odata.type': '#ComputerSystem.v1_17_0.ComputerSystem', 'Id': 'Garden',
                    'UUID': self.vm.uuid, 'PowerState': 'On' if alive else 'Off',
                    'Boot': {'BootSourceOverrideEnabled': 'Once' if self.once else 'Disabled', 'BootSourceOverrideTarget': 'Hdd'}}
        if etag != '"' + str(self.revision) + '"':
            raise ValueError('Stale local controller resource version')
        if method == 'PATCH' and path == SYSTEM:
            if body != {'Boot': {'BootSourceOverrideEnabled': 'Once', 'BootSourceOverrideTarget': 'Hdd'}} or alive:
                raise ValueError('Only an owned powered-off VM may receive the one-time disk boot policy')
            self.once = True
        elif method == 'POST' and path == MEDIA + '/Actions/VirtualMedia.InsertMedia':
            if body != {'Image': self.media_uri, 'Inserted': True, 'WriteProtected': True} or alive:
                raise ValueError('Virtual media must match the preapproved local configuration CD')
            if digest(self.seed) != self.seed_sha256:
                raise ValueError('Virtual media content changed')
            self.inserted = True
        elif method == 'POST' and path == MEDIA + '/Actions/VirtualMedia.EjectMedia':
            if body != {} or alive:
                raise ValueError('Virtual media may be ejected only while the owned target is off')
            self.inserted = False
        elif method == 'POST' and path == SYSTEM + '/Actions/ComputerSystem.Reset':
            if body == {'ResetType': 'On'} and not alive and self.once:
                if self.inserted and digest(self.seed) != self.seed_sha256:
                    raise ValueError('Virtual media changed before power-on')
                NativeVM.start(self.vm, seed=self.seed if self.inserted else None)
                self.once = False
            elif body == {'ResetType': 'GracefulShutdown'} and alive:
                NativeVM.poweroff(self.vm)
            else:
                raise ValueError('Unsupported or out-of-order owned VM power operation')
        else:
            raise ValueError('Unknown local Redfish resource or operation')
        self.revision += 1
        return {}

    def request(self, method, path, body=None):
        context = ssl.create_default_context(cadata=self.certificate)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        headers = {'X-Auth-Token': self.token, 'If-Match': '"' + str(self.revision) + '"', 'Content-Type': 'application/json'}
        request = urllib.request.Request(self.origin + path, data=None if body is None else json.dumps(body).encode(),
                                         method=method, headers=headers)
        with opener.open(request, timeout=120) as response:
            return json.loads(response.read(8193))

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class ControlledVM(NativeVM):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.controller = None
    def start(self, *, seed=None, ignition=None, smbios=None):
        if ignition or smbios:
            raise ValueError('This local controller profile uses a NoCloud configuration CD')
        if self.controller is None:
            if seed is None:
                raise ValueError('First controller power-on requires approved configuration media')
            self.controller = Controller(self, seed)
            status = self.controller.request('GET', SYSTEM)
            if status['UUID'] != self.uuid or status['PowerState'] != 'Off':
                raise ValueError('Controller is not bound to the owned target')
            self.controller.request('POST', MEDIA + '/Actions/VirtualMedia.InsertMedia',
                                    {'Image': self.controller.media_uri, 'Inserted': True, 'WriteProtected': True})
        elif seed is None:
            self.controller.request('POST', MEDIA + '/Actions/VirtualMedia.EjectMedia', {})
        self.controller.request('PATCH', SYSTEM, {'Boot': {'BootSourceOverrideEnabled': 'Once', 'BootSourceOverrideTarget': 'Hdd'}})
        self.controller.request('POST', SYSTEM + '/Actions/ComputerSystem.Reset', {'ResetType': 'On'})
        return self.folder / f'boot-{self.boot}.log'
    def poweroff(self):
        self.controller.request('POST', SYSTEM + '/Actions/ComputerSystem.Reset', {'ResetType': 'GracefulShutdown'})


class RedfishAdapter:
    route, kind, seed_route = 'redfish', 'ubuntu', 'cloud-init-local'
    source_paths = ['src/agenticvm/redfish_lab.py']
    limitations = ['Local Redfish subset emulator on pinned TLS, backed by an actual owned QEMU VM; no physical/vendor BMC acceptance',
                   'Virtual media maps one preapproved local NoCloud configuration ISO URI; no arbitrary URI fetch or OS installer boot']
    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        return payloads, metadata
    def create_vm(self, *args, **kwargs):
        self.vm = ControlledVM(*args, **kwargs)
        return self.vm
    def tick(self, target, folder):
        pass
    def finish(self, folder):
        controller = getattr(getattr(self, 'vm', None), 'controller', None)
        if not controller:
            return {'started': False}
        controller.close()
        if (folder / 'guest-report.json').exists():
            resets = [event['body']['ResetType'] for event in controller.events if event['path'] == SYSTEM + '/Actions/ComputerSystem.Reset']
            if resets != ['On', 'GracefulShutdown', 'On'] or any(event['tls'] != 'TLSv1.3' for event in controller.events):
                raise ValueError('Native controller power/TLS evidence is incomplete')
        path = folder / 'redfish-operations.json'
        save(path, {'target_uuid': self.vm.uuid, 'events': controller.events, 'virtual_media_sha256': controller.seed_sha256,
                    'native_backend': 'QEMU owned process', 'physical_bmc_tested': False})
        return {'path': path.relative_to(folder).as_posix(), 'sha256': digest(path), 'operation_count': len(controller.events)}
