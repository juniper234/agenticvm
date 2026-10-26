"""Shared agent control client. Only the pinned local VM service and exchange."""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, ProxyHandler

from .errors import AgenticVMError

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA = ROOT / 'runtime/glass-app'
PROFILES = {'linux': 'desktop', 'android': 'android', 'windows': 'windows', 'custom':'custom'}
MAX_FILE = 1024 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AgenticVMError('The local VM service must not redirect requests.', 'invalid_service')


def safe_path(value, root):
    if not isinstance(value, str) or not value or '\x00' in value or len(value) > 1024:
        raise AgenticVMError('Choose a relative file in the exchange folder.', 'invalid_path')
    relative = Path(value)
    if (relative.is_absolute() or relative.drive or '..' in relative.parts
            or ':' in value or getattr(os.path, 'isreserved', lambda value: False)(value)):
        raise AgenticVMError('Host paths must stay inside the exchange folder.', 'invalid_path')
    root = Path(root).absolute()
    path = root / relative
    for parent in (path, *path.parents):
        if parent.is_symlink() or getattr(parent, 'is_junction', lambda: False)():
            raise AgenticVMError('Exchange paths must not redirect.', 'invalid_path')
        if parent == root:
            break
    if not path.resolve().is_relative_to(root.resolve()) or path.resolve() == root.resolve():
        raise AgenticVMError('Host paths must stay inside the exchange folder.', 'invalid_path')
    return path


class ControlClient:
    def __init__(self, *, ready_file=None, workspace=None, exchange=None, session='desktop-app'):
        self.ready_file = Path(ready_file or DEFAULT_DATA / 'viewer-ready.json').absolute()
        self.workspace = Path(workspace or DEFAULT_DATA / 'workspace').resolve()
        self.exchange = Path(exchange or DEFAULT_DATA / 'exchange').absolute()
        self.session = session
        self.target_session='main'
        self.lease=None
        self.generation=None
        self.routed=False
        self.opener = build_opener(ProxyHandler({}), NoRedirects())

    def _connection(self):
        if self.ready_file.is_symlink() or self.ready_file.stat().st_size > 4096:
            raise AgenticVMError('Invalid local VM service receipt.', 'invalid_service')
        ready = json.loads(self.ready_file.read_text(encoding='utf-8'))
        link = urlsplit(ready['url'])
        fields = parse_qs(link.fragment)
        token = fields.get('token', [''])[0]
        if (link.scheme != 'http' or link.hostname != '127.0.0.1' or not link.port
                or link.username or link.password or link.path != '/' or link.query
                or set(fields) != {'token'} or len(fields['token']) != 1
                or re.fullmatch(r'[A-Za-z0-9_-]{30,128}', token) is None
                or Path(ready['workspace']).resolve() != self.workspace
                or (ready['session'] not in {self.session, self.session + '-android', self.session + '-windows'}
                    and re.fullmatch(re.escape(self.session[:40]) + r'-custom-[0-9a-f]{12}', ready['session']) is None)):
            raise AgenticVMError('VM service scope does not match this client.', 'invalid_service')
        return 'http://127.0.0.1:' + str(link.port), token

    def request(self, path, body=None, *, vm=None, identifier=None, content_type=None, limit=2 * MAX_FILE, timeout=360):
        origin, token = self._connection()
        headers = {'X-AgenticVM-Token': token, 'Origin': origin}
        if vm:
            if vm not in PROFILES:
                raise AgenticVMError('Choose linux, android or windows.', 'invalid_profile')
            headers['X-AgenticVM-Profile'] = PROFILES[vm]
        if identifier:
            headers['X-AgenticVM-Guest'] = identifier
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=True).encode()
            headers['Content-Type'] = 'application/json'
        elif body is not None:
            headers['Content-Type'] = content_type or 'application/octet-stream'
        if not path.startswith('/api/') or '\r' in path or '\n' in path:
            raise AgenticVMError('Invalid VM service endpoint.', 'invalid_request')
        for attempt in range(40):
            try:
                with self.opener.open(Request(origin + path, body, headers), timeout=timeout) as response:
                    data = response.read(limit + 1)
                    if len(data) > limit:
                        raise AgenticVMError('VM response exceeds its limit.', 'response_too_large')
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        result = json.loads(data)
                        if result.get('ok') is not True:
                            error = result.get('error', {})
                            raise AgenticVMError(error.get('message', 'VM action failed.'), error.get('code', 'vm_error'))
                        return result['result']
                    return data
            except HTTPError as error:
                detail = json.loads(error.read(65536))
                failure = detail.get('error', {})
                # Viewer busy is rejected before dispatch. Lifecycle busy may
                # occur after part of a mutation (e.g. reset), so only retry
                # that condition for observation. Never replay timeouts.
                retryable = (error.code == 409 and failure.get('code') == 'busy') or (
                    body is None and failure.get('code') == 'session_busy' and error.code in {400,409})
                if retryable and attempt < 39:
                    time.sleep(.5)
                    continue
                raise AgenticVMError(failure.get('message', 'VM action failed.'), failure.get('code', 'vm_error')) from error

    def bound(self, session='main', lease=None, generation=None):
        client=copy.copy(self)
        client.target_session,client.lease,client.generation=session,lease,generation
        client.routed=True
        return client

    def status(self, vm=None):
        if self.routed:
            return self.control('status',vm)
        return self.request('/api/status', vm=vm)

    def control(self, operation, vm=None, *, session=None, timeout=360, **arguments):
        if vm is not None and vm not in PROFILES:
            raise AgenticVMError('Choose linux, android or windows.','invalid_profile')
        context={'lease':self.lease,'generation':self.generation} if self.lease is not None else {}
        return self.request('/api/control',{'operation':operation,'session':session or self.target_session,
            **({'vm':vm} if vm else {}),**context,**arguments},timeout=timeout,limit=32*MAX_FILE if operation=='screen' else 2*MAX_FILE)

    def wait(self, vm, condition='guest', timeout_seconds=60, *, session=None):
        if type(timeout_seconds) is not int or not 0<=timeout_seconds<=60:
            raise ValueError('Wait timeout must be 0-60 seconds.')
        started=time.monotonic()
        deadline=started+timeout_seconds
        last=None
        while True:
            try:
                last=self.control('probe',vm,session=session,condition=condition,timeout=max(.1,deadline-time.monotonic()))
                if last['satisfied']:
                    return {**last,'timed_out':False,'elapsed_seconds':round(time.monotonic()-started,3)}
            except AgenticVMError as error:
                if error.code not in {'session_busy','busy'}:
                    raise
                last={'condition':condition,'satisfied':False,'busy':True}
            except TimeoutError:
                last={'condition':condition,'satisfied':False,'transport_timed_out':True}
            if time.monotonic()>=deadline:
                return {**last,'timed_out':True,'elapsed_seconds':round(time.monotonic()-started,3)}
            time.sleep(min(.25,max(0,deadline-time.monotonic())))

    def _target(self, vm):
        state = self.status(vm)
        if state.get('profile') != PROFILES.get(vm):
            raise AgenticVMError('The selected VM changed. Check status first.', 'target_changed')
        return state.get('uuid')

    def action(self, vm, name, **arguments):
        if self.routed:
            return self.control('action',vm,action=name,**arguments)
        identifier = self._target(vm)
        return self.request('/api/action', {'action': name, **arguments}, vm=vm, identifier=identifier)

    def start(self, vm, *, memory=None, network=None, persistent=None, os_id=None, cpus=None):
        if vm not in PROFILES:
            raise AgenticVMError('Choose linux, android or windows.', 'invalid_profile')
        settings = {key:value for key,value in {'memory':memory,'network':network,'persistent':persistent,'os_id':os_id,'cpus':cpus}.items() if value is not None}
        if vm == 'custom' and not os_id:
            raise AgenticVMError('Custom starts require an explicit OS library ID.', 'invalid_profile')
        if self.routed:
            return self.action(vm,'start',**settings)
        state = self.status()
        current = next((name for name, profile in PROFILES.items() if profile == state['profile']), None)
        payload = {'action': 'start', 'profile': PROFILES[vm], **settings}
        return self.request('/api/action', payload, vm=current, identifier=state.get('uuid'))

    def screenshot(self, vm):
        data = (base64.b64decode(self.control('screen',vm)['data_b64'],validate=True) if self.routed else
            self.request('/api/screen', vm=vm, identifier=self._target(vm), limit=32 * MAX_FILE))
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise AgenticVMError('VM returned an invalid screenshot.', 'invalid_screenshot')
        return data

    def write_file(self, vm, path, data):
        if not isinstance(data, bytes) or len(data) > MAX_FILE:
            raise AgenticVMError('Files are limited to 1 MiB.', 'file_too_large')
        return self.action(vm, 'upload', path=path, data_b64=base64.b64encode(data).decode('ascii'))

    def read_file(self, vm, path):
        if self.routed:
            return base64.b64decode(self.control('read',vm,path=path)['data_b64'],validate=True)
        return self.request('/api/download?' + urlencode({'path': path}), vm=vm, identifier=self._target(vm), limit=MAX_FILE)

    def import_file(self, vm, exchange_path, guest_path):
        source = safe_path(exchange_path, self.exchange)
        with source.open('rb') as stream:
            data = stream.read(MAX_FILE + 1)
        return self.write_file(vm, guest_path, data)

    def export_file(self, vm, guest_path, exchange_path):
        destination = safe_path(exchange_path, self.exchange)
        data = self.read_file(vm, guest_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
        return {'exchange_path': exchange_path, 'bytes': len(data)}

    def save_screenshot(self, vm, exchange_path):
        destination = safe_path(exchange_path, self.exchange)
        data = self.screenshot(vm)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
        return {'exchange_path': exchange_path, 'bytes': len(data)}
