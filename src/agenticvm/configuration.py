"""Versioned next-start settings and an owned, local-only OS media library."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from uuid import uuid4

from .errors import AgenticVMError
from .state import StateStore
from .control_store import checked, load_json, save_json

RESOLUTIONS = {(800, 600), (1024, 768), (1280, 720), (1280, 800), (1600, 900), (1920, 1080)}
BUILTINS = {'desktop', 'android', 'windows'}


def fail(message, code='invalid_configuration'):
    raise AgenticVMError(message, code)


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        fail(f'{label} must be an integer from {low} to {high}.')
    return value


def defaults(profile):
    android, windows = profile == 'android', profile == 'windows'
    return {'memory': 2560 if android else 2048 if windows else 768,
            'cpus': 2 if windows else 1, 'width': 720 if android else 1024,
            'height': 1280 if android else 768, 'network': profile == 'desktop',
            'persistent': True, **({'disk_gib': 32, 'firmware': 'bios', 'boot': 'media',
                                    'disk_bus': 'sata'} if profile == 'custom' else {})}


def validate_settings(profile, values):
    expected = defaults(profile)
    if not isinstance(values, dict) or set(values) != set(expected):
        fail('Supply the complete supported settings for this operating system.')
    integer(values['memory'], 2560 if profile == 'android' else 2048 if profile == 'windows' else 512 if profile == 'custom' else 768,
            8192 if profile == 'android' else 16384, 'Memory (MiB)')
    integer(values['cpus'], 1, 8, 'CPUs')
    if type(values['width']) is not int or type(values['height']) is not int:
        fail('Choose a supported display size.')
    if (values['width'], values['height']) not in ({(720, 1280)} if profile == 'android' else RESOLUTIONS):
        fail('Choose a supported display size; Android uses 720 × 1280.')
    if any(type(values[key]) is not bool for key in ('network', 'persistent')):
        fail('Internet and persistence must be boolean values.')
    if profile == 'windows' and not values['persistent']:
        fail('The prepared Windows installation always keeps its disk.')
    if profile == 'custom':
        integer(values['disk_gib'], 4, 512, 'New disk capacity (GiB)')
        if values['firmware'] not in {'bios', 'uefi'} or values['boot'] not in {'media', 'disk'} or values['disk_bus'] not in {'sata', 'virtio'}:
            fail('Choose BIOS/UEFI, media/disk boot and SATA/virtio storage.')
    return dict(values)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Configuration:
    def __init__(self, workspace, root):
        self.workspace, self.root = Path(workspace), Path(root)
        self.path = self.workspace / 'configuration.json'
        self.guard = StateStore(self.workspace, 'configuration')
        self.media = self.root / 'media'

    def load(self):
        checked(self.path, self.workspace)
        data = load_json(self.path, default={'schema': 1, 'revision': 0, 'machines': {}, 'oses': {}})
        if (not isinstance(data, dict) or set(data) != {'schema', 'revision', 'machines', 'oses'}
                or data['schema'] != 1 or type(data['revision']) is not int or data['revision'] < 0
                or not isinstance(data['machines'], dict) or not isinstance(data['oses'], dict) or len(data['oses']) > 32):
            fail('The saved configuration is invalid; preserve it for recovery.')
        for key, entry in data['oses'].items():
            if not re.fullmatch(r'[0-9a-f]{12}', key) or not isinstance(entry, dict) or set(entry) != {'name', 'file', 'format', 'sha256', 'bytes'}:
                fail('The OS library entry is invalid.')
            if (not isinstance(entry['name'], str) or not 1 <= len(entry['name']) <= 60 or any(ord(c) < 32 for c in entry['name'])
                    or entry['format'] not in {'iso', 'qcow2', 'raw'}
                    or entry['file'] != 'library/' + key + '/source.' + entry['format']
                    or not isinstance(entry['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', entry['sha256'])
                    or type(entry['bytes']) is not int or entry['bytes'] < 1):
                fail('The OS library entry has invalid media metadata.')
        for key, value in data['machines'].items():
            profile = key if key in BUILTINS else 'custom'
            if profile == 'custom' and (not key.startswith('custom:') or key[7:] not in data['oses']):
                fail('The saved machine has no registered OS.')
            validate_settings(profile, value)
        return data

    def key(self, profile, os_id=None):
        if profile in BUILTINS:
            return profile
        if profile != 'custom' or not isinstance(os_id, str) or os_id not in self.load()['oses']:
            fail('Choose a registered operating system.', 'invalid_profile')
        return 'custom:' + os_id

    def settings(self, profile, os_id=None):
        return dict(self.load()['machines'].get(self.key(profile, os_id), defaults(profile)))

    def snapshot(self):
        data = self.load()
        incoming = checked(self.media / 'incoming', self.media)
        incoming.mkdir(parents=True, exist_ok=True)
        files = [p.name for p in incoming.iterdir() if p.is_file() and not p.is_symlink()
                 and not getattr(p, 'is_junction', lambda: False)() and p.suffix.lower() in {'.iso', '.qcow2', '.raw'}]
        return {**data, 'incoming': sorted(files)[:128], 'incoming_folder': str(incoming),
                'available': {'desktop': (self.root/'runtime/linux-desktop/agenticvm-linux-desktop.iso').is_file(),
                              'android': (self.root/'tools/android/prepared.json').is_file(),
                              'windows': (self.root/'runtime/windows-desktop/prepared.json').is_file()},
                'limits': {'cpus_max': min(8, os.cpu_count() or 1), 'memory_max': 16384,
                           'resolutions': [list(size) for size in sorted(RESOLUTIONS)]},
                'bridge': {'transport': 'stdio', 'exchange': 'runtime/glass-app/exchange',
                           'launcher': str(self.root / 'agenticvm-desktop-mcp.cmd'), 'remote': False}}

    def save(self, profile, os_id, values, revision):
        with self.guard.lock():
            data = self.load()
            self.revision(data, revision)
            key = self.key(profile, os_id)
            data['machines'][key] = validate_settings(profile, values)
            data['revision'] += 1
            save_json(checked(self.path, self.workspace), data)
            return self.snapshot()

    @staticmethod
    def revision(data, revision):
        if type(revision) is not int or revision != data['revision']:
            fail('Settings changed in another window. Reload before saving.', 'configuration_conflict')

    def add_os(self, name, filename, revision):
        if not isinstance(name, str) or not name.strip() or len(name) > 60 or any(ord(c) < 32 for c in name):
            fail('Use an OS name of 1–60 printable characters.')
        if (not isinstance(filename, str) or Path(filename).name != filename or '/' in filename or '\\' in filename
                or ':' in filename or Path(filename).suffix.lower() not in {'.iso', '.qcow2', '.raw'}):
            fail('Choose one ISO, qcow2 or raw file from media/incoming.')
        with self.guard.lock():
            data = self.load()
            self.revision(data, revision)
            if len(data['oses']) >= 32:
                fail('The OS library supports up to 32 entries.')
            source = checked(self.media / 'incoming' / filename, self.media)
            if not source.is_file() or not 0 < source.stat().st_size <= 128 * 1024**3:
                fail('Media must be a regular file of at most 128 GiB.')
            fmt = source.suffix.lower()[1:]
            inspect_media(source, fmt)
            if shutil.disk_usage(self.root).free < source.stat().st_size + 512 * 1024**2:
                fail('Free space is too low to copy this media.', 'insufficient_disk')
            identifier = uuid4().hex[:12]
            destination = checked(self.media / 'library' / identifier / ('source.' + fmt), self.media)
            destination.parent.mkdir(parents=True, mode=0o700)
            before = (source.stat().st_size, source.stat().st_mtime_ns)
            with source.open('rb') as incoming, destination.open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024**2)
            source_hash, copied_hash = digest(source), digest(destination)
            if before != (source.stat().st_size, source.stat().st_mtime_ns) or source_hash != copied_hash:
                fail('Source media changed while copying; no OS was registered.')
            inspect_media(destination, fmt)
            data['oses'][identifier] = {'name': name.strip(), 'file': destination.relative_to(self.media).as_posix(),
                'format': fmt, 'sha256': copied_hash, 'bytes': destination.stat().st_size}
            choices = defaults('custom')
            if fmt != 'iso':
                choices['boot'] = 'disk'
            data['machines']['custom:' + identifier] = choices
            data['revision'] += 1
            save_json(checked(self.path, self.workspace), data)
            return {'os_id': identifier, **self.snapshot()}

    def media_file(self, os_id):
        entry = self.load()['oses'].get(os_id)
        if not entry:
            fail('Choose a registered operating system.', 'invalid_profile')
        path = checked(self.media / entry['file'], self.media)
        if not path.is_file() or path.stat().st_size != entry['bytes'] or digest(path) != entry['sha256']:
            fail('The library media changed; restore the original bytes.', 'media_changed')
        inspect_media(path, entry['format'])
        return path, entry


def inspect_media(path, fmt):
    # Reject host-file indirection before any QEMU tool opens a qcow2 image.
    if fmt == 'qcow2':
        with Path(path).open('rb') as stream:
            header = stream.read(104)
        if (len(header) < 72 or header[:4] != b'QFI\xfb' or struct.unpack_from('>I', header, 4)[0] not in {2, 3}
                or struct.unpack_from('>Q', header, 8)[0] or struct.unpack_from('>I', header, 16)[0]
                or struct.unpack_from('>I', header, 32)[0] or not 1 <= struct.unpack_from('>Q', header, 24)[0] <= 512 * 1024**3
                or (len(header) >= 80 and struct.unpack_from('>I', header, 4)[0] == 3 and struct.unpack_from('>Q', header, 72)[0] & ~3)):
            fail('Use a standalone, unencrypted qcow2 image without external backing/data files.', 'unsupported_media')
    elif fmt == 'iso':
        with Path(path).open('rb') as stream:
            stream.seek(32769)
            if stream.read(5) != b'CD001':
                fail('The selected file is not an ISO9660 installation image.', 'unsupported_media')
