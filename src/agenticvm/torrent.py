"""Pinned agent bundles transferred by real BitTorrent on host loopback only.

Torrent hashes detect transport damage. The separately pinned local catalog is
the execution trust root. Neither mechanism authenticates an arbitrary publisher.
"""
from __future__ import annotations

import gc
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
from uuid import uuid4
import zipfile

MAX_BUNDLE = 320 * 1024**2
MAX_FILES = 80
HEX = re.compile(r'[0-9a-f]{64}\Z')


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def plain(path):
    """Reject redirected directories before writing or trusting any local path."""
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or (ancestor.exists() and getattr(os.path, 'isjunction', lambda _: False)(ancestor)):
            raise ValueError('Redirected path refused: '+str(ancestor))
    return path


def member_name(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./+\-]{1,180}', name):
        raise ValueError('Unsafe package member name')
    path = PurePosixPath(name)
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *('COM'+str(i) for i in range(1, 10)), *('LPT'+str(i) for i in range(1, 10))}
    if path.is_absolute() or path.as_posix() != name or any(p in ('.', '..') or p.endswith('.') or p.split('.')[0].upper() in reserved for p in path.parts):
        raise ValueError('Unsafe package member path')
    return name


def read_json(path, maximum=128*1024):
    path = plain(path)
    if not 0 < path.stat().st_size <= maximum:
        raise ValueError('Manifest size limit')
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate manifest key')
            result[key] = value
        return result
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def load_catalog(path, expected_sha):
    if not isinstance(expected_sha, str) or not HEX.fullmatch(expected_sha) or digest(plain(path)) != expected_sha:
        raise ValueError('Agent catalog trust pin mismatch')
    catalog = read_json(path)
    if catalog.get('schema') != 'agenticvm.agent-catalog.v1':
        raise ValueError('Unknown catalog schema')
    payload = catalog['payload']
    if member_name(payload['name']) != Path(payload['name']).name or not HEX.fullmatch(payload['sha256']):
        raise ValueError('Invalid payload identity')
    if type(payload['bytes']) is not int or not 1 <= payload['bytes'] <= MAX_BUNDLE or not HEX.fullmatch(catalog['torrent_sha256']):
        raise ValueError('Invalid payload bound')
    files = catalog['files']
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('Invalid package inventory')
    seen, total = set(), 0
    for entry in files:
        name = member_name(entry['path'])
        if name.casefold() in seen or type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= MAX_BUNDLE or not HEX.fullmatch(entry['sha256']):
            raise ValueError('Invalid package entry')
        seen.add(name.casefold())
        total += entry['bytes']
    if total > MAX_BUNDLE:
        raise ValueError('Unpacked package budget exceeded')
    return catalog


def load_libtorrent(root):
    directory = plain(Path(root)/'tools/torrent-runtime/2.1.1')
    sys.path.insert(0, str(directory))
    import libtorrent
    if libtorrent.__version__ != '2.1.1.0':
        raise ValueError('Unexpected torrent runtime version')
    return libtorrent


def make_torrent(lt, payload, destination):
    payload, destination = plain(payload), plain(destination)
    files = lt.file_storage()
    files.add_file(payload.name, payload.stat().st_size)
    torrent = lt.create_torrent(files, 256*1024, lt.create_torrent.v1_only)
    torrent.set_creator('AgenticVM local agent bundle')
    lt.set_piece_hashes(torrent, str(payload.parent))
    with destination.open('xb') as stream:
        stream.write(lt.bencode(torrent.generate()))


def local_session(lt):
    settings = {'listen_interfaces': '127.0.0.1:0', 'outgoing_interfaces': '127.0.0.1',
                'enable_dht': False, 'enable_lsd': False, 'enable_upnp': False, 'enable_natpmp': False,
                'dht_bootstrap_nodes': '', 'enable_outgoing_utp': False, 'enable_incoming_utp': False,
                'listen_system_port_fallback': False, 'enable_ip_notifier': False,
                'connections_limit': 4, 'active_downloads': 1, 'active_seeds': 1,
                'upload_rate_limit': 24*1024**2, 'download_rate_limit': 24*1024**2,
                'ignore_limits_on_local_network': False, 'alert_queue_size': 256,
                'max_web_seed_connections': 0, 'network_threads': 1, 'aio_threads': 1,
                'disk_io_write_mode': 0, 'disk_io_read_mode': 0}
    session = lt.session(settings)
    addresses = lt.ip_filter()
    addresses.add_rule('0.0.0.0', '255.255.255.255', 1)
    addresses.add_rule('::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 1)
    addresses.add_rule('127.0.0.1', '127.0.0.1', 0)
    session.set_ip_filter(addresses)
    return session


def add(lt, session, info, directory):
    params = lt.add_torrent_params()
    params.ti, params.save_path = info, str(plain(directory))
    params.flags &= ~(lt.torrent_flags.auto_managed | lt.torrent_flags.paused)
    # No discovery plugins, web seeds, trackers or inherited resume addresses.
    params.flags |= lt.torrent_flags.disable_dht | lt.torrent_flags.disable_lsd | lt.torrent_flags.disable_pex
    return session.add_torrent(params)


def download_local(root, torrent_path, catalog, seed, destination, *, timeout=180, event=lambda *a, **k: None):
    """Transfer or recheck partial pieces; never copy the seed into destination."""
    torrent_path, seed, destination = map(plain, (torrent_path, seed, destination))
    if torrent_path.stat().st_size > 128*1024 or digest(torrent_path) != catalog['torrent_sha256']:
        raise ValueError('Torrent metadata pin mismatch')
    lt = load_libtorrent(root)
    metadata = lt.bdecode(torrent_path.read_bytes())
    if any(metadata.get(k) for k in (b'announce', b'announce-list', b'url-list', b'httpseeds', b'nodes')):
        raise ValueError('This local release permits no discovery endpoints')
    info = lt.torrent_info(str(torrent_path))
    files = info.files()
    payload = catalog['payload']
    if files.num_files() != 1 or files.file_path(0) != payload['name'] or files.file_size(0) != payload['bytes']:
        raise ValueError('Torrent inventory mismatch')
    seed_file = plain(seed/payload['name'])
    if seed_file.stat().st_size != payload['bytes'] or digest(seed_file) != payload['sha256']:
        raise ValueError('Local seed does not match trusted package')
    destination.mkdir(parents=True, exist_ok=True)
    downloaded = plain(destination/payload['name'])
    if downloaded.exists() and downloaded.stat().st_size > payload['bytes']:
        raise ValueError('Oversized partial payload retained; use a fresh run')
    sessions, handles = [], []
    started = time.monotonic()
    evidence = {'engine': lt.__version__, 'protocol': 'BitTorrent v1 with pinned package SHA-256',
                'scope': '127.0.0.1 only', 'public_swarm_joined': False, 'dht': False, 'trackers': [],
                'web_seeds': [], 'resumed_existing_file': downloaded.exists(), 'peer_addresses': []}
    try:
        for directory in (seed, destination):
            sessions.append(local_session(lt))
            handles.append(add(lt, sessions[-1], info, directory))
        seeder, receiver = handles
        deadline, last_progress, reconnected = started+timeout, -1, 0
        while time.monotonic() < deadline:
            for session in sessions:
                for alert in session.pop_alerts():
                    if isinstance(alert, lt.file_error_alert):
                        raise RuntimeError('Torrent file error: '+str(alert))
            if seeder.status().is_seeding and sessions[0].is_listening() and time.monotonic()-reconnected >= 2:
                receiver.connect_peer(('127.0.0.1', sessions[0].listen_port()))
                reconnected = time.monotonic()
            state = receiver.status()
            if state.errc.value():
                raise RuntimeError('Torrent receiver error: '+state.errc.message())
            for peer in receiver.get_peer_info():
                endpoint = peer.ip
                if endpoint[0] != '127.0.0.1':
                    raise ValueError('Nonlocal torrent peer observed')
                if list(endpoint) not in evidence['peer_addresses']:
                    evidence['peer_addresses'].append(list(endpoint))
            progress = int(state.progress*100)//10*10
            if progress != last_progress:
                event('torrent_progress', percent=progress, downloaded_bytes=state.total_done)
                last_progress = progress
            if state.is_seeding:
                # A completed libtorrent state includes disk flush before removal;
                # SHA-256 below independently verifies every byte.
                evidence.update(payload_downloaded_bytes=state.total_payload_download,
                                payload_uploaded_bytes=seeder.status().total_payload_upload,
                                total_verified_bytes=state.total_done,
                                elapsed_seconds=round(time.monotonic()-started, 3))
                break
            time.sleep(.1)
        else:
            raise TimeoutError('Local torrent exceeded its deadline; partial pieces retained for recheck')
    finally:
        for session, handle in zip(sessions, handles):
            session.remove_torrent(handle)
            session.pause()
        handles.clear()
        sessions.clear()
        # Python binding destruction joins libtorrent's networking threads.
        session = seeder = receiver = handle = None
        gc.collect()
    if not downloaded.is_file() or downloaded.stat().st_size != payload['bytes'] or digest(downloaded) != payload['sha256']:
        raise ValueError('Downloaded agent package SHA-256 verification failed')
    evidence.update(sha256=payload['sha256'], sha256_verified=True)
    return downloaded, evidence


def verify_install(directory, catalog):
    directory = plain(directory)
    expected = {entry['path']: entry for entry in catalog['files']}
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    if actual != set(expected):
        raise ValueError('Installed package inventory mismatch')
    for name, entry in expected.items():
        path = plain(directory/name)
        if path.stat().st_size != entry['bytes'] or digest(path) != entry['sha256']:
            raise ValueError('Installed agent file differs from pin: '+name)
    return directory


def install_bundle(archive, catalog, cache):
    archive, cache = plain(archive), plain(cache)
    if archive.stat().st_size != catalog['payload']['bytes'] or digest(archive) != catalog['payload']['sha256']:
        raise ValueError('Untrusted agent archive')
    target = plain(cache/catalog['payload']['sha256'])
    if target.exists():
        return verify_install(target, catalog)
    stage = plain(cache/('.partial-'+uuid4().hex))
    expected = {entry['path']: entry for entry in catalog['files']}
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        names = [member_name(entry.filename) for entry in entries]
        if len(entries) != len(expected) or set(names) != set(expected) or len(set(n.casefold() for n in names)) != len(names):
            raise ValueError('Archive inventory mismatch')
        for entry in entries:
            if entry.is_dir() or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG) or entry.flag_bits & 1 or entry.file_size != expected[entry.filename]['bytes']:
                raise ValueError('Archive contains unexpected type, encryption or size')
        stage.mkdir(parents=True, exist_ok=False)
        for entry in entries:
            path = plain(stage/entry.filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            count, sha = 0, hashlib.sha256()
            with package.open(entry) as incoming, path.open('xb') as outgoing:
                while block := incoming.read(1024*1024):
                    count += len(block)
                    if count > entry.file_size:
                        raise ValueError('Extraction budget exceeded')
                    sha.update(block)
                    outgoing.write(block)
            if count != entry.file_size or sha.hexdigest() != expected[entry.filename]['sha256']:
                raise ValueError('Extracted agent file differs from pin')
    verify_install(stage, catalog)
    stage.rename(target)
    return target
