"""Extract publisher-pinned Ubuntu guest-agent bytes; never execute them here."""
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def fetch(url, limit):
    with urllib.request.urlopen(url, timeout=30) as response:
        value = response.read(limit + 1)
    if len(value) > limit:
        raise ValueError('Ubuntu package input exceeds bound')
    return value


def main():
    folder = ROOT / 'runtime/enrollment-images'
    manifest = folder / 'qemu-ga-ubuntu.json'
    if manifest.exists():
        value = json.loads(manifest.read_text())
        if digest(ROOT / value['path']) != value['sha256']:
            raise ValueError('Pinned guest-agent executable changed')
        print(json.dumps({'ready': True, 'version': value['version']}))
        return
    spec = importlib.util.spec_from_file_location('ubuntu_deb_reader', ROOT / 'scripts/desktop-image-debian.py')
    debian = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(debian)
    base = 'https://archive.ubuntu.com/ubuntu/'
    index_url = base + 'dists/noble-updates/universe/binary-amd64/Packages.xz'
    raw_index = fetch(index_url, 16 * 1024**2)
    records = debian.paragraphs(lzma.decompress(raw_index))
    entry = next(row for row in records if row['Package'] == 'qemu-guest-agent' and row['Architecture'] == 'amd64')
    if not entry['Filename'].startswith(('pool/main/q/qemu/', 'pool/universe/q/qemu/')) or '..' in entry['Filename'].split('/'):
        raise ValueError('Unexpected publisher package location')
    raw = fetch(base + entry['Filename'], 8 * 1024**2)
    if hashlib.sha256(raw).hexdigest() != entry['SHA256'] or len(raw) != int(entry['Size']):
        raise ValueError('Publisher guest-agent package pin failed')
    cache = ROOT / 'downloads/enrollment'
    package = cache / Path(entry['Filename']).name
    if package.exists() and package.read_bytes() != raw:
        raise ValueError('Existing downloaded guest-agent package changed')
    package.write_bytes(raw)
    stream = io.BytesIO(raw)
    if stream.read(8) != b'!<arch>\n':
        raise ValueError('Invalid Ubuntu package container')
    payload = None
    while header := stream.read(60):
        size = int(header[48:58])
        name = header[:16].decode().strip().rstrip('/')
        value = stream.read(size)
        if size % 2:
            stream.read(1)
        if name.startswith('data.tar'):
            if name.endswith('.zst'):
                compressed = cache / 'qemu-ga-data.tar.zst'
                compressed.write_bytes(value)
                child = subprocess.run([str(ROOT / 'tools/7zip/26.04/7z.exe'), 'x', '-so', str(compressed)], capture_output=True, timeout=30)
                if child.returncode or len(child.stdout) > 32 * 1024**2:
                    raise ValueError('Guest-agent package decompression failed')
                payload = child.stdout
            else:
                payload = value
            break
    if payload is None:
        raise ValueError('Guest-agent package has no data archive')
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as archive:
        member = next(item for item in archive if item.name.removeprefix('./') == 'usr/sbin/qemu-ga')
        if not member.isfile() or member.size > 4 * 1024**2:
            raise ValueError('Unexpected native guest-agent executable')
        binary = archive.extractfile(member).read()
    if not binary.startswith(b'\x7fELF'):
        raise ValueError('Expected a native Linux guest-agent ELF')
    destination = folder / 'qemu-ga-ubuntu'
    destination.write_bytes(binary)
    save(manifest, {'path': destination.relative_to(ROOT).as_posix(), 'sha256': digest(destination),
        'version': entry['Version'], 'dependencies': entry.get('Depends'), 'package_sha256': entry['SHA256'],
        'package_url': base + entry['Filename'], 'index_url': index_url,
        'index_sha256': hashlib.sha256(raw_index).hexdigest(),
        'trust': 'Publisher HTTPS package index and SHA256; no detached archive signature verification claimed'})
    print(json.dumps({'ready': True, 'version': entry['Version'], 'bytes': len(binary), 'dependencies': entry.get('Depends')}))


if __name__ == '__main__':
    main()
