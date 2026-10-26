"""Pin the Ubuntu liburing dependency absent from the stock cloud image."""
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


def fetch(url, bound):
    with urllib.request.urlopen(url, timeout=30) as response:
        value = response.read(bound + 1)
    if len(value) > bound:
        raise ValueError('Ubuntu library input exceeds bound')
    return value


def main():
    manifest = ROOT / 'runtime/enrollment-images/qemu-ga-ubuntu-libraries.json'
    if manifest.exists():
        for entry in json.loads(manifest.read_text())['files']:
            if digest(ROOT / entry['path']) != entry['sha256']:
                raise ValueError('Pinned guest-agent library changed')
        return print('Pinned guest-agent libraries ready')
    spec = importlib.util.spec_from_file_location('ubuntu_library_deb', ROOT / 'scripts/desktop-image-debian.py')
    debian = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(debian)
    base = 'https://archive.ubuntu.com/ubuntu/'
    index_url = base + 'dists/noble/main/binary-amd64/Packages.xz'
    index = fetch(index_url, 16 * 1024**2)
    entry = next(row for row in debian.paragraphs(lzma.decompress(index)) if row['Package'] == 'liburing2' and row['Architecture'] == 'amd64')
    raw = fetch(base + entry['Filename'], 2 * 1024**2)
    if hashlib.sha256(raw).hexdigest() != entry['SHA256'] or len(raw) != int(entry['Size']):
        raise ValueError('Publisher library pin mismatch')
    source = io.BytesIO(raw)
    if source.read(8) != b'!<arch>\n':
        raise ValueError('Invalid Ubuntu package')
    while header := source.read(60):
        size = int(header[48:58])
        name = header[:16].decode().strip().rstrip('/')
        data = source.read(size)
        if size % 2:
            source.read(1)
        if not name.startswith('data.tar'):
            continue
        if name.endswith('.zst'):
            path = ROOT / 'downloads/enrollment/liburing-data.tar.zst'
            path.write_bytes(data)
            child = subprocess.run([str(ROOT / 'tools/7zip/26.04/7z.exe'), 'x', '-so', str(path)], capture_output=True, timeout=20)
            if child.returncode or len(child.stdout) > 8 * 1024**2:
                raise ValueError('Library archive decompression failed')
            data = child.stdout
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = next(item for item in archive if item.isfile() and Path(item.name).name.startswith('liburing.so.2.'))
            binary = archive.extractfile(member).read()
        break
    else:
        raise ValueError('Library package has no data payload')
    if not binary.startswith(b'\x7fELF') or len(binary) > 512 * 1024:
        raise ValueError('Unexpected guest-agent library')
    path = ROOT / 'runtime/enrollment-images/qga-liburing.so.2'
    path.write_bytes(binary)
    save(manifest, {'files': [{'name': 'liburing.so.2', 'path': path.relative_to(ROOT).as_posix(), 'sha256': digest(path)}],
        'package_version': entry['Version'], 'package_url': base + entry['Filename'], 'package_sha256': entry['SHA256'],
        'index_url': index_url, 'index_sha256': hashlib.sha256(index).hexdigest(),
        'trust': 'Publisher HTTPS index/SHA256; detached archive signature not verified'})
    print(json.dumps({'ready': True, 'bytes': len(binary), 'version': entry['Version']}))


if __name__ == '__main__':
    main()
