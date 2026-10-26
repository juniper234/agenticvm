"""Acquire and extract a publisher-pinned Ubuntu Server autoinstall source."""
import json
from pathlib import Path
import re
import shutil
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tools/python/iso')]
import pycdlib
from agenticvm.lan_lab import digest, save


def main():
    manifest = ROOT / 'runtime/enrollment-images/ubuntu-installer/manifest.json'
    lock = ROOT / 'tools/ubuntu-installer-lock.json'
    base = 'https://releases.ubuntu.com/24.04/'
    if lock.exists():
        entry = json.loads(lock.read_text())
    else:
        with urllib.request.urlopen(base + 'SHA256SUMS', timeout=30) as response:
            sums = response.read(65537).decode()
        choices = re.findall(r'^([0-9a-f]{64})\s+\*?(ubuntu-([0-9.]+)-live-server-amd64.iso)\s*$', sums, re.M)
        pin, name, version = max(choices, key=lambda row: tuple(map(int, row[2].split('.'))))
        entry = {'path': 'downloads/enrollment-installers/' + name, 'sha256': pin, 'name': name,
                 'url': base + name, 'digest_source': base + 'SHA256SUMS', 'version': version,
                 'trust': 'Publisher HTTPS checksums; detached signature verification not claimed'}
        save(lock, entry)
    path = ROOT / entry['path']
    if not path.exists():
        if shutil.disk_usage(ROOT).free < 5 * 1024**3:
            raise RuntimeError('At least 5 GiB free required before acquiring Ubuntu Server installation media')
        partial = path.with_suffix('.iso.partial')
        offset = partial.stat().st_size if partial.exists() else 0
        request = urllib.request.Request(entry['url'], headers={'Range': f'bytes={offset}-'} if offset else {})
        with urllib.request.urlopen(request, timeout=30) as source:
            append = bool(offset and source.status == 206)
            if append and not source.headers.get('Content-Range', '').startswith('bytes ' + str(offset) + '-'):
                raise ValueError('Ubuntu installer download resume offset mismatch')
            count = offset if append else 0
            announced = int(source.headers.get('Content-Length', '0')) + count
            if announced > 4608 * 1024**2:
                raise ValueError('Ubuntu installer exceeds the bounded source size')
            print('Downloading publisher-pinned Ubuntu Server installer: ' + entry['name'], flush=True)
            with partial.open('ab' if append else 'wb') as output:
                while data := source.read(1024 * 1024):
                    count += len(data)
                    if count > 4608 * 1024**2 or shutil.disk_usage(ROOT).free < 2 * 1024**3:
                        raise ValueError('Ubuntu media acquisition stopped to preserve host headroom')
                    output.write(data)
        if digest(partial) != entry['sha256']:
            raise ValueError('Ubuntu installer publisher digest failed; partial retained')
        partial.replace(path)
    if digest(path) != entry['sha256']:
        raise ValueError('Pinned Ubuntu installation medium changed')
    if not manifest.exists():
        manifest.parent.mkdir(exist_ok=True)
        result = {'iso': entry, 'boot': {}, 'native_installation_tested': False}
        iso = pycdlib.PyCdlib()
        iso.open(str(path))
        try:
            for source, name in (('/casper/vmlinuz', 'vmlinuz'), ('/casper/initrd', 'initrd.gz')):
                target = manifest.parent / name
                iso.get_file_from_iso(str(target), rr_path=source)
                result['boot'][name] = {'path': target.relative_to(ROOT).as_posix(), 'sha256': digest(target)}
        finally:
            iso.close()
        save(manifest, result)
    print(json.dumps({'ready': True, 'bytes': path.stat().st_size, 'sha256': entry['sha256'], 'manifest': str(manifest)}))


if __name__ == '__main__':
    main()
