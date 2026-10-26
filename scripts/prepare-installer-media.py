"""Acquire a publisher-pinned Debian installer for a disposable offline VM."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def main():
    lock_path = ROOT / 'tools/installer-assets-lock.json'
    if lock_path.exists():
        entry = json.loads(lock_path.read_text())['debian-netinst']
    else:
        base = 'https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/'
        with urllib.request.urlopen(base + 'SHA256SUMS', timeout=30) as response:
            sums = response.read(65537)
        if len(sums) > 65536:
            raise ValueError('Publisher checksum file exceeds bound')
        matches = re.findall(r'^([0-9a-f]{64})\s+\*?(debian-([0-9.]+)-amd64-netinst\.iso)\s*$', sums.decode(), re.M)
        if len(matches) != 1:
            raise ValueError('Expected one official Debian amd64 network installer')
        pin, name, version = matches[0]
        entry = {'url': base + name, 'sha256': pin, 'name': name, 'version': version,
                 'digest_source': base + 'SHA256SUMS', 'path': 'downloads/enrollment-installers/' + name,
                 'trust': 'Publisher HTTPS checksum; detached signature not yet verified'}
        save(lock_path, {'schema': 'agenticvm.installer-assets.v1', 'debian-netinst': entry})
    path = ROOT / entry['path']
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if digest(path) != entry['sha256']:
            raise ValueError('Pinned Debian installer changed; existing file retained')
    else:
        if shutil.disk_usage(ROOT).free < 3 * 1024**3:
            raise RuntimeError('At least 3 GiB free required before acquiring this installer')
        partial = path.with_suffix('.iso.partial')
        urls = [entry['url'].replace('https://cdimage.debian.org/', 'https://get.debian.org/'), entry['url']]
        failure = None
        for url in urls:
            print('Official installer download: ' + url, flush=True)
            offset = partial.stat().st_size if partial.exists() else 0
            request = urllib.request.Request(url, headers={'User-Agent': 'AgenticVM-owned-lab/0.1',
                                                           **({'Range': f'bytes={offset}-'} if offset else {})})
            try:
                with urllib.request.urlopen(request, timeout=20) as response:
                    append = bool(offset and response.status == 206)
                    if append and not response.headers.get('Content-Range', '').startswith('bytes ' + str(offset) + '-'):
                        raise ValueError('Installer mirror resume offset mismatch')
                    expected = int(response.headers.get('Content-Length', '0'))
                    if expected + (offset if append else 0) > 1280 * 1024**2:
                        raise ValueError('Installer exceeds the approved download bound')
                    total = offset if append else 0
                    with partial.open('ab' if append else 'wb') as stream:
                        while data := response.read(64 * 1024):
                            total += len(data)
                            if total > 1280 * 1024**2 or shutil.disk_usage(ROOT).free < 1536 * 1024**2:
                                raise ValueError('Installer download stopped to preserve host disk headroom')
                            stream.write(data)
                failure = None
                break
            except (OSError, TimeoutError) as error:
                failure = error
                print('Installer source did not complete: ' + str(error), flush=True)
        if failure:
            raise failure
        if digest(partial) != entry['sha256']:
            raise ValueError('Downloaded installer digest failed; partial retained')
        partial.replace(path)
    print(json.dumps({'ready': True, 'name': entry['name'], 'bytes': path.stat().st_size, 'sha256': digest(path)}))


if __name__ == '__main__':
    main()
