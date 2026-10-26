"""Publisher-pinned Fedora/openSUSE installer inputs; one large image at a time."""
import argparse
import json
from pathlib import Path
import re
import shutil
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tools/python/iso')]
import pycdlib
from agenticvm.lan_lab import digest, save


def read(url, limit):
    with urllib.request.urlopen(url, timeout=30) as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Installer publisher metadata exceeds bound')
    return raw


def main(kind, metadata_only):
    lock_path = ROOT / ('tools/' + kind + '-installer-lock.json')
    if lock_path.exists():
        entry = json.loads(lock_path.read_text())
    elif kind == 'fedora':
        source = 'https://fedoraproject.org/releases.json'
        rows = json.loads(read(source, 8 * 1024**2))
        choices = [row for row in rows if row.get('arch') == 'x86_64' and row.get('variant') == 'Server'
                   and str(row.get('version', '')).isdigit() and '-dvd-' in row.get('link', '')]
        chosen = max(choices, key=lambda row: int(row['version']))
        name = Path(urllib.parse.urlparse(chosen['link']).path).name
        entry = {'url': chosen['link'], 'name': name, 'sha256': chosen['sha256'], 'expected_bytes': int(chosen['size']),
                 'version': chosen['version'], 'digest_source': source, 'path': 'downloads/enrollment-installers/' + name,
                 'trust': 'Publisher HTTPS release metadata and SHA256; detached signature verification not claimed'}
        save(lock_path, entry)
    else:
        name = 'openSUSE-Leap-15.6-DVD-x86_64-Build710.3-Media.iso'
        url = 'https://download.opensuse.org/distribution/leap/15.6/iso/' + name
        sums = read(url + '.sha256', 65536).decode()
        matches = re.findall(r'^([0-9a-f]{64})\s+\*?' + re.escape(name) + r'\s*$', sums, re.M)
        if len(matches) != 1:
            raise ValueError('Expected an exact publisher openSUSE checksum')
        entry = {'url': url, 'name': name, 'sha256': matches[0], 'version': '15.6', 'digest_source': url + '.sha256',
                 'path': 'downloads/enrollment-installers/' + name,
                 'trust': 'Publisher HTTPS checksum; detached signature verification not claimed'}
        save(lock_path, entry)
    if re.fullmatch('[0-9a-f]{64}', entry['sha256']) is None or '/' in entry['name'] or '\\' in entry['name']:
        raise ValueError('Unexpected installer filename or publisher pin')
    if metadata_only:
        return print(json.dumps({'metadata_ready': True, 'native_acceptance': False, **entry}, indent=2))
    path = ROOT / entry['path']
    if not path.exists():
        if shutil.disk_usage(ROOT).free < 7 * 1024**3:
            raise RuntimeError('At least 7 GiB free required before acquiring this local installer; recycle only verified task media first')
        partial = path.with_suffix('.iso.partial')
        offset = partial.stat().st_size if partial.exists() else 0
        request = urllib.request.Request(entry['url'], headers={'Range': f'bytes={offset}-'} if offset else {})
        print('Downloading publisher-pinned installer: ' + entry['name'], flush=True)
        with urllib.request.urlopen(request, timeout=30) as source:
            append = bool(offset and source.status == 206)
            if append and not source.headers.get('Content-Range', '').startswith('bytes ' + str(offset) + '-'):
                raise ValueError('Installer mirror returned the wrong resume offset')
            count = offset if append else 0
            with partial.open('ab' if append else 'wb') as output:
                while data := source.read(1024 * 1024):
                    count += len(data)
                    if count > 6 * 1024**3 or shutil.disk_usage(ROOT).free < 2 * 1024**3:
                        raise ValueError('Installer acquisition stopped to preserve host disk headroom')
                    output.write(data)
        if digest(partial) != entry['sha256']:
            raise ValueError('Publisher installer digest failed; partial retained')
        partial.replace(path)
    if digest(path) != entry['sha256']:
        raise ValueError('Pinned installer ISO changed')
    manifest = ROOT / 'runtime/enrollment-images' / (kind + '-installer') / 'manifest.json'
    if not manifest.exists():
        manifest.parent.mkdir(exist_ok=True)
        result = {'iso': entry, 'boot': {}, 'native_installation_tested': False}
        iso = pycdlib.PyCdlib()
        iso.open(str(path))
        try:
            result['volume_id'] = iso.pvd.volume_identifier.decode('ascii').strip()
            sources = (('/images/pxeboot/vmlinuz', 'vmlinuz'), ('/images/pxeboot/initrd.img', 'initrd.gz')) if kind == 'fedora' else (
                       ('/boot/x86_64/loader/linux', 'vmlinuz'), ('/boot/x86_64/loader/initrd', 'initrd.gz'))
            for source, name in sources:
                target = manifest.parent / name
                iso.get_file_from_iso(str(target), rr_path=source)
                result['boot'][name] = {'path': target.relative_to(ROOT).as_posix(), 'sha256': digest(target)}
        finally:
            iso.close()
        save(manifest, result)
    print(json.dumps({'ready': True, 'native_acceptance': False, 'manifest': str(manifest), 'bytes': path.stat().st_size}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=('fedora', 'opensuse'), required=True)
    parser.add_argument('--metadata-only', action='store_true')
    args = parser.parse_args()
    main(args.kind, args.metadata_only)
