"""Extract verified installer boot artifacts and inventory offline CD packages."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tools/python/iso')]
import pycdlib
from agenticvm.lan_lab import digest, save


def main():
    source = json.loads((ROOT / 'tools/installer-assets-lock.json').read_text())['debian-netinst']
    path = ROOT / source['path']
    if digest(path) != source['sha256']:
        raise ValueError('Publisher-pinned Debian installation medium changed')
    folder = ROOT / 'runtime/enrollment-images/debian-installer'
    folder.mkdir(exist_ok=True)
    manifest = folder / 'manifest.json'
    if manifest.exists():
        value = json.loads(manifest.read_text())
        for entry in value['boot'].values():
            if digest(ROOT / entry['path']) != entry['sha256']:
                raise ValueError('Pinned installer boot artifacts changed')
        return print(json.dumps({'ready': True, 'offline_packages': value['offline_packages']}))
    iso = pycdlib.PyCdlib()
    iso.open(str(path))
    result = {'iso': source, 'boot': {}, 'offline_packages': {}, 'native_installation_tested': False}
    try:
        for name in ('vmlinuz', 'initrd.gz'):
            target = folder / name
            iso.get_file_from_iso(str(target), rr_path='/install.amd/' + name)
            result['boot'][name] = {'path': target.relative_to(ROOT).as_posix(), 'sha256': digest(target)}
        prefixes = ('python3_', 'python3-minimal_', 'python3.13_', 'python3.13-minimal_',
                    'libpython3.13-stdlib_', 'openssl_', 'curl_', 'libssl3t64_', 'libpython3.13-minimal_')
        for _, _, files in iso.walk(rr_path='/pool'):
            for filename in files:
                for prefix in prefixes:
                    if filename.startswith(prefix) and filename.endswith('.deb'):
                        result['offline_packages'][prefix[:-1]] = filename
    finally:
        iso.close()
    save(manifest, result)
    print(json.dumps({'ready': True, 'offline_packages': result['offline_packages']}, indent=2))


if __name__ == '__main__':
    main()
