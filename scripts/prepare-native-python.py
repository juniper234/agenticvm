"""Package the pinned Debian Python/OpenSSL for newer-glibc appliance guests.

Ubuntu uses its own Python. CoreOS may use this explicit delivered dependency;
it is not silently assumed to contain a Python runtime or garden receiver.
"""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import posixpath
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def main():
    folder = ROOT / 'runtime/enrollment-images'
    manifest_path = folder / 'portable-python.json'
    if manifest_path.exists():
        data = json.loads(manifest_path.read_text())
        if digest(ROOT / data['path']) != data['sha256']:
            raise ValueError('Portable runtime changed')
        print(json.dumps({'ready': True, 'bytes': data['bytes']}))
        return
    base = json.loads((ROOT / 'runtime/linux-pxe-base-v3/build-manifest.json').read_text())
    source = ROOT / base['ram_root']['path']
    if digest(source) != base['ram_root']['sha256']:
        raise ValueError('Pinned Debian runtime source changed')
    spec = importlib.util.spec_from_file_location('native_cpio', ROOT / 'scripts/build-linux-probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = module.unpack_newc(gzip.decompress(source.read_bytes()))

    def resolve(name):
        for _ in range(12):
            mode, data = files[name]
            if not stat.S_ISLNK(mode):
                return mode, data
            target = data.decode()
            name = target.lstrip('/') if target.startswith('/') else posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
        raise ValueError('Runtime link resolution limit')

    chosen = {}
    for name, (mode, _) in files.items():
        target = None
        if name.startswith('usr/lib/python3.13/'):
            target = 'runtime/lib/python3.13/' + name.removeprefix('usr/lib/python3.13/')
        elif name in ('usr/bin/python3.13', 'usr/bin/openssl'):
            target = 'runtime/bin/' + name.rsplit('/', 1)[-1]
        elif name.startswith('usr/lib/x86_64-linux-gnu/') and '.so' in name.rsplit('/', 1)[-1]:
            basename = name.rsplit('/', 1)[-1]
            if basename.startswith(('libc.so', 'libm.so', 'libpthread.so', 'librt.so', 'libdl.so', 'libresolv.so', 'ld-linux')):
                continue
            target = 'runtime/lib/' + name.removeprefix('usr/lib/')
        if target is None or stat.S_ISDIR(mode) or name.endswith('.pyc'):
            continue
        actual_mode, data = resolve(name)
        if not stat.S_ISREG(actual_mode):
            raise ValueError('Unexpected runtime member type')
        chosen[target] = (actual_mode & 0o755, data)
    if 'runtime/bin/python3.13' not in chosen or 'runtime/lib/python3.13/os.py' not in chosen:
        raise ValueError('Portable interpreter incomplete')
    wrapper = b'''#!/bin/sh
runtime_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export LD_LIBRARY_PATH="$runtime_dir/lib/x86_64-linux-gnu"
exec "$runtime_dir/bin/python3.13" "$@"
'''
    chosen['runtime/python'] = (0o755, wrapper)
    archive = folder / 'portable-python.tar.gz'
    with archive.open('xb') as output, gzip.GzipFile(fileobj=output, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as package:
            for name, (mode, data) in sorted(chosen.items()):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(data), mode, 0
                package.addfile(entry, io.BytesIO(data))
    manifest = {'schema': 'agenticvm.portable-python.v1', 'path': str(archive.relative_to(ROOT)),
                'bytes': archive.stat().st_size, 'sha256': digest(archive), 'source_ram_root_sha256': digest(source),
                'minimum_glibc': '2.41; only used with compatible newer guest libc',
                'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, (_, data) in chosen.items()}}
    save(manifest_path, manifest)
    print(json.dumps({'ready': True, 'bytes': archive.stat().st_size, 'files': len(chosen)}))


if __name__ == '__main__':
    main()
