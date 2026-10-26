"""Bundle pinned Debian libc/loader with Python for older Linux lab guests."""
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
from agenticvm.resources import check_memory_budget


def main():
    folder = ROOT / 'runtime/enrollment-images'
    result_path = folder / 'portable-userspace.json'
    if result_path.exists():
        result = json.loads(result_path.read_text())
        if digest(ROOT / result['path']) != result['sha256']:
            raise ValueError('Pinned portable userspace changed')
        return print(json.dumps({'ready': True, 'bytes': result['bytes']}))
    check_memory_budget(512)
    base = json.loads((ROOT / 'runtime/linux-pxe-base-v3/build-manifest.json').read_text())
    ram = ROOT / base['ram_root']['path']
    original = json.loads((folder / 'portable-python.json').read_text())
    if digest(ram) != base['ram_root']['sha256'] or digest(ROOT / original['path']) != original['sha256']:
        raise ValueError('Pinned userspace input changed')
    members = {}
    with tarfile.open(ROOT / original['path']) as archive:
        for item in archive:
            if not item.isfile() or not item.name.startswith('runtime/') or '..' in item.name.split('/'):
                raise ValueError('Unexpected portable runtime entry')
            members[item.name] = (item.mode, archive.extractfile(item).read())
    spec = importlib.util.spec_from_file_location('portable_userspace_cpio', ROOT / 'scripts/build-linux-probe.py')
    cpio = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cpio)
    source = cpio.unpack_newc(gzip.decompress(ram.read_bytes()))
    def resolve(name):
        for _ in range(12):
            mode, data = source[name]
            if not stat.S_ISLNK(mode):
                if not stat.S_ISREG(mode):
                    raise ValueError('Userspace input is not a regular ELF')
                return mode & 0o755, data
            target = data.decode()
            name = target.lstrip('/') if target.startswith('/') else posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
        raise ValueError('Userspace link resolution bound')
    for name in ('libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1', 'libresolv.so.2', 'ld-linux-x86-64.so.2'):
        key = 'usr/lib/x86_64-linux-gnu/' + name
        members['runtime/lib/x86_64-linux-gnu/' + name] = resolve(key)
    members['runtime/bin/openssl.elf'] = members.pop('runtime/bin/openssl')
    members['runtime/python'] = (0o755, b'''#!/bin/sh
runtime_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export OPENSSL_CONF=/dev/null
exec "$runtime_dir/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" --library-path "$runtime_dir/lib/x86_64-linux-gnu" "$runtime_dir/bin/python3.13" "$@"
''')
    members['runtime/bin/openssl'] = (0o755, b'''#!/bin/sh
runtime_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export OPENSSL_CONF=/dev/null
exec "$runtime_dir/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" --library-path "$runtime_dir/lib/x86_64-linux-gnu" "$runtime_dir/bin/openssl.elf" "$@"
''')
    path = folder / 'portable-userspace.tar.gz'
    with path.open('xb') as output, gzip.GzipFile(fileobj=output, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, (mode, raw) in sorted(members.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(raw), mode, 0
                archive.addfile(item, io.BytesIO(raw))
    result = {'path': path.relative_to(ROOT).as_posix(), 'sha256': digest(path), 'bytes': path.stat().st_size,
              'source_python_archive_sha256': original['sha256'], 'source_ram_root_sha256': digest(ram),
              'native_platform_acceptance': False, 'uses_explicit_loader_without_replacing_system_libraries': True,
              'files': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for name, (_, raw) in members.items()}}
    save(result_path, result)
    print(json.dumps({'ready': True, 'bytes': path.stat().st_size, 'files': len(members), 'native_platform_acceptance': False}))


if __name__ == '__main__':
    main()
