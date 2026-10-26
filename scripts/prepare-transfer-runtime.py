"""Prepare pinned private PyNaCl runtimes for Windows and offline Linux guests."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def prepare():
    lock = json.loads((ROOT/'tools/transfer-runtime-lock.json').read_text())
    for platform, packages in lock['platforms'].items():
        destination = ROOT/'tools/transfer-runtime'/platform
        destination.mkdir(parents=True, exist_ok=True)
        expected = set()
        for package in packages:
            archive = ROOT/'downloads/transfer'/package['filename']
            archive.parent.mkdir(parents=True, exist_ok=True)
            if not archive.exists():
                with urllib.request.urlopen(package['url'], timeout=30) as response:
                    content = response.read(package['bytes']+1)
                if len(content) != package['bytes'] or hashlib.sha256(content).hexdigest() != package['sha256']:
                    raise ValueError('Downloaded transfer wheel does not match its pin')
                with archive.open('xb') as target:
                    target.write(content)
            with archive.open('rb') as source:
                if archive.stat().st_size != package['bytes'] or hashlib.file_digest(source, 'sha256').hexdigest() != package['sha256']:
                    raise ValueError('Cached transfer wheel changed')
            with zipfile.ZipFile(archive) as wheel:
                entries = wheel.infolist()
                if len(entries) > 300 or sum(e.file_size for e in entries) > 24*1024**2:
                    raise ValueError('Wheel exceeds its inventory bounds')
                for entry in entries:
                    path = PurePosixPath(entry.filename)
                    if path.is_absolute() or '..' in path.parts or '\\' in entry.filename or ':' in entry.filename or stat.S_ISLNK(entry.external_attr >> 16):
                        raise ValueError('Unsafe wheel member')
                    if entry.is_dir():
                        continue
                    expected.add(path.as_posix())
                    target = destination.joinpath(*path.parts)
                    content = wheel.read(entry)
                    if target.exists():
                        if target.read_bytes() != content:
                            raise ValueError('Existing private transfer runtime changed')
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open('xb') as output:
                            output.write(content)
        actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*')
                  if path.is_file() and '__pycache__' not in path.parts}
        if actual != expected:
            raise ValueError('Private transfer runtime has unexpected or missing files')
    return {platform: str(ROOT/'tools/transfer-runtime'/platform) for platform in lock['platforms']}


if __name__ == '__main__':
    print(json.dumps({'prepared': prepare()}))
