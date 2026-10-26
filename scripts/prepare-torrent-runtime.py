"""Prepare a pinned private libtorrent runtime without pip or global installs."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def prepare():
    lock = json.loads((ROOT/'tools/torrent-runtime-lock.json').read_text())
    archive = ROOT/'downloads/torrent'/lock['filename']
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with urllib.request.urlopen(lock['url'], timeout=30) as stream:
            content = stream.read(lock['bytes']+1)
        if len(content) != lock['bytes'] or hashlib.sha256(content).hexdigest() != lock['sha256']:
            raise ValueError('Torrent wheel verification failed')
        with archive.open('xb') as stream:
            stream.write(content)
    if archive.stat().st_size != lock['bytes'] or hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != lock['sha256']:
        raise ValueError('Cached torrent wheel changed')
    destination = ROOT/lock['destination']
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as wheel:
        entries = wheel.infolist()
        if len(entries) > 40 or sum(e.file_size for e in entries) > 32*1024**2:
            raise ValueError('Unexpected wheel inventory')
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in entry.filename or ':' in entry.filename or stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError('Unsafe wheel member')
            if entry.is_dir():
                continue
            target = destination.joinpath(*path.parts)
            content = wheel.read(entry)
            if target.exists():
                if target.read_bytes() != content:
                    raise ValueError('Existing torrent runtime changed')
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(content)
    return destination


if __name__ == '__main__':
    print(json.dumps({'prepared': str(prepare())}))
