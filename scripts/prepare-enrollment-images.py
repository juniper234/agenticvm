"""Acquire pinned public Linux images and a local disk-image utility.

No installer runs on Windows. Images remain data until an owned lab VM boots.
Published HTTPS digests are verified; detached signatures are not claimed here.
"""
from __future__ import annotations
import concurrent.futures
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'tools/enrollment-assets-lock.json'


def digest(path, algorithm='sha256'):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read(1024 * 1024))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def acquire(entry):
    path = ROOT / entry['path']
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if digest(path) != entry['sha256']:
            raise ValueError('Cached image differs from pin: ' + path.name)
        return path
    partial = path.with_suffix(path.suffix + '.partial')
    # Resume is rechecked by the full digest; never append a 200 response.
    offset = partial.stat().st_size if partial.exists() else 0
    request = urllib.request.Request(entry['url'], headers={'Range': f'bytes={offset}-'} if offset else {})
    print('Downloading pinned ' + entry['name'], flush=True)
    with urllib.request.urlopen(request, timeout=60) as response:
        append = bool(offset and response.status == 206)
        if append and not response.headers.get('Content-Range', '').startswith(f'bytes {offset}-'):
            raise ValueError('Image resume offset mismatch')
        count = offset if append else 0
        with partial.open('ab' if append else 'wb') as output:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > 2 * 1024**3:
                    raise ValueError('Compressed image input limit')
                output.write(chunk)
    if digest(partial) != entry['sha256']:
        raise ValueError('Downloaded image digest mismatch: ' + entry['name'])
    partial.replace(path)
    print('Verified ' + entry['name'] + ': ' + str(path.stat().st_size) + ' bytes', flush=True)
    return path


def main():
    if not LOCK.exists():
        stream_url = 'https://builds.coreos.fedoraproject.org/streams/stable.json'
        stream = fetch_json(stream_url)
        release = stream['architectures']['x86_64']['artifacts']['qemu']
        core = release['formats']['qcow2.xz']['disk']
        ubuntu_root = 'https://cloud-images.ubuntu.com/noble/current/'
        with urllib.request.urlopen(ubuntu_root + 'SHA256SUMS', timeout=30) as response:
            sums = response.read(128 * 1024).decode()
        ubuntu_name = 'noble-server-cloudimg-amd64.img'
        ubuntu_sha = next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*') == ubuntu_name)
        write_json(LOCK, {'schema': 'agenticvm.enrollment-assets.v1', 'digest_trust': 'Publisher HTTPS manifests; signatures not yet verified',
            'assets': [
                {'name': 'Ubuntu 24.04 LTS cloud image', 'url': ubuntu_root + ubuntu_name,
                 'sha256': ubuntu_sha, 'digest_source': ubuntu_root + 'SHA256SUMS',
                 'path': 'downloads/enrollment/ubuntu-noble-amd64.img'},
                {'name': 'Fedora CoreOS QEMU ' + release['release'], 'url': core['location'],
                 'sha256': core['sha256'], 'uncompressed_sha256': core['uncompressed-sha256'],
                 'signature_url': core['signature'], 'digest_source': stream_url,
                 'path': 'downloads/enrollment/fedora-coreos-amd64.qcow2.xz',
                 'uncompressed_path': 'runtime/enrollment-images/fedora-coreos-amd64.qcow2'}]})
    lock = json.loads(LOCK.read_text())
    if shutil.disk_usage(ROOT).free < 7 * 1024**3:
        raise RuntimeError('At least 7 GiB free disk is required before image preparation')
    # Extract only the known utility from the already pinned QEMU archive.
    qemu = json.loads((ROOT / 'tools/build-tools-lock.json').read_text())['sources']['qemu']
    archive = ROOT / qemu['archive']
    if archive.stat().st_size != qemu['bytes'] or digest(archive, qemu['algorithm']) != qemu['digest']:
        raise ValueError('Pinned QEMU archive mismatch')
    tool_dir = ROOT / 'tools/enrollment-image-tools'
    tool_dir.mkdir(exist_ok=True)
    utility = tool_dir / 'qemu-img.exe'
    if not utility.exists():
        with utility.open('xb') as output:
            child = subprocess.run([str(ROOT / 'tools/7zip/26.04/7z.exe'), 'x', '-so', str(archive), 'qemu-img.exe'],
                                   stdout=output, stderr=subprocess.PIPE, timeout=60)
        if child.returncode or utility.stat().st_size != 1934744:
            raise ValueError('Disk utility extraction failed')
    env = {**os.environ, 'PATH': str(ROOT / qemu['destination']) + os.pathsep + os.environ['PATH']}
    child = subprocess.run([str(utility), '--version'], env=env, capture_output=True, text=True, timeout=10)
    if child.returncode or '11.1.0' not in child.stdout:
        raise ValueError('Unexpected disk utility')
    receipt = tool_dir / 'manifest.json'
    if receipt.exists() and json.loads(receipt.read_text())['sha256'] != digest(utility):
        raise ValueError('Disk utility changed')
    write_json(receipt, {'sha256': digest(utility), 'version': child.stdout.splitlines()[0],
                         'source_archive_sha512': qemu['digest']})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(acquire, entry) for entry in lock['assets']]:
            future.result()
    for entry in lock['assets']:
        if 'uncompressed_path' not in entry:
            continue
        target = ROOT / entry['uncompressed_path']
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            partial = target.with_suffix('.partial')
            if partial.exists():
                raise ValueError('Interrupted decompression retained; reconcile this owned partial file')
            count = 0
            print('Decompressing verified CoreOS image', flush=True)
            with lzma.open(ROOT / entry['path']) as source, partial.open('xb') as output:
                while chunk := source.read(1024 * 1024):
                    count += len(chunk)
                    if count > 5 * 1024**3:
                        raise ValueError('Uncompressed image bound exceeded')
                    output.write(chunk)
            if digest(partial) != entry['uncompressed_sha256']:
                raise ValueError('Uncompressed CoreOS image mismatch')
            partial.replace(target)
        if digest(target) != entry['uncompressed_sha256']:
            raise ValueError('Cached uncompressed image changed')
    print(json.dumps({'ready': True, 'lock': str(LOCK), 'free_disk_bytes': shutil.disk_usage(ROOT).free}), flush=True)


if __name__ == '__main__':
    main()
