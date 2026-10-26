"""Prepare pinned Windows application dependencies; never run model inference."""
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import re
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def main():
    folder = ROOT / 'runtime/enrollment-images'
    destination = folder / 'windows-python.zip'
    manifest = folder / 'windows-application-runtime.json'
    if manifest.exists():
        value = json.loads(manifest.read_text())
        for row in value['assets'].values():
            if digest(ROOT / row['path']) != row['sha256']:
                raise ValueError('Pinned Windows application asset changed')
        return print(json.dumps({'ready': True, 'native_acceptance': False, 'manifest': str(manifest)}))
    source = ROOT / 'downloads/python/python-3.13.16-embed-amd64.zip'
    verification = json.loads((ROOT / 'tools/python-runtime/3.13.16/runtime-verification.json').read_text())
    if digest(source) != verification['archive_sha256']:
        raise ValueError('Previously verified PSF embedded Python archive changed')
    members = {}
    with zipfile.ZipFile(source) as archive:
        for name in archive.namelist():
            if '/' in name or '\\' in name:
                raise ValueError('Unexpected embedded Python archive layout')
            members[name] = archive.read(name)
    members['python313._pth'] = b'python313.zip\n.\nsite-packages\nimport site\n'
    sdk = ROOT / 'tools/enrollment-management'
    dependencies = []
    for distribution in importlib.metadata.distributions(path=[str(sdk)]):
        if distribution.metadata['Name'].lower() not in ('cryptography', 'cffi', 'pycparser'):
            continue
        record = distribution.read_text('RECORD')
        for name, pin, _ in csv.reader(io.StringIO(record)):
            path = (sdk / name).resolve()
            if not path.is_relative_to(sdk) or name.startswith('../'):
                continue  # pip-generated command wrappers are not runtime files.
            if not path.is_file() or not pin or name.endswith('.pyc'):
                continue
            algorithm, expected = pin.split('=', 1)
            if algorithm != 'sha256' or base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode().rstrip('=') != expected:
                raise ValueError('Installed dependency differs from its wheel RECORD')
            members['site-packages/' + name.replace('\\', '/')] = path.read_bytes()
        dependencies.append({'name': distribution.metadata['Name'], 'version': distribution.version,
            'record_sha256': hashlib.sha256(record.encode()).hexdigest()})
    if len(dependencies) != 3:
        raise ValueError('Expected the three pinned native cryptography dependency distributions')
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, raw in sorted(members.items()):
            entry = zipfile.ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, raw)
    lock_path = ROOT / 'tools/windows-llama-lock.json'
    if lock_path.exists():
        llama = json.loads(lock_path.read_text())
    else:
        with urllib.request.urlopen('https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/b11711', timeout=30) as response:
            release = json.load(response)
        asset = next(row for row in release['assets'] if row['name'] == 'llama-b11711-bin-win-cpu-x64.zip')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest', '')) or asset['size'] > 128 * 1024**2:
            raise ValueError('Expected a bounded publisher-digested Windows CPU runtime')
        llama = {'url': asset['browser_download_url'], 'path': 'downloads/enrollment/' + asset['name'],
                 'bytes': asset['size'], 'sha256': asset['digest'].split(':')[1],
                 'digest_source': 'GitHub release b11711 asset digest from the upstream publisher'}
        save(lock_path, llama)
    path = ROOT / llama['path']
    if not path.exists():
        with urllib.request.urlopen(llama['url'], timeout=30) as source, path.with_suffix('.partial').open('wb') as output:
            count = 0
            while raw := source.read(1024 * 1024):
                count += len(raw)
                if count > llama['bytes']:
                    raise ValueError('Windows inference archive exceeded publisher size')
                output.write(raw)
        if digest(path.with_suffix('.partial')) != llama['sha256']:
            raise ValueError('Windows inference archive publisher digest failed')
        path.with_suffix('.partial').replace(path)
    if path.stat().st_size != llama['bytes'] or digest(path) != llama['sha256']:
        raise ValueError('Pinned Windows inference runtime changed')
    with zipfile.ZipFile(path) as archive:
        if not any(name.endswith('/llama-server.exe') or name == 'llama-server.exe' for name in archive.namelist()):
            raise ValueError('Windows CPU runtime lacks the actual inference server')
        files = archive.namelist()
    result = {'schema': 'agenticvm.windows-application-runtime.v1', 'native_acceptance': False,
        'model_executed_on_host': False, 'source_python_archive_sha256': verification['archive_sha256'],
        'dependency_distributions': dependencies, 'dependency_install_report_sha256': digest(ROOT / 'tools/enrollment-management-install.json'),
        'python_files': {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()},
        'llama_archive_members': files,
        'assets': {'python': {'path': destination.relative_to(ROOT).as_posix(), 'sha256': digest(destination), 'bytes': destination.stat().st_size},
                   'llama': llama}}
    save(manifest, result)
    print(json.dumps({'ready': True, 'native_acceptance': False, 'model_executed_on_host': False,
        'python_bytes': destination.stat().st_size, 'llama_bytes': path.stat().st_size, 'manifest': str(manifest)}))


if __name__ == '__main__':
    main()
