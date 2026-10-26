"""Test the actual ZIP/native launcher with spaces, foreign CWD and restricted PATH."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def main():
    archive_path = ROOT/'dist/Encrypted-Transfer-v1.zip'
    receipt = json.loads(archive_path.with_suffix('.archive.json').read_text())
    if archive_path.stat().st_size != receipt['bytes'] or sha(archive_path) != receipt['sha256']:
        raise ValueError('Archive does not match its build receipt')
    folder = ROOT/'runtime/transfer-portable-check'/str(uuid4())/'Offline computers'
    folder.mkdir(parents=True)
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP CRC failed')
        names = set()
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or '..' in path.parts or ':' in entry.filename or '\\' in entry.filename
                    or path.parts[0] != 'Encrypted-Transfer-v1' or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.filename.casefold() in names or entry.file_size > 24*1024**2):
                raise ValueError('Unsafe or unexpected portable ZIP entry')
            names.add(entry.filename.casefold())
            target = folder.joinpath(*path.parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(archive.read(entry))
    bundle = folder/'Encrypted-Transfer-v1'
    manifest = json.loads((bundle/'manifest.json').read_text())
    for item in manifest['files']:
        path = bundle/item['path']
        if path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
            raise ValueError('Extracted payload does not match its manifest')
    selected = {item['path'] for item in manifest['files']}|{'manifest.json'}
    actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob('*') if path.is_file()}
    if selected != actual or any(path.startswith('runtime/') or 'private.json' in path for path in actual):
        raise ValueError('Private state or unexpected files shipped in archive')
    environment = os.environ.copy()
    windows = Path(os.environ.get('SystemRoot',r'C:\Windows'))
    environment['PATH'] = str(windows/'System32')+';'+str(windows)
    for key in ('PYTHONPATH','PYTHONHOME'):
        environment.pop(key,None)
    child = subprocess.run([str(bundle/'Encrypted-Transfer.exe'),'demo'],cwd=windows/'Temp',env=environment,
        capture_output=True, timeout=45, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if child.returncode:
        raise RuntimeError('Native portable demo failed: '+child.stderr.decode('utf-8','replace')[-1200:])
    demo = json.loads(child.stdout)
    if not demo['passed']:
        raise ValueError('Native demo reported a failure')
    report = {'passed':True,'archive_sha256':receipt['sha256'],'archive_bytes':receipt['bytes'],
              'native_executable_sha256':receipt['exe_sha256'],'extracted_payload_files_verified':len(actual),
              'path_contains_spaces':True,'foreign_working_directory':str(windows/'Temp'),
              'system_python_removed_from_path':True,'private_runtime_state_in_archive':False,
              'demo':demo,'scope':'Portable host-process demonstration, not a VM or physical multi-host test',
              'separate_physical_hosts_tested':False}
    target = ROOT/'docs/validation/encrypted-transfer-portable-report.json'
    target.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'report':str(target),'archive_bytes':receipt['bytes']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
