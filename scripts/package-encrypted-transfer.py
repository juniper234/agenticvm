"""Build a fresh small transfer utility; exclude all endpoint/runtime state."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'dist/Encrypted-Transfer-v1')
    args = parser.parse_args()
    output = args.output.absolute()
    output.relative_to(ROOT/'dist')
    if output.exists() or output.is_symlink() or any(p.is_symlink() or getattr(p,'is_junction',lambda:False)() for p in (output.parent,*output.parents)):
        raise ValueError('Choose a fresh ordinary directory inside dist')
    portable = module('transfer_portable', 'package-portable.py')
    python, archive, verified = portable.prepare_python(download=False)
    module('transfer_prepare', 'prepare-transfer-runtime.py').prepare()
    output.mkdir(parents=True)
    target_python = output/'tools/python'
    target_python.mkdir(parents=True)
    lock = json.loads((ROOT/'tools/python-runtime-lock.json').read_text())
    for entry in portable.zip_entries(archive, lock):
        shutil.copy2(python/entry.filename, target_python/entry.filename)
    (target_python/lock['pth_file']).write_bytes(portable.pth_contents(lock, portable=True))
    portable.verify_python_tree(target_python, archive, lock, portable=True)
    for name in ('__init__.py', 'offline_transfer.py', 'blind_transfer.py'):
        target = output/'src/agenticvm'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT/'src/agenticvm'/name, target)
    target = output/'scripts/run-encrypted-transfer.py'
    target.parent.mkdir(parents=True)
    shutil.copy2(ROOT/'scripts/run-encrypted-transfer.py', target)
    for platform in ('windows','linux'):
        shutil.copytree(ROOT/'tools/transfer-runtime'/platform, output/'tools/transfer-runtime'/platform,
                        ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    shutil.copy2(ROOT/'tools/transfer-runtime-lock.json', output/'tools/transfer-runtime-lock.json')
    docs = output/'docs'
    docs.mkdir()
    shutil.copy2(ROOT/'docs/encrypted-transfer.md', docs/'encrypted-transfer.md')
    (docs/'validation').mkdir()
    for name in ('disconnected-transfer-report.json','test-scope-audit.json'):
        path = ROOT/'docs/validation'/name
        if path.is_file():
            shutil.copy2(path, docs/'validation'/name)
    zig = ROOT/'tools/zig/zig-x86_64-windows-0.15.2/zig.exe'
    spec = json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['zig']
    if digest(zig) != spec['exe_sha256']:
        raise ValueError('Compiler does not match its pin')
    build = ROOT/'runtime'/('build-transfer-launcher-'+uuid4().hex[:8])
    subprocess.run([sys.executable,'-I',str(ROOT/'scripts/run-bounded.py'),'--output',str(build),'--',str(zig),
        'cc','-target','x86_64-windows-gnu','-nostdlib','-Os','-s',
        '-isystem',str(zig.parent/'lib/libc/include/any-windows-any'),'-Wl,-e,mainCRTStartup',
        '-Wl,--subsystem,console','-lkernel32','-lshell32','-DAGENTICVM_TRANSFER=1',
        str(ROOT/'guest/chain-launcher.c'),'-o',str(output/'Encrypted-Transfer.exe')],check=True,cwd=ROOT)
    (output/'QUICKSTART.txt').write_text(
        'Double-click Encrypted-Transfer.exe. Keep the whole folder together.\n'
        'It demonstrates encrypted delivery and receipts between two independent host processes.\n'
        'This small utility does not boot VMs or download models.\n'
        'For the separately verified offline Linux VM test, see docs/validation/disconnected-transfer-report.json.\n'
        'Two separate physical computers and remote HTTPS deployment remain untested.\n'
        'Commands: Encrypted-Transfer.exe endpoint --help / courier --help\n'
        'Guide: docs/encrypted-transfer.md\n'
        'Demo state: runtime/transfer-demo/<UUID>. Each endpoint retains its own private keys locally.\n'
        'No private identities or runtime user state are shipped in this archive.\n'
        'Remote use requires an explicitly configured HTTPS relay and independent public-key fingerprint checks.\n'
        'The launcher is not Authenticode-signed; bundled Python publisher signatures were checked.\n',encoding='utf-8')
    (output/'Start-Encrypted-Transfer.cmd').write_bytes(b'@echo off\r\n"%~dp0Encrypted-Transfer.exe" %*\r\n')
    (output/'THIRD-PARTY-NOTICES.txt').write_text(
        'Python 3.13.16: Python Software Foundation license, tools/python/LICENSE.txt.\n'
        'PyNaCl 1.6.2: Apache-2.0; includes libsodium ISC license.\n'
        'CFFI 2.1.1: MIT. pycparser 3.11: BSD-3-Clause.\n'
        'Original wheel license texts are preserved in the platform-specific *.dist-info directories.\n'
        'Official artifacts and SHA-256 pins: tools/transfer-runtime-lock.json.\n',encoding='utf-8')
    files = [{'path':p.relative_to(output).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)}
             for p in sorted(output.rglob('*')) if p.is_file()]
    manifest = {'schema':'agenticvm.encrypted-transfer-bundle.v1', 'files':files,
                'python_verified':verified, 'vm_images_included':False, 'private_keys_included':False}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    archive_path = output.with_name(output.name+'.zip')
    with zipfile.ZipFile(archive_path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for item in files:
            if item['path'].startswith('runtime/') or 'private.json' in item['path']:
                raise ValueError('Private runtime data selected for packaging')
            archive.write(output/item['path'],output.name+'/'+item['path'])
        archive.write(output/'manifest.json',output.name+'/manifest.json')
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise ValueError('Archive CRC verification failed')
    smoke = subprocess.run([str(output/'Encrypted-Transfer.exe'),'--describe'],capture_output=True,timeout=20,cwd=ROOT)
    if smoke.returncode or b'Encrypted-Transfer.exe' not in smoke.stdout:
        raise ValueError('Native launcher description failed')
    receipt = {'passed':True,'archive':str(archive_path.relative_to(ROOT)),'bytes':archive_path.stat().st_size,
               'sha256':digest(archive_path),'files':len(files)+1,'crc_verified':True,'native_description_passed':True,
               'runtime_user_state_in_archive':False,'exe_sha256':digest(output/'Encrypted-Transfer.exe')}
    archive_path.with_suffix('.archive.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipt))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
