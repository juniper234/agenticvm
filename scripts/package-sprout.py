"""Make a self-contained Sprout.exe from verified local runtime inputs."""
import base64
import argparse
import hashlib
import json
import os
import importlib.util
import io
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rebuild-bootstrap',action='store_true')
    parser.add_argument('--refresh-runtime',action='store_true')
    parser.add_argument('--lfm',action='store_true',help='Bundle the actual pinned LFM2.5 model and inference boot profile')
    args = parser.parse_args()
    if args.refresh_runtime and args.rebuild_bootstrap:
        raise ValueError('Choose either a runtime rebuild or bootstrap rebuild')
    old = ROOT/'dist/Agent-Live-v1'
    output = ROOT/('dist/Garden-Sprout-LFM-v1' if args.lfm else 'dist/Garden-Sprout-v1')
    if not args.rebuild_bootstrap and not args.refresh_runtime:
        output.mkdir()
    if args.refresh_runtime:
        index = 1
        while (output/('runtime-attempt-'+str(index))).exists():
            index += 1
        backup = output/('runtime-attempt-'+str(index))
        backup.mkdir()
        for name in ('sprout-payload.zip','Sprout.exe','build-report.json','sprout-manifest.json'):
            (output/name).rename(backup/name)
    # The immutable earlier manifest, not a recursive search through VM state.
    manifest = json.loads((old/'live-manifest.json').read_text())
    selected = {}
    for item in manifest['files']:
        name = item['path']
        if name.startswith(('tools/python/','tools/qemu/','runtime/linux-peer/','runtime/linux-desktop/')) or name == 'THIRD-PARTY-NOTICES.txt':
            # The peer profile needs the common immutable root and its ISO;
            # omit the graphical boot ISO/manifests, extra CLI launchers/docs.
            if name.startswith('runtime/linux-desktop/') and name != 'runtime/linux-desktop/rootfs.ext2':
                continue
            path = old/name
            if not path.is_file() or path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
                raise ValueError('Prior pinned runtime changed: '+name)
            selected[name] = path
    for pattern in ('src/agenticvm/**/*.py','guest/*.py'):
        for path in ROOT.glob(pattern):
            selected[path.relative_to(ROOT).as_posix()] = path
    selected['scripts/run-garden.py'] = ROOT/'scripts/run-garden.py'
    if args.lfm:
        model = ROOT/'runtime/local-model-test'
        prepared = json.loads((model/'preparation.json').read_text())
        boot = json.loads((model/'boot/build-manifest.json').read_text())
        library_sha = '6456b504ac347bd50c419667440b691f6966ad8aff5309d2f06c977fe2f9debe'
        provenance = json.loads((model/'dependencies/provenance.json').read_text())
        deb = model/'dependencies/libgomp1_14.2.0-19_amd64.deb'
        if sha(deb)!=provenance['sha256'] or sha(model/'dependencies/libgomp.so.1')!=library_sha:
            raise ValueError('Pinned Linux OpenMP runtime changed')
        spec = importlib.util.spec_from_file_location('sprout_debian',ROOT/'scripts/desktop-image-debian.py')
        debian = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(debian)
        with tarfile.open(fileobj=io.BytesIO(debian.package_payload(deb))) as package:
            libraries = [entry for entry in package if entry.isfile() and '/libgomp.so.' in entry.name]
            if len(libraries)!=1 or hashlib.sha256(package.extractfile(libraries[0]).read()).hexdigest()!=library_sha:
                raise ValueError('OpenMP differs from its verified Debian package')
        assets = {'model.gguf':model/'downloads/LFM2.5-350M-Q4_K_M.gguf',
                  'llama-b11711-bin-ubuntu-x64.tar.gz':model/'downloads/llama-b11711-bin-ubuntu-x64.tar.gz',
                  'libgomp.so.1':model/'dependencies/libgomp.so.1',
                  'agenticvm-linux-peer.iso':model/'boot/agenticvm-linux-peer.iso'}
        expected = {'model.gguf':('LFM2.5-350M-Q4_K_M.gguf',prepared['sources']['LFM2.5-350M-Q4_K_M.gguf']['sha256']),
                    'llama-b11711-bin-ubuntu-x64.tar.gz':('llama-b11711-bin-ubuntu-x64.tar.gz',prepared['sources']['llama-b11711-bin-ubuntu-x64.tar.gz']['sha256']),
                    'libgomp.so.1':(None,library_sha),'agenticvm-linux-peer.iso':(None,boot['iso']['sha256'])}
        for name,path in assets.items():
            if sha(path)!=expected[name][1]:
                raise ValueError('Pinned model/runtime changed: '+name)
            selected['models/lfm2.5-350m/'+name] = path
        model_lock = {'schema':'agenticvm.garden-lfm.v1','name':'LFM2.5-350M-Q4_K_M',
                      'model_revision':prepared['model_revision'],'sources':prepared['sources'],
                      'guest_memory_mib':512,'process_virtual_address_space_bytes':2*1024**3,
                      'execution_location':'Linux guests only','cpu_threads':1,'context_tokens':1024,'gpu':False,
                      'files':{name:{'bytes':path.stat().st_size,'sha256':sha(path)} for name,path in assets.items()}}
        path = output/'model-lock.json'
        path.write_text(json.dumps(model_lock,indent=2)+'\n')
        selected['models/lfm2.5-350m/model-lock.json'] = path
        for name,source in (('agent-inference-test.c',model/'agent-inference-test.c'),
                            ('boot-build-manifest.json',model/'boot/build-manifest.json'),
                            ('preparation.json',model/'preparation.json'),
                            ('libgomp-provenance.json',model/'dependencies/provenance.json')):
            selected['models/lfm2.5-350m/'+name] = source
        selected['scripts/run-garden-lfm.py'] = ROOT/'scripts/run-garden-lfm.py'
        notices = output/'LFM-NOTICES.txt'
        notices.write_text('Local development assembly; not externally published.\n'
            'LiquidAI LFM2.5-350M Q4_K_M, revision '+prepared['model_revision']+'\n'
            'Model card/license: https://huggingface.co/LiquidAI/LFM2.5-350M-GGUF/tree/'+prepared['model_revision']+'\n'
            'llama.cpp b11711 (MIT), license included in its pinned runtime archive.\n'
            'libgomp1 14.2.0-19: GPL with GCC runtime exception; Debian package provenance pinned.\n')
        selected['LFM-NOTICES.txt'] = notices
    required = ('tools/python/python.exe','tools/qemu/11.1.0/qemu-system-x86_64.exe',
                'runtime/linux-peer/agenticvm-linux-peer.iso','runtime/linux-desktop/rootfs.ext2')
    if any(name not in selected for name in required):
        raise ValueError('Required garden runtime missing')
    files = [{'path':name,'bytes':path.stat().st_size,'sha256':sha(path)} for name,path in sorted(selected.items())]
    lock = {'schema':'agenticvm.sprout.v1','files':files,'guest_memory_mib':512 if args.lfm else 256,'max_members':3,
            'private_state_included':False,'model_inference':args.lfm,'requires_existing_whpx':True,
            'scope':'same physical computer; two seeds then one new sprout'}
    payload = output/'sprout-payload.zip'
    if args.rebuild_bootstrap:
        with zipfile.ZipFile(payload) as package:
            if json.loads(package.read('sprout-manifest.json')) != lock:
                raise ValueError('Runtime source changed; a full fresh package is required')
        previous = json.loads((output/'build-report.json').read_text())
        if sha(payload) != previous['payload_sha256']:
            raise ValueError('Previous payload changed')
        index = 1
        while (output/('Sprout-attempt-'+str(index)+'.exe')).exists():
            index += 1
        (output/'Sprout.exe').rename(output/('Sprout-attempt-'+str(index)+'.exe'))
        (output/'build-report.json').rename(output/('build-report-attempt-'+str(index)+'.json'))
    else:
        with zipfile.ZipFile(payload,'x',zipfile.ZIP_DEFLATED,compresslevel=6) as package:
            for name,path in sorted(selected.items()):
                package.write(path,name)
            package.writestr('sprout-manifest.json',json.dumps(lock,indent=2)+'\n')
    with zipfile.ZipFile(payload) as package:
        if package.testzip():
            raise ValueError('Sprout payload CRC failed')
    payload_sha = sha(payload)
    script = (ROOT/'scripts/sprout-bootstrap.ps1').read_text().replace('__PAYLOAD_SHA256__',payload_sha)
    if args.lfm:
        script = script.replace("'.agenticvm\\Garden-v1'","'.agenticvm\\Garden-LFM-v1'")
        script = script.replace('scripts\\run-garden.py','scripts\\run-garden-lfm.py')
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    if len(encoded)>27000:
        raise ValueError('Native bootstrap command too large')
    (output/'sprout-bootstrap.h').write_text('#define SPROUT_COMMAND L"'+encoded+'"\n')
    zig = ROOT/'tools/zig/zig-x86_64-windows-0.15.2/zig.exe'
    zig_lock = json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['zig']
    if sha(zig) != zig_lock['exe_sha256']:
        raise ValueError('Pinned compiler changed')
    exe = output/'Sprout.exe'
    subprocess.run([sys.executable,'-I',str(ROOT/'scripts/run-bounded.py'),'--output',
                    str(ROOT/'runtime'/('build-sprout-'+uuid4().hex[:8])),'--',str(zig),
                    'cc','-target','x86_64-windows-gnu','-nostdlib','-Os','-s',
                    '-isystem',str(zig.parent/'lib/libc/include/any-windows-any'),'-I',str(output),
                    '-Wl,-e,mainCRTStartup','-Wl,--subsystem,console','-lkernel32',
                    str(ROOT/'guest/sprout-installer.c'),'-o',str(exe)],check=True)
    with exe.open('ab') as destination,payload.open('rb') as source:
        shutil.copyfileobj(source,destination,1024*1024)
        destination.write(b'AGARDEN-PAYLOAD1'+struct.pack('<Q',payload.stat().st_size))
    result = {'schema':'agenticvm.sprout-build.v1','exe':str(exe.relative_to(ROOT)),
              'bytes':exe.stat().st_size,'sha256':sha(exe),'payload_sha256':payload_sha,
              'payload_bytes':payload.stat().st_size,'files':len(files),
              'one_file_needed':True,'no_external_runtime_needed':True,'private_state_included':False,
              'model_inference':args.lfm,'guest_memory_mib':512 if args.lfm else 256,
              'unsigned_development_build':True,'installed_root':str(Path(os.environ['USERPROFILE'])/('.agenticvm/Garden-LFM-v1' if args.lfm else '.agenticvm/Garden-v1')/payload_sha[:16])}
    (output/'build-report.json').write_text(json.dumps(result,indent=2)+'\n')
    (output/'sprout-manifest.json').write_text(json.dumps(lock,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
