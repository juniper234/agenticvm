"""Assemble a runnable continuous-contact VM pair; no models or user VM state."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'dist/Agent-Live-v1')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('live_portable',ROOT/'scripts/package-portable.py')
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    python,archive,verified = portable.prepare_python(download=False)
    output = args.output.absolute()
    report = portable.build_bundle(output,python,archive,verified)
    (output/'live-runtime-lock.json').write_text(json.dumps({
        'schema':'agenticvm.live-runtime.v1','guest_memory_mib':256,'guest_nics':False,
        'default_mode':'continuous blind byte relay','tls':'mutual TLS 1.3, exact peer pins, agenticvm-live/1',
        'model_inference':False,'http':False,'usb':False,'cross_physical_hosts_tested':False},indent=2)+'\n')
    zig = ROOT/'tools/zig/zig-x86_64-windows-0.15.2/zig.exe'
    lock = json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['zig']
    if sha(zig) != lock['exe_sha256']:
        raise ValueError('Compiler changed')
    subprocess.run([sys.executable,'-I',str(ROOT/'scripts/run-bounded.py'),'--output',
        str(ROOT/'runtime'/('build-live-launcher-'+uuid4().hex[:8])),'--',str(zig),
        'cc','-target','x86_64-windows-gnu','-nostdlib','-Os','-s',
        '-isystem',str(zig.parent/'lib/libc/include/any-windows-any'),'-Wl,-e,mainCRTStartup',
        '-Wl,--subsystem,console','-lkernel32','-lshell32','-DAGENTICVM_LIVE=1',
        str(ROOT/'guest/chain-launcher.c'),'-o',str(output/'Agent-Live.exe')],check=True,cwd=ROOT)
    (output/'Start-Agent-Live.cmd').write_bytes(b'@echo off\r\n"%~dp0Agent-Live.exe" %*\r\n')
    (output/'LIVE-QUICKSTART.txt').write_text(
        'Double-click Agent-Live.exe. Keep this whole folder together.\n'
        'Starts two real 256 MiB Linux VMs, both running simultaneously.\n'
        'Their agents maintain continuous encrypted contact over virtual serial and a blind live byte relay.\n'
        'No guest Ethernet, HTTP, USB, shared folder, model download or model inference.\n'
        'A small deterministic event is sent in both directions four times per second.\n'
        'Contact continues until Ctrl+C; all owned VMs then stop and their disposable keys are removed.\n'
        'Alternative: Agent-Live.exe direct (direct virtual serial, no host application relay).\n'
        'Checks: Agent-Live.exe test (finite sustained traffic + idle heartbeats + relay outage).\n'
        'Stop from another terminal: Agent-Live.exe stop RUN-UUID. The UUID is printed at startup.\n'
        'If the controller/PC crashes, the next launch cleans incomplete owned runs before starting a new pair.\n'
        'Recovery stops owned VMs and removes disposable keys; no pending task is replayed.\n'
        'Manual recovery: Agent-Live.exe recover RUN-UUID.\n'
        'Evidence: runtime/live-agent-runs/<UUID>/report.json. Design: docs/live-communication.md.\n'
        'Windows Hypervisor Platform and firmware virtualization must already be available.\n'
        'Same-PC simulation. Different physical hosts and physical 4 GB operation remain untested.\n'
        'The host/hypervisor remains trusted; endpoint keys are generated inside each VM.\n'
        'The native development launcher is not Authenticode-signed. Nothing was installed or published.\n',encoding='utf-8')
    smoke = subprocess.run([str(output/'Agent-Live.exe'),'--describe'],capture_output=True,timeout=20)
    if smoke.returncode or b'Agent-Live.exe' not in smoke.stdout:
        raise ValueError('Native launcher failed its description check')
    # Freeze the static selection BEFORE any VM test creates runtime data.
    (output/'package-manifest.json').unlink()  # Superseded for this fresh assembly by the final live manifest.
    selected = [path for path in sorted(output.rglob('*')) if path.is_file()]
    inventory = [{'path':p.relative_to(output).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in selected]
    allowed_runtime = ('runtime/linux-agent/','runtime/linux-peer/','runtime/linux-desktop/')
    for item in inventory:
        name = item['path']
        if name.startswith('runtime/') and not name.startswith(allowed_runtime) or name.endswith(('.key','.sqlite')) or 'identity.private' in name:
            raise ValueError('Private runtime state was selected')
    manifest = {'schema':'agenticvm.live-bundle.v1','files':inventory,'file_count':len(inventory),
                'private_runtime_state_included':False,'base_portable_validation':report['python_smoke']}
    (output/'live-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    path = output.with_name(output.name+'.zip')
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as package:
        for item in inventory:
            package.write(output/item['path'],output.name+'/'+item['path'])
        package.write(output/'live-manifest.json',output.name+'/live-manifest.json')
    with zipfile.ZipFile(path) as package:
        if package.testzip() is not None:
            raise ValueError('Portable archive CRC failed')
    receipt = {'passed':True,'archive':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,
               'sha256':sha(path),'static_files':len(inventory)+1,'crc_verified':True,
               'private_runtime_state_in_archive':False,'exe_sha256':sha(output/'Agent-Live.exe')}
    path.with_suffix('.archive.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
