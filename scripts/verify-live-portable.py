"""Test the shipped native executable, continuous retention, stop and recovery."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.ext2 import read_image_file
from agenticvm.qemu import QemuBackend
from agenticvm.state import StateStore


def main():
    bundle = ROOT/'dist/Agent-Live-v1'
    executable = bundle/'Agent-Live.exe'
    archive = ROOT/'dist/Agent-Live-v1.zip'
    receipt = json.loads(archive.with_suffix('.archive.json').read_text())
    with archive.open('rb') as source:
        if hashlib.file_digest(source,'sha256').hexdigest() != receipt['sha256']:
            raise ValueError('ZIP pin changed')
    with zipfile.ZipFile(archive) as package:
        if package.testzip() is not None:
            raise ValueError('ZIP CRC failed')
        if any('/runtime/live-agent-runs/' in name or name.endswith(('.key','.sqlite')) for name in package.namelist()):
            raise ValueError('Private state was shipped')
    manifest = json.loads((bundle/'live-manifest.json').read_text())
    def verify_static():
        for item in manifest['files']:
            path = bundle/item['path']
            with path.open('rb') as source:
                if path.stat().st_size != item['bytes'] or hashlib.file_digest(source,'sha256').hexdigest() != item['sha256']:
                    raise ValueError('Static payload changed: '+item['path'])
    verify_static()
    env = os.environ.copy()
    windows = Path(os.environ.get('SystemRoot',r'C:\Windows'))
    env['PATH'] = str(windows/'System32')+';'+str(windows)
    env['AGENTICVM_QEMU'] = str(windows/'System32/whoami.exe')
    env.pop('PYTHONPATH',None)
    env.pop('PYTHONHOME',None)
    base = bundle/'runtime/live-agent-runs'

    def folders():
        return {p for p in base.iterdir() if p.is_dir()} if base.exists() else set()

    def run(*args,timeout=180):
        return subprocess.run([str(executable),*args],cwd=windows/'Temp',env=env,
            capture_output=True,timeout=timeout,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

    def new_run(before):
        found = folders()-before
        if len(found) != 1:
            raise ValueError('Expected exactly one new owned run')
        return found.pop()

    def assert_clean(folder):
        for name in ('live-a','live-b'):
            workspace = folder/name
            state = StateStore(workspace).load()
            if state['registered'] or state['status'] != 'stopped':
                raise AssertionError('A test VM remained registered')
            try:
                read_image_file(workspace/'data/default.ext2','peer/live.key')
                raise AssertionError('Disposable guest private key remains')
            except FileNotFoundError:
                pass

    before = folders()
    full = run('test')
    full_folder = new_run(before)
    full_report = json.loads((full_folder/'report.json').read_text())
    if full.returncode or not full_report['passed'] or full_report['cleanup_failures']:
        raise AssertionError('Native sustained run failed: '+str(full_report.get('error')))
    assert_clean(full_folder)
    print(json.dumps({'event':'native_sustained_passed','run':full_folder.name}),flush=True)

    before = folders()
    log = (bundle/'runtime/native-continuous-check.log').open('xb')
    controller = subprocess.Popen([str(executable),'run'],cwd=windows/'Temp',env=env,stdout=log,stderr=log,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    continuous_folder = None
    try:
        deadline = time.monotonic()+90
        while time.monotonic() < deadline:
            found = folders()-before
            if len(found) == 1:
                continuous_folder = next(iter(found))
                journal = continuous_folder/'checkpoints.jsonl'
                if journal.exists() and any(json.loads(line)['event']=='live_agents_started' for line in journal.read_text().splitlines()):
                    break
            if controller.poll() is not None:
                raise RuntimeError('Continuous native run exited during startup')
            time.sleep(.25)
        else:
            raise TimeoutError('Continuous native pair did not start')
        # Beyond 128 events per direction, verify explicit rolling retention.
        end = time.monotonic()+45
        while time.monotonic() < end:
            if controller.poll() is not None:
                raise RuntimeError('Continuous contact stopped unexpectedly')
            time.sleep(.5)
        snapshots = {}
        for name in ('live-a','live-b'):
            command = [str(bundle/'tools/python/python.exe'),'-I','-B','-m','agenticvm','--workspace',str(continuous_folder/name),
                'exec','--timeout-ms','10000','--','/usr/bin/python3','-I','-c',
                "import json,sqlite3;d=sqlite3.connect('file:/workspace/peer/live.sqlite?mode=ro',uri=True);print(json.dumps({'counters':d.execute('SELECT sent,received,acked,consumed FROM counters').fetchone(),'outgoing_rows':d.execute('SELECT COUNT(*) FROM outgoing').fetchone()[0],'incoming_rows':d.execute('SELECT COUNT(*) FROM incoming').fetchone()[0]}))"]
            response = subprocess.run(command,cwd=windows/'Temp',env=env,capture_output=True,timeout=20)
            envelope = json.loads(response.stdout)
            if response.returncode or envelope['result']['exit_code']:
                raise RuntimeError('Could not inspect owned continuous mailbox')
            snapshot = json.loads(envelope['result']['stdout'])
            sent,received,acked,consumed = snapshot['counters']
            if min(sent,received,acked,consumed) <= 128 or max(snapshot['outgoing_rows'],snapshot['incoming_rows']) > 140:
                raise AssertionError('Continuous delivery or bounded retention did not advance')
            snapshots[name] = snapshot
        stopped = run('stop',continuous_folder.name,timeout=20)
        if stopped.returncode:
            raise RuntimeError('Native stop request failed')
        controller.wait(timeout=40)
        continuous_report = json.loads((continuous_folder/'report.json').read_text())
        if controller.returncode or not continuous_report.get('stopped_by_user') or continuous_report['cleanup_failures']:
            raise AssertionError('Continuous native cleanup failed')
        assert_clean(continuous_folder)
    finally:
        if controller.poll() is None:
            if continuous_folder and not (continuous_folder/'CANCEL').exists():
                (continuous_folder/'CANCEL').write_bytes(b'stop\n')
            try:
                controller.wait(timeout=45)
            except subprocess.TimeoutExpired:
                # Do not kill unknown VM processes. Exact recovery follows below.
                controller.terminate()
                controller.wait(timeout=10)
                if continuous_folder:
                    run('recover',continuous_folder.name,timeout=100)
        log.close()
    print(json.dumps({'event':'native_continuous_retention_and_stop_passed','run':continuous_folder.name}),flush=True)

    before = folders()
    fault = run('test-crash',timeout=100)
    fault_folder = new_run(before)
    if fault.returncode != 23:
        raise AssertionError('Controlled controller crash was not reached')
    for name in ('live-a','live-b'):
        store = StateStore(fault_folder/name)
        state = store.load()
        with QemuBackend(store,Path(state['executable']))._process(state) as owned:
            if not state['registered'] or not owned.alive():
                raise AssertionError('Crash fixture did not leave two real owned VMs running')
    recovered = run('recover',fault_folder.name,timeout=120)
    recovery = json.loads((fault_folder/'recovery.json').read_text())
    if recovered.returncode or not recovery['passed'] or recovery['tasks_replayed']:
        raise AssertionError('Native crash recovery failed')
    assert_clean(fault_folder)
    recovery_report = {'passed':True,'native_controller_exit_code':23,'actual_owned_vms_alive_at_crash':2,
        'tasks_replayed':False,'guest_private_keys_removed':True,'recovery':recovery,
        'evidence_directory':str(fault_folder.relative_to(ROOT)),'separate_physical_hosts_tested':False}
    (ROOT/'docs/validation/live-recovery-report.json').write_text(json.dumps(recovery_report,indent=2)+'\n')
    verify_static()
    report = {'passed':True,'archive_sha256':receipt['sha256'],'archive_bytes':receipt['bytes'],
        'native_executable_sha256':receipt['exe_sha256'],'static_files_verified':len(manifest['files']),
        'foreign_cwd':str(windows/'Temp'),'system_python_removed_from_path':True,'inherited_qemu_override_ignored':True,
        'finite_live_vm_run':str(full_folder.relative_to(ROOT)),'continuous_until_explicit_stop':True,
        'continuous_mailbox_snapshots':snapshots,'continuous_run':str(continuous_folder.relative_to(ROOT)),
        'controller_crash_recovery_passed':True,'private_runtime_state_in_archive':False,
        'separate_physical_hosts_tested':False,'physical_4gb_host_tested':False}
    (ROOT/'docs/validation/live-native-portable-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'report':str(ROOT/'docs/validation/live-native-portable-report.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
