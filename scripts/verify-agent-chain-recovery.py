"""Crash a real owned persistent VM controller, then recover through the EXE."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.chain import Checkpoints, exclusive
from agenticvm.ext2 import read_image_file
from agenticvm.state import StateStore
from agenticvm.torrent import plain, read_json


CHILD = '''
from pathlib import Path
import os,sys
from agenticvm.peers import Runner,VM
root,run=Path(sys.argv[1]),sys.argv[2]
folder=root/'runtime/pong-agent-runs'/run
folder.mkdir(parents=True)
runner=Runner(folder,run,256,1)
runner.journal.add('run_started',purpose='two local-model agents build Pong',fault_fixture=True,model_not_started=True)
runner.provision()
vm=VM(runner,'guest-a-serial')
vm.start('--persistent')
vm.install('guest-a','host')
runner.journal.add('fault_injected',exit_code=23,persistent_guest_key_present=True)
os._exit(23)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=ROOT/'dist/Agent-Chain-v1')
    args = parser.parse_args()
    bundle = plain(args.bundle)
    if bundle.parent != ROOT/'dist' or read_json(bundle/'chain/launcher-lock.json', 256*1024)['schema'] != 'agenticvm.chain-launcher.v1':
        raise ValueError('Select a known local chain assembly')
    run = str(uuid4())
    folder = bundle/'runtime/chain-runs'/run
    with exclusive(bundle/'runtime/chain-runs'):
        folder.mkdir()
        journal = Checkpoints(folder, run)
        journal.add('phase', phase='created', fault_fixture=True)
        journal.add('phase', phase='vms_starting')
        journal.close()
        child = subprocess.run([str(bundle/'tools/python/python.exe'), '-I', '-B', '-c', CHILD, str(bundle), run],
                               capture_output=True, timeout=120, cwd=bundle,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        workspace = bundle/'runtime/pong-agent-runs'/run/'guest-a-serial'
        if child.returncode != 23 or not StateStore(workspace).load()['registered']:
            raise RuntimeError('Crash fixture failed: '+child.stderr.decode(errors='replace')[-1500:])
        if not (workspace.parent/'private/guest-a.key').is_file():
            raise AssertionError('Fixture did not leave a real disposable host key')
    # Invoke the exact user entry point after releasing our setup-only lock.
    # An inherited override must not divert recovery's cleanup boot away from
    # the bundled, verified hypervisor. Setup above uses the normal environment.
    recovery = subprocess.run([str(bundle/'Agent-Chain.exe'), '--recover', run], capture_output=True, timeout=180, cwd=bundle,
        env={**os.environ, 'AGENTICVM_QEMU': str(Path(os.environ['SystemRoot'])/'System32/whoami.exe')})
    if recovery.returncode:
        raise RuntimeError('Native recovery failed: '+recovery.stdout.decode(errors='replace')[-2000:]+recovery.stderr.decode(errors='replace')[-1000:])
    result = read_json(folder/'recovery.json')
    if not result['passed'] or result['tasks_replayed'] or StateStore(workspace).load()['registered']:
        raise AssertionError('Native recovery did not stop the owned VM without replay')
    if (workspace.parent/'private').exists():
        raise AssertionError('Disposable host keys remain')
    try:
        read_image_file(workspace/'data/default.ext2', 'peer/key.pem')
    except FileNotFoundError:
        pass
    else:
        raise AssertionError('Disposable guest key remains')
    report = {'passed': True, 'run_id': run, 'injected_exit_code': 23, 'actual_vm_was_left_running': True,
              'native_executable_recovery': True, 'host_keys_removed': True, 'guest_key_absent_in_stopped_disk': True,
              'tasks_replayed': False, 'fixture_model_not_started': True, 'recovery': result}
    report['inherited_hypervisor_override_ignored'] = True
    output = ROOT/'docs/validation/agent-chain-recovery-report.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'passed': True, 'run_id': run, 'report': str(output)}))


if __name__ == '__main__':
    main()
