"""Crash after an agent-requested child starts; recover via the native EXE."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.ext2 import read_image_file
from agenticvm.peers import verify_journal
from agenticvm.qemu import QemuBackend
from agenticvm.replication_policy import Ledger
from agenticvm.state import StateStore
from agenticvm.torrent import read_json


def main():
    bundle = ROOT/'dist/Agent-Replicator-v1'
    executable = bundle/'Agent-Replicator.exe'
    runs = bundle/'runtime/replication-runs'
    before = {path.name for path in runs.iterdir() if path.is_dir()}
    fault = subprocess.run([str(executable), '--test-crash-after-child'], cwd=bundle,
                           capture_output=True, timeout=300)
    created = [path for path in runs.iterdir() if path.is_dir() and path.name not in before]
    if fault.returncode != 23 or len(created) != 1:
        raise RuntimeError('Controller did not reach its fault checkpoint: '+fault.stdout.decode(errors='replace')[-2000:]+fault.stderr.decode(errors='replace')[-1000:])
    folder = created[0]
    verified = verify_journal(folder/'checkpoints.jsonl')
    events = [json.loads(row) for row in (folder/'checkpoints.jsonl').read_text().splitlines()]
    if events[-1]['event'] != 'fault_injected' or events[-1]['actual_owned_vms'] != 2:
        raise AssertionError('Fault must leave the actual parent and agent-requested child running')
    for name in ('replica-0', 'replica-1'):
        workspace = folder/name
        state = StateStore(workspace).load()
        if not state['registered']:
            raise AssertionError('Fault fixture did not leave an owned VM registered')
        with QemuBackend(StateStore(workspace), Path(state['executable']))._process(state) as owned:
            if not owned.alive():
                raise AssertionError('Fault fixture VM is not actually alive')
    ledger = Ledger(folder/'ledger.sqlite')
    previous = ledger.snapshot()
    ledger.close()
    if len(previous['nodes']) != 2 or len(previous['requests']) != 1:
        raise AssertionError('Fixture must preserve exactly one durable child reservation')
    if not (folder/'private/broker.key').is_file():
        raise AssertionError('No real disposable host key was left for recovery')
    recovery = subprocess.run([str(executable), '--recover', folder.name], cwd=bundle, capture_output=True, timeout=240,
        env={**os.environ, 'AGENTICVM_QEMU': str(Path(os.environ['SystemRoot'])/'System32/whoami.exe')})
    if recovery.returncode:
        raise RuntimeError('Native recovery failed: '+recovery.stdout.decode(errors='replace')[-2500:]+recovery.stderr.decode(errors='replace')[-1000:])
    result = read_json(folder/'recovery.json')
    if not result['passed'] or result['tasks_replayed'] or not result['private_host_files_removed']:
        raise AssertionError('Recovery did not remove identities without replay')
    key_removals = {row['replica']: row for row in result['resources']}
    for name in ('replica-0', 'replica-1'):
        workspace = folder/name
        if StateStore(workspace).load()['registered'] or not key_removals[name]['guest_key_was_present']:
            raise AssertionError('Actual replica resource/key cleanup was not proved')
        try:
            read_image_file(workspace/'data/default.ext2', 'peer/key.pem')
        except FileNotFoundError:
            pass
        else:
            raise AssertionError('Disposable guest key remains allocated')
    ledger = Ledger(folder/'ledger.sqlite')
    after = ledger.snapshot()
    ledger.close()
    if len(after['nodes']) != 2 or len(after['requests']) != 1 or any(n['state'] != 'aborted' for n in after['nodes']):
        raise AssertionError('Recovery replayed or restarted an uncertain birth')
    report = {'passed': True, 'run_id': folder.name, 'injected_controller_exit_code': 23,
        'actual_parent_and_child_were_running': True, 'authenticated_agent_requests_before_crash': 1,
        'durable_child_reservations_before_and_after': 1, 'nodes_before_and_after': 2,
        'all_reservations_aborted': True, 'native_executable_recovery': True,
        'inherited_hypervisor_override_ignored': True, 'both_guest_key_entries_removed': True,
        'private_host_keys_removed': True, 'births_replayed': False, 'checkpoint_before_recovery': verified,
        'recovery': result}
    output = ROOT/'docs/validation/replication-recovery-report.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'passed': True, 'report': str(output), 'run_id': folder.name}))


if __name__ == '__main__':
    main()
