"""Independently verify the completed native reproduction lineage and cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.chain import identifier
from agenticvm.ext2 import read_image_file
from agenticvm.peers import verify_journal
from agenticvm.replication_policy import Ledger
from agenticvm.state import StateStore
from agenticvm.torrent import digest, read_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    run = identifier(args.run)
    bundle = ROOT/'dist/Agent-Replicator-v1'
    folder = bundle/'runtime/replication-runs'/run
    result = read_json(folder/'report.json')
    if not result['passed'] or result['cleanup_failures']:
        raise ValueError('Only a successfully cleaned reproduction run may be summarized')
    checked = verify_journal(folder/'checkpoints.jsonl')
    if result['checkpoints'] != checked:
        raise ValueError('Final journal receipt changed')
    ledger = Ledger(folder/'ledger.sqlite')
    snapshot = ledger.snapshot()
    ledger.close()
    if snapshot != result['lineage']:
        raise ValueError('Durable lineage changed after completion')
    expected = [('replica-0', None, 0), ('replica-1', 'replica-0', 1), ('replica-2', 'replica-1', 2)]
    if [(n['id'], n['parent'], n['generation']) for n in snapshot['nodes']] != expected:
        raise ValueError('Expected one seed and two recursively requested descendants')
    accepted = {row['actor']: row['result'].get('child') for row in snapshot['requests'] if row['result']['state'] == 'queued'}
    if accepted != {'replica-0': 'replica-1', 'replica-1': 'replica-2'}:
        raise ValueError('Descendants lack their parent\'s durable reproduction request')
    events = [json.loads(line) for line in (folder/'checkpoints.jsonl').read_text().splitlines()]
    reservations = {e['result']['child']: e['index'] for e in events if e['event'] == 'reproduction_requested' and e['result']['state'] == 'queued'}
    launches = {e['replica']: e['index'] for e in events if e['event'] == 'replica_launched'}
    if any(reservations[child] >= launches[child] for child in reservations):
        raise ValueError('A VM started before its parent request was durably reserved')
    proofs = {}
    identities = read_json(folder/'identities.json')['identities']
    for name, parent, generation in expected:
        workspace = folder/name
        state = StateStore(workspace).load()
        if state['registered']:
            raise ValueError('A completed replica is still registered')
        disk = workspace/'data/default.ext2'
        source = hashlib.sha256(read_image_file(disk, 'peer/replica_agent.py')).hexdigest()
        if source != snapshot['policy']['agent_sha']:
            raise ValueError('A descendant does not contain the identical reproduction program')
        config = json.loads(read_image_file(disk, 'peer/replica.json'))
        if (config['identity'], config['parent'], config['generation']) != (name, parent, generation):
            raise ValueError('Child workspace inherited incorrect instance configuration')
        for forbidden in ('peer/key.pem', 'peer/broker.key', 'peer/replica-0.key', 'peer/replica-1.key', 'peer/replica-2.key'):
            try:
                read_image_file(disk, forbidden)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('A guest contains a disposable or another instance\'s private key')
        summary = result['agents'][name]
        if not summary['duplicate_request_verified'] or not summary['communication']['both_directions_reconciled']:
            raise ValueError('Request idempotency or encrypted communication proof is missing')
        proofs[name] = {'stopped': True, 'identical_reproduction_source_sha256': source,
                       'certificate_sha256': identities[name]['sha256'], 'generation': generation, 'parent': parent,
                       'private_key_entries_absent': True, 'model_calls': summary['model_calls'],
                       'model_peak_rss_mib': round(summary['model_peak_rss_kib']/1024, 2),
                       'model_greeting': summary['model_greeting'], 'tls': summary['communication']['tls']}
    if len({p['certificate_sha256'] for p in proofs.values()}) != 3 or (folder/'private').exists():
        raise ValueError('Identity separation or host key cleanup failed')
    messages = snapshot['messages']
    if len(messages) != 6 or not all(row['acknowledged'] for row in messages):
        raise ValueError('The six parent/child mailbox messages were not all acknowledged')
    recovery_path = ROOT/'docs/validation/replication-recovery-report.json'
    recovery = read_json(recovery_path)
    if not recovery['passed']:
        raise ValueError('The native crash-recovery verification has not passed')
    tests = read_json(ROOT/'docs/validation/replication-host-tests.json')
    if not tests['passed']:
        raise ValueError('The host regression suite has not passed')
    report = {'schema': 'agenticvm.self-replication-validation.v1', 'passed': True, 'run_id': run,
        'native_executable': str(bundle/'Agent-Replicator.exe'), 'native_executable_sha256': digest(bundle/'Agent-Replicator.exe'),
        'raw_report': str(folder/'report.json'), 'raw_report_sha256': digest(folder/'report.json'),
        'torrent': result['torrent'], 'agent_initiated_lineage': expected, 'replica_proofs': proofs,
        'seed_instances_started_by_launcher': 1, 'descendants_requested_by_agents': 2,
        'all_copies_inherit_reproduction_capability': True, 'reservations_precede_vm_launch': True,
        'duplicate_requests_create_no_additional_vms': True, 'max_active_vms': result['peak_active_vms'],
        'third_agent_queued_at_capacity': result['third_agent_queued_at_capacity'],
        'further_reproduction_denied': result['terminal_replication_denied'],
        'acknowledged_lineage_messages': len(messages), 'reproduction_rule': 'fixed agent policy; request one identical child',
        'model_role': result['model_role'], 'host_broker_can_read_messages': True,
        'transport': 'mutual TLS 1.3 on separate guest-broker virtio-serial links',
        'elapsed_agent_experiment_seconds': result['elapsed_seconds'], 'checkpoints': checked,
        'recovery_verification': recovery, 'recovery_verification_sha256': digest(recovery_path),
        'host_tests': tests,
        'physical_4gb_host_tested': False, 'cross_computer_replication': False, 'public_swarm_joined': False,
        'key_removal': 'Filesystem unlink of exact disposable key entries; not cryptographic block erasure'}
    output = ROOT/'docs/validation/self-replication-report.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'passed': True, 'report': str(output), 'identical_code_instances': 3, 'peak_active_vms': 2}))


if __name__ == '__main__':
    main()
