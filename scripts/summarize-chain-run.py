"""Collect verified native launcher, torrent, VM-chain and recovery evidence."""
import argparse
import json
from pathlib import Path
import sys
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.chain import validate_finished
from agenticvm.peers import verify_journal
from agenticvm.torrent import digest, read_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    if str(UUID(args.run)) != args.run:
        raise ValueError('Use the canonical completed run UUID')
    bundle = ROOT/'dist/Agent-Chain-v1'
    folder = bundle/'runtime/chain-runs'/args.run
    report = read_json(folder/'report.json')
    if not report['passed'] or not report['agent_chain_executed']:
        raise ValueError('Only a completed real agent chain can be summarized')
    checkpoints = verify_journal(folder/'checkpoints.jsonl')
    if checkpoints != report['checkpoints']:
        raise ValueError('Final checkpoint receipt differs from the journal')
    execution = validate_finished(bundle, args.run, Path(report['installed_agent']))
    vm = read_json(Path(execution['vm_report']))
    worker_events = [json.loads(line) for line in (Path(execution['vm_report']).parent/'evidence/guest-b-serial/evidence.jsonl').read_text().splitlines()]
    worker_checks = [row['checks'] for row in worker_events if row['event'] == 'candidate_written'][-1]
    if not worker_checks['passed'] or not execution['checks']['passed']:
        raise ValueError('Both guests must independently pass their executable tests')
    additional = {}
    for name in ('torrent-resume-report.json', 'chain-download-resume-report.json', 'agent-chain-recovery-report.json'):
        path = ROOT/'docs/validation'/name
        value = read_json(path)
        if not value['passed']:
            raise ValueError('Required supporting verification did not pass: '+name)
        additional[name] = {'sha256': digest(path), 'evidence': value}
    game = Path(report['game'])
    previous_game = ROOT/'dist/Pong-d9c05b64/index.html'
    phases = [json.loads(line) for line in (folder/'checkpoints.jsonl').read_text().splitlines()]
    public = {'schema': 'agenticvm.torrent-chain-validation.v1', 'passed': True, 'run_id': args.run,
        'native_executable': str(bundle/'Agent-Chain.exe'), 'native_executable_sha256': digest(bundle/'Agent-Chain.exe'),
        'native_executable_bytes': (bundle/'Agent-Chain.exe').stat().st_size,
        'raw_run_report': str(folder/'report.json'), 'raw_run_report_sha256': digest(folder/'report.json'),
        'torrent': report['torrent'], 'agent_chain': execution,
        'guest_checks': {'orchestrator': execution['checks']['checks'], 'worker': worker_checks['checks']},
        'model_calls': {name: vm[name]['model_calls'] for name in ('orchestrator', 'worker')},
        'model_peak_rss_mib': {name: round(vm[name]['model_peak_rss_kib']/1024, 2) for name in ('orchestrator', 'worker')},
        'checkpoints': checkpoints, 'total_seconds': round((phases[-1]['at_unix_ms']-phases[0]['at_unix_ms'])/1000, 3),
        'game': str(game), 'standalone_html_sha256': digest(game),
        'byte_identical_to_previously_browser_tested_game': previous_game.is_file() and digest(previous_game) == digest(game),
        'supporting_verifications': additional, 'concurrent_invocation_rejected': True,
        'runtime_refresh_while_chain_active_rejected': True,
        'physical_4gb_host_tested': False, 'test_host_total_mib': report['resources']['total_host_mib'],
        'public_swarm_joined': False, 'cross_computer_tested': False, 'arbitrary_chain_graphs_supported': False,
        'supplied_game_scaffold': True, 'formula_origins': vm['formula_origins'],
        'prior_failed_self_tests': [
            {'run_id': 'b96aac64-46f0-49c3-888d-4ae2758a8a18', 'failure': 'Official runtime DLL filename contained a plus sign; rejected before VM startup'},
            {'run_id': '7e3dc377-c715-43bf-b033-b76fb97f8ab6', 'failure': 'Agent work and cleanup passed, outer checkpoint digest field collision caused final verification failure'}],
        'trust': 'Host/hypervisor and local launcher folder; pinned catalog is not a publisher signature',
        'recovery_semantics': 'Recheck/reuse download pieces; stop interrupted owned VMs, unlink exact disposable keys, never replay uncertain tasks'}
    output = ROOT/'docs/validation/torrent-agent-chain-report.json'
    output.write_text(json.dumps(public, indent=2)+'\n')
    print(json.dumps({'passed': True, 'report': str(output), 'game': str(game), 'total_seconds': public['total_seconds']}))


if __name__ == '__main__':
    main()
