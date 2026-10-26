"""Resume a prepared partial release through the real executable, download-only."""
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.chain import Checkpoints, exclusive
from agenticvm.torrent import read_json


def main():
    bundle = ROOT/'dist/Agent-Chain-v1'
    catalog = read_json(bundle/'chain/agent-catalog.json')
    run = str(uuid4())
    folder = bundle/'runtime/chain-runs'/run
    with exclusive(bundle/'runtime/chain-runs'):
        (folder/'download').mkdir(parents=True)
        journal = Checkpoints(folder, run)
        journal.add('phase', phase='created', download_only=True, prepared_restart_fixture=True)
        journal.add('phase', phase='downloading')
        failure = {'class': 'TimeoutError', 'message': 'Prepared failed-download fixture', 'phase': 'downloading'}
        journal.add('phase', phase='failed', failure=failure)
        journal.close()
        (folder/'report.json').write_text(json.dumps({'passed': False, 'failure': failure})+'\n')
        source = bundle/'seed'/catalog['payload']['name']
        partial = folder/'download'/source.name
        with source.open('rb') as incoming, partial.open('xb') as outgoing:
            outgoing.write(incoming.read(262144))
            outgoing.truncate(catalog['payload']['bytes'])
    child = subprocess.run([str(bundle/'Agent-Chain.exe'), '--resume', run], cwd=bundle,
                           capture_output=True, timeout=180)
    if child.returncode:
        raise RuntimeError(child.stdout.decode(errors='replace')[-2500:]+child.stderr.decode(errors='replace')[-1000:])
    report = read_json(folder/'report.json')
    transfer = report['torrent']
    assert report['passed'] and not report['agent_chain_executed']
    assert transfer['resumed_existing_file'] and 0 < transfer['payload_downloaded_bytes'] < catalog['payload']['bytes']
    assert transfer['sha256_verified'] and list(folder.glob('attempt-*-report.json'))
    evidence = {'passed': True, 'run_id': run, 'native_executable': True,
                'fixture': 'prepared failed-download checkpoint and one valid piece; not a process-kill test',
                'download_only_mode_preserved': True, 'earlier_failure_report_preserved': True,
                'download': transfer, 'checkpoints': report['checkpoints']}
    output = ROOT/'docs/validation/chain-download-resume-report.json'
    output.write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps({'passed': True, 'report': str(output), 'run_id': run}))


if __name__ == '__main__':
    main()
