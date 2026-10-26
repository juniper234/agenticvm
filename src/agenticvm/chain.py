"""Local torrent-to-VM agent chain with bounded capabilities and checkpoints."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from uuid import UUID, uuid4

from .ext2 import read_image_file
from .peers import Journal, verify_journal
from .state import StateStore
from .torrent import digest, download_local, install_bundle, load_catalog, plain, read_json

ROOT = Path(__file__).resolve().parents[2]
EARLY = {'created', 'runtime_verified', 'downloading', 'download_verified', 'agent_installed'}


def identifier(value):
    if str(UUID(value)) != value:
        raise ValueError('Use a canonical run UUID')
    return value


def emit(event, **fields):
    print(json.dumps({'event': event, **fields}, ensure_ascii=True), flush=True)


class Checkpoints(Journal):
    def __init__(self, directory, run_id, *, resume=False):
        if not resume:
            super().__init__(directory, run_id)
            return
        verified = verify_journal(directory/'checkpoints.jsonl')
        records = [json.loads(row) for row in (directory/'checkpoints.jsonl').read_text().splitlines()]
        if not records or any(row['run_id'] != run_id for row in records):
            raise ValueError('Checkpoint run identity mismatch')
        self.directory, self.run_id = directory, run_id
        self.previous, self.count = verified['sha256'], verified['records']
        self.file = (directory/'checkpoints.jsonl').open('a', encoding='ascii')


@contextmanager
def exclusive(directory):
    import msvcrt
    path = plain(directory/'launcher.lock')
    with path.open('a+b') as stream:
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise RuntimeError('Another agent chain is running in this folder') from error
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def verify_runtime(root, lock):
    for entry in lock['runtime_files']:
        from .torrent import member_name
        path = plain(root/member_name(entry['path']))
        if path.stat().st_size != entry['bytes'] or digest(path) != entry['sha256']:
            raise ValueError('Launcher dependency changed: '+entry['path'])
    return len(lock['runtime_files'])


def resources(root):
    class Memory(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
                    *[(name, ctypes.c_ulonglong) for name in ('total', 'available', 'page_total', 'page_available', 'virtual_total', 'virtual_available', 'extended')]]
    memory = Memory()
    memory.length = ctypes.sizeof(Memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise OSError('Cannot check available host memory')
    if memory.available < 1408*1024**2:
        raise RuntimeError('Two 512 MiB agent VMs need at least 1408 MiB of available host RAM; close other applications and retry')
    if shutil.disk_usage(root).free < 3*1024**3:
        raise RuntimeError('Keep at least 3 GiB of disk space free for downloads, two VM disks and evidence')
    return {'total_host_mib': memory.total//1024**2, 'available_host_mib': memory.available//1024**2,
            'memory_mib_per_vm': 512, 'physical_4gb_host_tested': False}


def child(root, arguments, *, timeout=1800, cancel=None):
    """No shell. A cancellation requests guest cleanup before forced recovery."""
    process = subprocess.Popen([sys.executable, '-I', '-B', *map(str, arguments)], cwd=root,
                               env={**os.environ, 'AGENTICVM_QEMU': str(root/'tools/qemu/11.1.0/qemu-system-x86_64.exe')},
                               creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
    start = time.monotonic()
    try:
        while time.monotonic()-start < timeout:
            try:
                return process.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                pass
        raise TimeoutError('Agent chain process exceeded its total deadline')
    except (KeyboardInterrupt, TimeoutError):
        if cancel:
            if cancel.parent.exists():
                plain(cancel).write_text('cancel requested\n')
            else:
                process.terminate()
            emit('cancelling', detail='Waiting for owned VM/key cleanup')
            try:
                process.wait(timeout=240)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=15)
        else:
            process.terminate()
            process.wait(timeout=15)
        raise


def recover(root, run_id):
    run_id = identifier(run_id)
    folder = plain(root/'runtime/chain-runs'/run_id)
    verify_journal(folder/'checkpoints.jsonl')
    vm_folder = plain(root/'runtime/pong-agent-runs'/run_id)
    emit('recovery_started', run_id=run_id, tasks_replayed=False)
    if vm_folder.exists():
        code = child(root, [root/'scripts/run-pong-agents.py', '--recover', run_id], timeout=600)
        if code:
            raise RuntimeError('VM recovery failed; inspect preserved recovery evidence')
        result = read_json(vm_folder/'pong-recovery.json')
        if not result['passed'] or result.get('tasks_replayed') is not False:
            raise ValueError('Recovery evidence did not verify')
    else:
        result = {'passed': True, 'tasks_replayed': False, 'no_vms_created': True}
    report = {'run_id': run_id, 'passed': True, 'tasks_replayed': False, 'vm_recovery': result,
              'checkpoint_verification': verify_journal(folder/'checkpoints.jsonl')}
    (folder/'recovery.json').write_text(json.dumps(report, indent=2)+'\n')
    emit('recovery_completed', run_id=run_id, tasks_replayed=False)
    return report


def reconcile(folder):
    transcripts = []
    for name in ('guest-a-serial', 'guest-b-serial'):
        path = folder/'evidence'/name/'evidence.jsonl'
        if path.stat().st_size > 4*1024**2:
            raise ValueError('Agent transcript exceeds its bound')
        transcripts.append([json.loads(row) for row in path.read_text().splitlines()])
    result = {}
    for direction, left, right in (('orchestrator_to_worker', transcripts[0], transcripts[1]),
                                    ('worker_to_orchestrator', transcripts[1], transcripts[0])):
        sent = {r['message_id']: r['body_sha256'] for r in left if r['event'] == 'sent'}
        received = {r['message_id']: r['body_sha256'] for r in right if r['event'] == 'received'}
        if not sent or sent != received:
            raise ValueError('Agent transcript reconciliation failed: '+direction)
        result[direction] = {'messages': len(sent), 'matched_ids_and_body_sha256': True}
    return result


def validate_finished(root, run_id, installed):
    folder = plain(root/'runtime/pong-agent-runs'/run_id)
    report = read_json(folder/'report.json')
    if not report['passed'] or report['cleanup_failures'] or report['orchestrator']['hashes'] != report['worker']['hashes']:
        raise ValueError('VM chain did not finish and clean up successfully')
    proofs = {}
    for name in ('guest-a-serial', 'guest-b-serial'):
        workspace = folder/name
        state = StateStore(workspace).load()
        if state['registered']:
            raise ValueError('Agent VM remains registered after completion')
        disk = workspace/'data/default.ext2'
        sources = {}
        for filename in ('pong_agent.py', 'pong_synthesis.py', 'peer_agent.py', 'peer_protocol.py'):
            import hashlib
            actual = hashlib.sha256(read_image_file(disk, 'peer/'+filename)).hexdigest()
            if actual != digest(installed/'guest'/filename):
                raise ValueError('Executed guest agent differs from torrent package')
            sources[filename] = actual
        try:
            read_image_file(disk, 'peer/key.pem')
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Disposable guest private key remains allocated')
        proofs[name] = {'stopped': True, 'agent_source_sha256': sources, 'guest_private_key_absent': True}
    return {'vm_report': str(folder/'report.json'), 'vm_report_sha256': digest(folder/'report.json'),
            'communication': reconcile(folder), 'guest_proofs': proofs,
            'checks': report['orchestrator']['checks'], 'rounds': report['orchestrator']['rounds'],
            'formula_origins': report['formula_origins'], 'elapsed_agent_seconds': report['elapsed_agent_seconds'],
            'tls': report['orchestrator']['tls']}


def execute(root, lock, args):
    run_id = identifier(args.resume) if args.resume else str(uuid4())
    folder = plain(root/'runtime/chain-runs'/run_id)
    if args.resume:
        previous_report = read_json(folder/'report.json') if (folder/'report.json').exists() else None
        if (folder/'recovery.json').exists() or (previous_report and
                (previous_report.get('passed') or previous_report.get('failure', {}).get('phase') not in EARLY)):
            raise ValueError('A terminal run cannot be resumed; start a fresh chain')
        verify_journal(folder/'checkpoints.jsonl')
        records = [json.loads(row) for row in (folder/'checkpoints.jsonl').read_text().splitlines()]
        args.download_only = records[0].get('download_only', False)
        phase = records[-1]['phase']
        if phase == 'failed':
            phase = records[-1].get('failure', {}).get('phase', phase)
        if phase not in EARLY:
            return recover(root, run_id)
        if previous_report:
            (folder/'report.json').rename(folder/('attempt-'+uuid4().hex+'-report.json'))
    else:
        folder.mkdir(parents=True, exist_ok=False)
    journal = Checkpoints(folder, run_id, resume=bool(args.resume))
    report = {'schema': 'agenticvm.torrent-chain-run.v1', 'run_id': run_id, 'passed': False,
              'agent': 'LFM2.5-350M-Q4_K_M', 'chain': 'orchestrator -> worker -> independent review -> repair/accept',
              'agent_chain_executed': False, 'physical_4gb_host_tested': False, 'public_swarm_joined': False}
    phase = 'created'
    def checkpoint(value, **fields):
        nonlocal phase
        phase = value
        if 'sha256' in fields:
            fields['payload_sha256'] = fields.pop('sha256')
        journal.add('phase', phase=value, **fields)
        emit(value, run_id=run_id, **fields)
    try:
        checkpoint('created', resumed=bool(args.resume), download_only=bool(args.download_only))
        report['runtime_files_verified'] = verify_runtime(root, lock)
        catalog = load_catalog(root/'chain/agent-catalog.json', lock['catalog_sha256'])
        report['catalog_sha256'] = lock['catalog_sha256']
        checkpoint('runtime_verified', files=report['runtime_files_verified'])
        if not args.download_only:
            report['resources'] = resources(root)
        checkpoint('downloading')
        archive, transfer = download_local(root, root/'chain/lfm-agent.torrent', catalog,
                    root/'seed', folder/'download', event=lambda e, **kw: emit(e, **kw))
        report['torrent'] = transfer
        checkpoint('download_verified', **transfer)
        installed = install_bundle(archive, catalog, root/'runtime/agent-cache')
        report['installed_agent'] = str(installed)
        checkpoint('agent_installed', package_sha256=catalog['payload']['sha256'])
        if not args.download_only:
            checkpoint('vms_starting', roles=['orchestrator', 'worker'], memory_mib_each=512, guest_nics=False)
            vm_folder = root/'runtime/pong-agent-runs'/run_id
            code = child(root, [root/'scripts/run-pong-agents.py', '--run-id', run_id, '--agent-directory', installed],
                         cancel=vm_folder/'cancel.request')
            if code:
                raise RuntimeError('The VM agent loop failed; evidence and cleanup results were retained')
            report['execution'] = validate_finished(root, run_id, installed)
            report['agent_chain_executed'] = True
            checkpoint('agents_finished', communication=report['execution']['communication'])
            if child(root, [root/'scripts/package-pong-game.py', '--run', run_id], timeout=60):
                raise RuntimeError('Accepted game packaging failed')
            report['game'] = str(root/'dist'/('Pong-'+run_id[:8])/'index.html')
            checkpoint('artifacts_exported', game=report['game'])
        report['passed'] = True
        checkpoint('completed', agent_chain_executed=report['agent_chain_executed'])
    except (Exception, KeyboardInterrupt) as error:
        report['failure'] = {'class': type(error).__name__, 'message': str(error)[:1500], 'phase': phase}
        if phase not in EARLY:
            try:
                report['recovery'] = recover(root, run_id)
            except Exception as cleanup:
                report['recovery_failure'] = {'class': type(cleanup).__name__, 'message': str(cleanup)[:1500]}
        checkpoint('failed', failure=report['failure'])
        # Early interrupted transfers retain their verified checkpoint chain and
        # partial payload, with no terminal report, for --resume.
        if isinstance(error, KeyboardInterrupt) and report['failure']['phase'] in EARLY:
            journal.close()
            emit('download_interrupted', resume_command='Agent-Chain.exe --resume '+run_id)
            return report
    finally:
        if not journal.file.closed:
            journal.close()
    try:
        report['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
    except (ValueError, KeyError) as error:
        report['passed'] = False
        report['failure'] = {'class': type(error).__name__, 'message': str(error)[:1500], 'phase': 'final_checkpoint_verification'}
        report['checkpoints'] = {'verified': False}
    (folder/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    emit('result', passed=report['passed'], report=str(folder/'report.json'), game=report.get('game'))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Download the pinned LFM VM agent with local BitTorrent, then run an encrypted two-agent chain.')
    options = parser.add_mutually_exclusive_group()
    options.add_argument('--download-only', action='store_true')
    options.add_argument('--describe', action='store_true')
    options.add_argument('--resume', metavar='RUN_UUID', help='Resume an interrupted download; VM-phase interruptions are cleaned up without replay')
    options.add_argument('--recover', metavar='RUN_UUID', help='Stop owned interrupted VMs and remove disposable key files')
    args = parser.parse_args(argv)
    root = plain(ROOT)
    try:
        if os.name != 'nt':
            raise RuntimeError('This launcher currently supports Windows x64 hosts')
        lock = read_json(root/'chain/launcher-lock.json', maximum=256*1024)
        if lock['schema'] != 'agenticvm.chain-launcher.v1':
            raise ValueError('Unknown launcher lock')
        if args.describe:
            print(json.dumps(read_json(root/'chain/pong-chain.json'), indent=2))
            return 0
        runs = plain(root/'runtime/chain-runs')
        runs.mkdir(parents=True, exist_ok=True)
        with exclusive(runs):
            if args.recover:
                verify_runtime(root, lock)
                return 0 if recover(root, args.recover)['passed'] else 1
            # Prior VM interruptions must be cleaned before new VMs are started.
            for previous in sorted(runs.iterdir()):
                if not previous.is_dir() or previous.name == args.resume or not (previous/'checkpoints.jsonl').exists():
                    continue
                prior_report = read_json(previous/'report.json') if (previous/'report.json').exists() else None
                if not (previous/'recovery.json').exists() and (not prior_report or prior_report.get('recovery_failure')):
                    verify_runtime(root, lock)
                    recover(root, previous.name)
            result = execute(root, lock, args)
        return 0 if result['passed'] else 1
    except (Exception, KeyboardInterrupt) as error:
        emit('launcher_failed', error_class=type(error).__name__, message=str(error)[:1500])
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
