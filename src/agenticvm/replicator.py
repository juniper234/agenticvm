"""Finite local agent reproduction: authenticated requests create descendants."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import threading
import time
from uuid import uuid4

from .chain import Checkpoints, emit, exclusive, identifier, resources, verify_runtime
from .ext2 import read_image_file
from .peer_protocol import BIOStream, PeerSession, PeerTLSConfig
from .peers import Runner, VM, RecordedRaw, verify_journal
from .qemu import QemuBackend
from .replication_policy import ACTIVE, Ledger
from .state import StateStore
from .torrent import digest, download_local, install_bundle, load_catalog, plain, read_json
from .transport import SocketTransport

ROOT = Path(__file__).resolve().parents[2]
PURPOSE = 'bounded local agent self-replication'
NAMES = tuple('replica-'+str(i) for i in range(7))


def plan():
    return {'name': 'Local self-replication', 'schema': 'agenticvm.replication-plan.v1',
        'initial_seed_agents': 1, 'max_total_agents': 3, 'max_active_vms': 2, 'max_generation': 2,
        'children_per_agent': 1, 'memory_mib_per_vm': 512,
        'reproduction_policy': 'Each copy autonomously requests one identical child; broker enforces the finite budget.',
        'model': 'LFM2.5-350M-Q4_K_M', 'model_role': 'One local-model greeting per replica; reproduction follows fixed agent code.',
        'example': 'replica-0 -> replica-1 -> replica-2; replica-2 request denied at generation limit',
        'queue': 'A descendant waits until a completed ancestor releases one of the two VM slots.',
        'communication': 'Mutual TLS 1.3 over individual virtio-serial links to a trusted lineage mailbox broker.',
        'broker_can_read_messages': True, 'guest_network_adapters': False,
        'identities': 'Distinct fresh certificates per replica; issuer removed before agents start; no parent private keys copied.',
        'distribution': 'Pinned local BitTorrent package; no public discovery or Internet swarm.',
        'checkpoints': 'Synced hash-linked journal plus SQLite FULL/WAL reservations and idempotency receipts.',
        'recovery': 'Stop only owned VMs, remove disposable keys and abort pending reservations; never replay uncertain births.',
        'cross_computer_replication': False, 'physical_4gb_host_tested': False}


class BrokerClient(threading.Thread):
    """One bounded TLS session per live VM. Ledger mutations stay on main thread."""
    def __init__(self, runner, vm, inbox):
        super().__init__(name='broker-'+vm.name, daemon=True)
        self.runner, self.vm, self.inbox = runner, vm, inbox
        self.events, self.info = [], None
        self.transport = self.stream = None
        self.failure = None

    def run(self):
        try:
            state = StateStore(self.vm.workspace).load()
            backend = QemuBackend(StateStore(self.vm.workspace), Path(state['executable']))
            with backend._process(state) as owned:
                if not owned.alive():
                    raise RuntimeError('Replica process exited before its authenticated channel opened')
                self.transport = SocketTransport(state['peer_socket'], 8)
            raw = RecordedRaw(self.transport, self.runner.directory/(self.vm.name+'.tls'))
            config = PeerTLSConfig(str(self.runner.pki/'broker.pem'), str(self.runner.pki/'broker.key'),
                str(self.runner.pki/'ca.pem'), self.runner.identities[self.vm.name]['sha256'], self.vm.name)
            self.stream = BIOStream(raw, config, server_side=False, timeout=45)
            self.info = self.stream.info
            session = PeerSession(self.stream, self.runner.run_id, 'broker', self.vm.name, self.events.append)
            for _ in range(200):
                envelope = session.receive(timeout=240)
                if envelope['kind'] != 'request':
                    raise ValueError('Replica must send a typed request')
                response = queue.Queue(maxsize=1)
                self.inbox.put((self.vm.name, envelope['body'], response), timeout=10)
                result = response.get(timeout=180)
                session.send('response', result, reply_to=envelope['id'], timeout=20)
                if envelope['body'].get('op') == 'finish' and result.get('ok'):
                    break
            else:
                raise ValueError('Broker session request budget exceeded')
        except Exception as error:
            self.failure = {'class': type(error).__name__, 'message': str(error)[:1000]}
            self.inbox.put((self.vm.name, None, None))
        finally:
            if self.stream:
                self.stream.close()
            elif self.transport:
                self.transport.close()

    def abort(self):
        if self.transport:
            try:
                self.transport.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class ReplicationRun:
    def __init__(self, directory, run_id, package, package_sha, *, fault_after_child=False):
        self.folder, self.run_id, self.package = directory, run_id, package
        self.runner = Runner(directory, run_id, 512, 1)
        self.runner.journal.add('run_started', purpose=PURPOSE, package_sha256=package_sha,
                                max_active=2, max_total=3, max_generation=2)
        self.ledger = Ledger(directory/'ledger.sqlite', run_id=run_id, package_sha=package_sha,
                             agent_sha=digest(package/'guest/replica_agent.py'), on_event=self.runner.journal.add)
        self.inbox = queue.Queue(maxsize=64)
        self.active, self.clients, self.summaries = {}, {}, {}
        self.peak_active = 0
        self.fault_after_child = fault_after_child
        spec = importlib.util.spec_from_file_location('replication_disk_builder', ROOT/'scripts/run-pong-agents.py')
        self.disk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.disk)
        self.disk.MODEL, self.disk.GUEST = package, package/'guest'

    def provision(self):
        provisioner = VM(self.runner, 'provisioner')
        provisioner.start()
        provisioner.run('/bin/mkdir', '-p', '/workspace/peer')
        provisioner.upload(ROOT/'guest/peer_pki.py', 'peer/peer_pki.py')
        names = ('broker', *NAMES[:self.ledger.policy['max_total']])
        public = json.loads(provisioner.run('/usr/bin/python3', '-I', '/workspace/peer/peer_pki.py', '--output',
            '/workspace/peer/pki', '--run-id', self.run_id, '--identities', *names))
        if not public['ca_private_key_removed'] or public['ca_private_key_exported']:
            raise ValueError('Disposable authority cleanup was not confirmed')
        self.runner.identities = public['identities']
        for name in ('ca.pem', *[identity+suffix for identity in names for suffix in ('.pem', '.key')]):
            provisioner.download('peer/pki/'+name, self.runner.pki/name)
        (self.folder/'identities.json').write_text(json.dumps(public, indent=2)+'\n')
        provisioner.stop()
        self.runner.journal.add('identities_preallocated', identities=public, provisioner_stopped=True)

    def launch(self, node):
        actor = node['id']
        self.ledger.set_state(actor, 'starting')
        vm = VM(self.runner, actor)
        self.disk.prepare_disk(vm, extra_guest=('replica_agent.py',))
        config = {'run_id': self.run_id, 'identity': actor, 'parent': node['parent'], 'generation': node['generation'],
                  'package_sha256': self.ledger.policy['package_sha'], 'agent_sha256': self.ledger.policy['agent_sha'],
                  'broker_pin': self.runner.identities['broker']['sha256']}
        vm.start('--persistent', '--peer-channel', '--image', self.package/'boot/agenticvm-linux-peer.iso')
        vm.install(actor, 'broker')
        config_path = self.folder/(actor+'-config.json')
        config_path.write_text(json.dumps(config)+'\n')
        vm.upload(config_path, 'peer/replica.json')
        job = vm.cli('exec', '--async', '--timeout-ms', '0', '--', '/usr/bin/python3', '-I', '/workspace/peer/replica_agent.py')['job_id']
        vm.jobs.append(job)
        self.ledger.set_state(actor, 'running')
        self.active[actor] = (vm, job)
        self.peak_active = max(self.peak_active, len(self.active))
        self.runner.journal.add('replica_launched', replica=actor, parent=node['parent'], generation=node['generation'],
                                job_id=job, active_vms=len(self.active), source='seed_launcher' if node['parent'] is None else 'authenticated_agent_request')
        client = BrokerClient(self.runner, vm, self.inbox)
        self.clients[actor] = client
        client.start()
        emit('replica_started', identity=actor, parent=node['parent'], generation=node['generation'], active_vms=len(self.active))
        if self.fault_after_child and node['parent'] is not None:
            self.runner.journal.add('fault_injected', exit_code=23, actual_owned_vms=len(self.active), child_started=True)
            os._exit(23)

    def complete(self, actor, snapshot):
        vm, job = self.active[actor]
        if snapshot['exit_code'] != 0 or self.ledger.node(actor)['state'] != 'finishing':
            raise RuntimeError('Replica exited without a valid completion receipt: '+actor)
        client = self.clients[actor]
        client.join(timeout=5)
        if client.is_alive() or client.failure:
            raise RuntimeError('Replica broker session did not close cleanly: '+actor)
        destination = self.folder/'evidence'/actor
        destination.mkdir(parents=True)
        for name in ('summary.json', 'evidence.jsonl', 'model.log'):
            vm.download('peer/'+name, destination/name)
        summary = read_json(destination/'summary.json')
        if not summary['passed'] or summary['model_calls'] != 1 or summary['interfaces'] != ['lo']:
            raise ValueError('Replica did not complete local inference and its inherited reproduction policy')
        guest_events = [json.loads(line) for line in (destination/'evidence.jsonl').read_text().splitlines()]
        host_sent = {e['message_id']: e['body_sha256'] for e in client.events if e['event'] == 'sent'}
        guest_received = {e['message_id']: e['body_sha256'] for e in guest_events if e['event'] == 'received'}
        guest_sent = {e['message_id']: e['body_sha256'] for e in guest_events if e['event'] == 'sent'}
        host_received = {e['message_id']: e['body_sha256'] for e in client.events if e['event'] == 'received'}
        if not host_sent or host_sent != guest_received or guest_sent != host_received:
            raise ValueError('Replica TLS message transcript did not reconcile')
        (destination/'host-events.jsonl').write_text(''.join(json.dumps(e, sort_keys=True)+'\n' for e in client.events))
        self.disk.erase_generated_guest_key(vm)
        vm.cli('forget', job)
        vm.jobs.remove(job)
        vm.stop()
        actual = hashlib.sha256(read_image_file(vm.workspace/'data/default.ext2', 'peer/replica_agent.py')).hexdigest()
        if actual != self.ledger.policy['agent_sha']:
            raise ValueError('Stopped replica disk source does not match the reproduced agent')
        try:
            read_image_file(vm.workspace/'data/default.ext2', 'peer/key.pem')
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Disposable replica private key remains allocated')
        trace = self.folder/(actor+'.tls')
        wire = trace.read_bytes()
        if len(wire) > 4*1024**2 or b'"op":' in wire or b'"reproduction_capable":' in wire:
            raise ValueError('Invalid TLS wire observation')
        summary.update(communication={'guest_to_broker_messages': len(guest_sent), 'broker_to_guest_messages': len(host_sent),
            'both_directions_reconciled': True, 'tls': client.info, 'wire_sha256': digest(trace),
            'application_json_visible': False}, stopped_source_sha256=actual, guest_private_key_absent=True)
        self.summaries[actor] = summary
        self.ledger.set_state(actor, 'completed')
        del self.active[actor]
        emit('replica_completed', identity=actor, active_vms=len(self.active))

    def run(self):
        self.provision()
        deadline = time.monotonic()+900
        last_poll = last_progress = 0
        while time.monotonic() < deadline:
            try:
                actor, body, response = self.inbox.get(timeout=.15)
            except queue.Empty:
                pass
            else:
                if body is None:
                    raise RuntimeError('Authenticated broker channel failed: '+actor+': '+str(self.clients[actor].failure))
                try:
                    result = self.ledger.handle(actor, body)
                except Exception as error:
                    response.put({'ok': False, 'error': type(error).__name__+': '+str(error)[:300]})
                    raise
                response.put(result)
                if body['op'] == 'replicate':
                    emit('agent_requested_replica', identity=actor, result=result)
            if (self.folder/'cancel.request').exists():
                raise KeyboardInterrupt('Local cancellation requested')
            if time.monotonic()-last_poll > 1:
                last_poll = time.monotonic()
                for actor, (vm, job) in list(self.active.items()):
                    state = vm.cli('poll', job)
                    if state['state'] == 'exited':
                        self.complete(actor, state)
            queued = [node for node in self.ledger.nodes() if node['state'] == 'queued']
            if queued and len(self.active) < 2:
                self.launch(queued[0])
            if not self.active and not queued:
                break
            if time.monotonic()-last_progress > 20:
                last_progress = time.monotonic()
                emit('replication_progress', active=list(self.active),
                     queued=[n['id'] for n in self.ledger.nodes() if n['state'] == 'queued'], peak_active=self.peak_active)
        else:
            raise TimeoutError('Finite replication experiment exceeded 900 seconds')
        snapshot = self.ledger.snapshot()
        if len(snapshot['nodes']) != 3 or any(node['state'] != 'completed' for node in snapshot['nodes']):
            raise ValueError('The bounded A -> B -> C reproduction did not complete')
        if self.peak_active != 2 or not all(message['acknowledged'] for message in snapshot['messages']) or len(snapshot['messages']) != 6:
            raise ValueError('Slot limit or parent/child communication evidence failed')
        if len({value['stopped_source_sha256'] for value in self.summaries.values()}) != 1:
            raise ValueError('Descendants did not inherit identical reproduction software')
        fingerprints = [self.runner.identities[node['id']]['sha256'] for node in snapshot['nodes']]
        if len(set(fingerprints)) != 3:
            raise ValueError('Replicas did not receive separate identities')
        events = [json.loads(line) for line in (self.folder/'checkpoints.jsonl').read_text().splitlines()]
        queued_at_capacity = any(e['event'] == 'reproduction_requested' and e['result'].get('child') == 'replica-2' and e['active_at_request'] == 2 for e in events)
        if not queued_at_capacity:
            raise ValueError('The third agent was not observed queuing at capacity')
        return {'passed': True, 'lineage': snapshot, 'agents': self.summaries, 'peak_active_vms': self.peak_active,
                'third_agent_queued_at_capacity': True, 'fresh_replica_identities': fingerprints,
                'agent_initiated_descendants': 2, 'seed_instances_started_by_launcher': 1,
                'terminal_replication_denied': self.summaries['replica-2']['reproduction']['state'] == 'denied',
                'host_broker_can_read_messages': True, 'direct_guest_to_guest_transport_used': False,
                'replication_decision_origin': 'fixed_agent_policy', 'model_role': 'one local-model greeting per replica'}

    def cleanup(self):
        failures = []
        for client in self.clients.values():
            if client.is_alive():
                client.abort()
                client.join(timeout=3)
        for vm in self.runner.machines:
            if not (vm.workspace/'data/default.ext2').exists():
                continue
            try:
                state = StateStore(vm.workspace).load(required=False)
                if state and state['registered']:
                    for job in vm.jobs:
                        try:
                            vm.cli('cancel', job)
                        except Exception:
                            pass
                    self.disk.erase_generated_guest_key(vm)
            except Exception as error:
                failures.append({'replica': vm.name, 'guest_key_cleanup': type(error).__name__})
        failures.extend(self.runner.cleanup())
        self.ledger.close()
        return failures


def recover(run_id):
    run_id = identifier(run_id)
    folder = plain(ROOT/'runtime/replication-runs'/run_id)
    verified = verify_journal(folder/'checkpoints.jsonl')
    first = json.loads((folder/'checkpoints.jsonl').read_text().splitlines()[0])
    if first.get('purpose') != PURPOSE or first['run_id'] != run_id:
        raise ValueError('Selected run is not an owned replication experiment')
    journal = Checkpoints(folder, run_id, resume=True)
    journal.add('recovery_started', previous_verification=verified, tasks_replayed=False)
    helper = type('RecoveryRunner', (), {'directory': folder, 'run_id': run_id, 'memory': 256,
                                        'machines': [], 'journal': journal, 'control_calls': 0})()
    removed, failures = [], []
    for name in ('provisioner', *NAMES):
        vm = VM(helper, name)
        try:
            plain(vm.workspace)
            state = StateStore(vm.workspace).load(required=False)
            if not state:
                continue
            vm.stop()
            disk = vm.workspace/'data/default.ext2'
            present = False
            if disk.is_file():
                try:
                    read_image_file(disk, 'peer/key.pem')
                    present = True
                except FileNotFoundError:
                    pass
            if present:
                try:
                    vm.start('--persistent', '--image', ROOT/'runtime/linux-peer/agenticvm-linux-peer.iso')
                    code = "from pathlib import Path; p=Path('/workspace/peer/key.pem'); assert not p.is_symlink() and p.parent.resolve()==Path('/workspace/peer'); p.unlink(missing_ok=True); print('removed')"
                    if vm.run('/usr/bin/python3', '-I', '-c', code).strip() != 'removed':
                        raise ValueError('Guest key removal failed')
                    vm.run('/bin/sync')
                finally:
                    vm.stop()
                try:
                    read_image_file(disk, 'peer/key.pem')
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('Stopped disk still contains a private key entry')
            removed.append({'replica': name, 'stopped': True, 'guest_key_was_present': present, 'guest_key_absent': True})
        except Exception as error:
            failures.append({'replica': name, 'class': type(error).__name__, 'message': str(error)[:500]})
    private = plain(folder/'private')
    if private.exists():
        for name in ('ca.pem', *[identity+suffix for identity in ('broker', *NAMES) for suffix in ('.pem', '.key')]):
            path = plain(private/name)
            if path.is_file():
                path.unlink()
        try:
            private.rmdir()
        except OSError:
            failures.append({'private': 'Unknown files retained'})
    if (folder/'ledger.sqlite').exists():
        ledger = Ledger(folder/'ledger.sqlite', on_event=journal.add)
        for node in ledger.nodes():
            if node['state'] not in ('completed', 'aborted'):
                ledger.set_state(node['id'], 'aborted')
        ledger.close()
    report = {'passed': not failures, 'run_id': run_id, 'resources': removed, 'failures': failures,
              'private_host_files_removed': not private.exists(), 'tasks_replayed': False}
    journal.add('recovery_completed', result=report)
    journal.close()
    report['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
    (folder/'recovery.json').write_text(json.dumps(report, indent=2)+'\n')
    emit('recovery_completed', **report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group()
    options.add_argument('--describe', action='store_true')
    options.add_argument('--download-only', action='store_true')
    options.add_argument('--recover', metavar='RUN_UUID')
    options.add_argument('--test-crash-after-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        lock = read_json(ROOT/'chain/launcher-lock.json', maximum=256*1024)
        if lock.get('kind') != 'replication':
            raise ValueError('Use an Agent-Replicator release, not the Pong-chain launcher')
        if args.describe:
            print(json.dumps(plan(), indent=2))
            return 0
        if os.name != 'nt':
            raise ValueError('This local release requires a Windows host')
        verify_runtime(ROOT, lock)
        runs = plain(ROOT/'runtime/replication-runs')
        runs.mkdir(parents=True, exist_ok=True)
        with exclusive(runs):
            os.environ['AGENTICVM_QEMU'] = str(ROOT/'tools/qemu/11.1.0/qemu-system-x86_64.exe')
            if args.recover:
                return 0 if recover(args.recover)['passed'] else 1
            for prior in sorted(runs.iterdir()):
                if not prior.is_dir() or not (prior/'checkpoints.jsonl').exists():
                    continue
                report = read_json(prior/'report.json') if (prior/'report.json').exists() else None
                recovery = read_json(prior/'recovery.json') if (prior/'recovery.json').exists() else None
                if (not report or report.get('cleanup_failures')) and not (recovery and recovery['passed']):
                    if not recover(prior.name)['passed']:
                        raise RuntimeError('An interrupted reproduction run still needs cleanup')
            catalog = load_catalog(ROOT/'chain/agent-catalog.json', lock['catalog_sha256'])
            run_id = str(uuid4())
            folder = runs/run_id
            folder.mkdir()
            emit('replication_run_started', run_id=run_id, directory=str(folder))
            # Distribution has its own receipt before any VM/identity exists.
            archive, torrent = download_local(ROOT, ROOT/'chain/lfm-agent.torrent', catalog, ROOT/'seed', folder/'download',
                                               event=lambda event, **fields: emit(event, **fields))
            package = install_bundle(archive, catalog, ROOT/'runtime/agent-cache')
            (folder/'download-receipt.json').write_text(json.dumps({'torrent': torrent,
                'catalog_sha256': lock['catalog_sha256'], 'installed_package': str(package)}, indent=2)+'\n')
            if args.download_only:
                result = {'passed': True, 'agent_chain_executed': False, 'torrent': torrent, 'run_id': run_id}
                (folder/'report.json').write_text(json.dumps(result, indent=2)+'\n')
                emit('download_completed', report=str(folder/'report.json'))
                return 0
            resources(ROOT)
            for filename, host in (('peer_agent.py', ROOT/'guest/peer_agent.py'),
                                   ('peer_protocol.py', ROOT/'src/agenticvm/peer_protocol.py')):
                if digest(package/'guest'/filename) != digest(host):
                    raise ValueError('Replication package and host transport versions differ')
            if read_json(package/'agent.json').get('name') != 'lfm-replica-agent':
                raise ValueError('Downloaded package does not include the reproduction capability')
            instance = ReplicationRun(folder, run_id, package, catalog['payload']['sha256'], fault_after_child=args.test_crash_after_child)
            result = {'passed': False, 'run_id': run_id, 'torrent': torrent, 'physical_4gb_host_tested': False,
                      'memory_mib_per_vm': 512, 'local_computer_only': True}
            start = time.monotonic()
            try:
                result.update(instance.run())
            except (Exception, KeyboardInterrupt) as error:
                result['failure'] = {'class': type(error).__name__, 'message': str(error)[:1500]}
                instance.runner.journal.add('run_failed', failure=result['failure'])
                instance.runner.diagnose()
            finally:
                result['cleanup_failures'] = instance.cleanup()
                result['passed'] = result['passed'] and not result['cleanup_failures']
                result['elapsed_seconds'] = round(time.monotonic()-start, 3)
                instance.runner.journal.add('run_completed', passed=result['passed'])
                instance.runner.journal.close()
                result['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
                (folder/'report.json').write_text(json.dumps(result, indent=2)+'\n')
            emit('replication_result', passed=result['passed'], report=str(folder/'report.json'), failure=result.get('failure'))
            return 0 if result['passed'] else 1
    except (Exception, KeyboardInterrupt) as error:
        emit('replication_launcher_failed', error_class=type(error).__name__, message=str(error)[:1500])
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
