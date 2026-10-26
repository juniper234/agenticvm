"""Two offline Linux guests, never running together, exchange sealed envelopes.

One physical host is a trusted hypervisor and an explicit ciphertext courier.
This is simulation evidence, not a claim of physical air-gap validation.
"""
from pathlib import Path
import hashlib
import json
import os
import stat
import sys
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.ext2 import Node, build_ext2, read_image_file
from agenticvm.peers import Runner, VM, verify_journal
from agenticvm.state import StateStore
from agenticvm import blind_transfer as carrier


def main():
    run_id = str(uuid4())
    folder = ROOT/'runtime/disconnected-transfer'/run_id
    folder.mkdir(parents=True)
    runner = Runner(folder, run_id, 256, 1)
    runner.journal.add('run_started', purpose='disconnected host simulation with encrypted courier',
                       physical_hosts=1, max_live_test_vms=1, no_guest_network=True)
    a, b = VM(runner, 'offline-a'), VM(runner, 'offline-b')
    started = time.monotonic()
    service = thread = None
    report = {'passed': False, 'run_id': run_id, 'scope': 'single-physical-host simulation',
              'physical_hosts_tested': 1, 'separate_physical_hosts_tested': False,
              'physical_4gb_host_tested': False, 'simultaneous_test_vms': 0,
              'source_sha256': {str(path.relative_to(ROOT)).replace('\\','/'): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in (ROOT/'src/agenticvm/offline_transfer.py', ROOT/'src/agenticvm/blind_transfer.py',
                               ROOT/'guest/offline_demo_agent.py', ROOT/'tools/transfer-runtime-lock.json')}, 'checks': {}}
    checks = report['checks']

    def stopped(vm):
        state = StateStore(vm.workspace).load(required=False)
        return not state or not state['registered']

    def start(vm, other):
        if not stopped(other):
            raise AssertionError('The other simulated computer must be powered off')
        vm.start('--persistent')
        state = StateStore(vm.workspace).load()
        if state.get('network') != 'none' or state.get('peer_socket') or state.get('serial_link') or state.get('isolated_link'):
            raise AssertionError('An inter-guest link was configured')
        topology = json.loads(vm.run('/usr/bin/python3', '-I', '-c',
            "import json,pathlib;print(json.dumps({'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'routes':pathlib.Path('/proc/net/route').read_text(),'dns':pathlib.Path('/etc/resolv.conf').read_text(),'peer_device':pathlib.Path('/dev/virtio-ports/org.agenticvm.peer').exists(),'mounts':pathlib.Path('/proc/mounts').read_text()}))"))
        if topology['interfaces'] != ['lo'] or topology['peer_device'] or topology['dns'].strip() or len(topology['routes'].splitlines()) != 1:
            raise AssertionError('The guest has an unexpected communication path')
        if any(kind in topology['mounts'] for kind in (' virtiofs ', ' 9p ', ' cifs ', ' nfs ')):
            raise AssertionError('The guest has a shared network/host filesystem')
        report['simultaneous_test_vms'] = max(report['simultaneous_test_vms'], 1)
        runner.journal.add('offline_vm_verified', vm=vm.name, other_vm_stopped=True, only_loopback=True,
                           peer_device=False, shared_host_mounts=False)

    def call(vm, *args, expect=True):
        output = json.loads(vm.run('/usr/bin/python3', '-I', '/workspace/transfer.py', '--home', '/workspace/mailbox', *args))
        if output.get('ok') != expect:
            raise AssertionError('Unexpected transfer result: '+str(output))
        return output.get('result', output)

    def move(vm, message_id, label, *, fetch=True):
        # The endpoint exports ciphertext itself. The courier never reads its key.
        call(vm, 'export', message_id, '--output', '/workspace/'+label+'.sealed')
        vm.download(label+'.sealed', folder/(label+'.sealed'))
        vm.stop()
        if not stopped(a) or not stopped(b):
            raise AssertionError('Relay operation must occur with both VMs off')
        content = (folder/(label+'.sealed')).read_bytes()
        ticket = carrier.push(origin, content)['sha256']
        if fetch:
            fetched = carrier.pull(origin, ticket)
            if fetched != content:
                raise AssertionError('Relay changed the ciphertext')
            (folder/(label+'-received.sealed')).write_bytes(fetched)
        runner.journal.add('ciphertext_carried', label=label, envelope_sha256=ticket,
                           bytes=len(content), both_test_vms_stopped=True, carrier='loopback HTTP blind relay')
        return folder/(label+'-received.sealed')

    try:
        libraries = ROOT/'tools/transfer-runtime/linux'
        if not libraries.is_dir():
            raise ValueError('Run scripts/prepare-transfer-runtime.py first')
        for vm in (a, b):
            nodes = {'': Node(stat.S_IFDIR|0o700, uid=1000, gid=1000),
                     'transfer.py': Node(stat.S_IFREG|0o600, ROOT/'src/agenticvm/offline_transfer.py', 1000, 1000),
                     'demo_agent.py': Node(stat.S_IFREG|0o600, ROOT/'guest/offline_demo_agent.py', 1000, 1000)}
            for path in libraries.rglob('*'):
                if path.is_file() and '__pycache__' not in path.parts:
                    name = 'transfer-libs/'+path.relative_to(libraries).as_posix()
                    nodes[name] = Node(stat.S_IFREG|0o600, path, 1000, 1000)
            # All implied library directories must be traversable by the agent UID.
            for name in list(nodes):
                for parent in Path(name).parents:
                    if str(parent) != '.':
                        nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR|0o700, uid=1000, gid=1000))
            disk = vm.workspace/'data/default.ext2'
            disk.parent.mkdir(parents=True)
            build_ext2(disk, nodes, label='AGENTICVM_DATA')
        contacts = {}
        for vm, other, name in ((a,b,'orchestrator'),(b,a,'worker')):
            start(vm, other)
            contacts[vm.name] = call(vm, 'init', '--name', name)
            vm.download('mailbox/contact.json', folder/(vm.name+'-contact.json'))
            vm.stop()
        checks['independent_endpoint_keys'] = contacts[a.name]['fingerprint'] != contacts[b.name]['fingerprint']
        service = carrier.server(carrier.Store(folder/'blind-relay'))
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        origin = 'http://127.0.0.1:'+str(service.server_port)

        start(a, b)
        a.upload(folder/'offline-b-contact.json', 'other-contact.json')
        call(a, 'trust', '/workspace/other-contact.json', '--fingerprint', contacts[b.name]['fingerprint'])
        task = json.loads(a.run('/usr/bin/python3', '-I', '/workspace/demo_agent.py', 'orchestrator-send', '--peer', contacts[b.name]['fingerprint']))
        a.stop()  # Prove the durable outbox survives power cycling before export.
        start(b, a)
        b.upload(folder/'offline-a-contact.json', 'other-contact.json')
        call(b, 'trust', '/workspace/other-contact.json', '--fingerprint', contacts[a.name]['fingerprint'])
        checks['no_delivery_without_carrier'] = call(b, 'status')['mail'] == []
        b.stop()
        runner.journal.add('carrier_absent', recipient_mail_count=0, sender_stopped=True)

        start(a, b)
        task_file = move(a, task['id'], 'task')
        checks['sender_restart_preserved_outbox'] = hashlib.sha256(task_file.read_bytes()).hexdigest() == task['sha256']
        start(b, a)
        b.upload(task_file, 'incoming-task.sealed')
        received = call(b, 'receive', '/workspace/incoming-task.sealed')
        checks['task_payload_matches_sender'] = received['payload_sha256'] == task['payload_sha256']
        b.stop()
        start(b, a)
        duplicate = call(b, 'receive', '/workspace/incoming-task.sealed')
        checks['duplicate_after_recipient_reboot_reuses_receipt'] = duplicate['duplicate'] and duplicate['receipt'] == received['receipt']
        reply = json.loads(b.run('/usr/bin/python3', '-I', '/workspace/demo_agent.py', 'worker-reply',
                                  '--peer', contacts[a.name]['fingerprint'], '--message-id', task['id']))
        receipt_file = move(b, received['receipt'], 'task-receipt')
        start(b, a)
        reply_file = move(b, reply['id'], 'reply', fetch=False)

        # A relay outage must not make endpoints discard or regenerate ciphertext.
        service.shutdown()
        service.server_close()
        thread.join(3)
        service = thread = None
        outage = False
        try:
            carrier.pull(origin, reply['sha256'])
        except Exception:
            outage = True
        checks['relay_outage_blocks_delivery'] = outage and not reply_file.exists()
        service = carrier.server(carrier.Store(folder/'blind-relay'))
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        origin = 'http://127.0.0.1:'+str(service.server_port)
        fetched = carrier.pull(origin, reply['sha256'])
        checks['relay_restart_preserves_exact_ciphertext'] = fetched == (folder/'reply.sealed').read_bytes()
        reply_file.write_bytes(fetched)

        start(a, b)
        a.upload(receipt_file, 'incoming-task-receipt.sealed')
        call(a, 'receive', '/workspace/incoming-task-receipt.sealed')
        a.upload(reply_file, 'incoming-reply.sealed')
        reply_received = call(a, 'receive', '/workspace/incoming-reply.sealed')
        verified = json.loads(a.run('/usr/bin/python3', '-I', '/workspace/demo_agent.py', 'orchestrator-check',
                                     '--peer', contacts[b.name]['fingerprint'], '--message-id', reply['id']))
        checks['challenge_and_unicode_preserved'] = verified['challenge_matched'] and verified['unicode_preserved']
        ack_file = move(a, reply_received['receipt'], 'reply-receipt')
        start(b, a)
        b.upload(ack_file, 'incoming-reply-receipt.sealed')
        call(b, 'receive', '/workspace/incoming-reply-receipt.sealed')
        report['worker_mail'] = call(b, 'status')
        worker_private_digest = b.run('/usr/bin/python3', '-I', '-c', "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/workspace/mailbox/identity.private.json').read_bytes()).hexdigest())").strip()
        b.stop()
        start(a, b)
        report['orchestrator_mail'] = call(a, 'status')
        orchestrator_private_digest = a.run('/usr/bin/python3', '-I', '-c', "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/workspace/mailbox/identity.private.json').read_bytes()).hexdigest())").strip()
        a.stop()
        checks['both_application_messages_acknowledged'] = all(
            row['acked'] for name in ('worker_mail','orchestrator_mail') for row in report[name]['mail']
            if row['direction'] == 'out' and row['kind'] != 'receipt')
        checks['stopped_disk_public_contact_matches_own_guest_identity'] = all(
            read_image_file(vm.workspace/'data/default.ext2', 'mailbox/contact.json') ==
            (folder/(vm.name+'-contact.json')).read_bytes() for vm in (a,b))
        checks['stopped_guest_program_matches_verified_source'] = all(
            hashlib.sha256(read_image_file(vm.workspace/'data/default.ext2', 'transfer.py')).hexdigest() ==
            report['source_sha256']['src/agenticvm/offline_transfer.py'] for vm in (a,b))
        # Each VM computes its own private-file digest; key bytes never leave it.
        checks['distinct_private_identity_digests'] = worker_private_digest != orchestrator_private_digest
        sealed = list(folder.glob('*.sealed'))
        checks['carrier_contains_no_application_text'] = all(b'offline agent hello' not in path.read_bytes() and b'"challenge"' not in path.read_bytes() for path in sealed)
        checks['private_keys_never_exported_by_courier'] = not list(folder.glob('*.private.json'))
        report['retained_for_resume'] = 'Each owned stopped VM disk retains only its own persistent private identity and mailbox. No secure erasure claim.'
        report['limitations'] = ['Both guests share one physical trusted hypervisor and immutable base image.',
            'A host admin/control serial channel remains for setup and explicit export/import.',
            'The host can inspect VM memory/disks; this is not protection from a malicious hypervisor.',
            'Remote HTTPS gateway deployment and different physical hosts have not been tested.',
            'Delivery tickets were routed by the test controller; no remote mailbox discovery is implemented.',
            'Deterministic agent ping/pong; no new language-model inference or game generation was tested.']
        report['passed'] = all(checks.values())
    except Exception as error:
        report['error'] = {'class': type(error).__name__, 'message': str(error)[:1500]}
    finally:
        if service:
            service.shutdown()
            service.server_close()
            thread.join(3)
        report['cleanup_failures'] = runner.cleanup()
        if report['cleanup_failures']:
            report['passed'] = False
        runner.journal.close()
        report['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
        report['seconds'] = round(time.monotonic()-started, 3)
        (folder/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        if report['passed']:
            public = {**report, 'evidence_directory': str(folder.relative_to(ROOT))}
            (ROOT/'docs/validation/disconnected-transfer-report.json').write_text(json.dumps(public, indent=2)+'\n')
    print(json.dumps({'passed': report['passed'], 'report': str(folder/'report.json'), 'error': report.get('error'), 'seconds': report['seconds']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
