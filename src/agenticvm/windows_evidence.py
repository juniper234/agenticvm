"""Correlate real mixed Linux/Windows inference without fabricating OS fields."""
import hashlib
import json
from pathlib import Path

from .enrollment_catalog import validate_receipt
from .lan_lab import ROOT, MODEL_SHA, digest
from .peers import verify_journal
from .qemu import WindowsProcess
from .windows_recovery import PARENT


def verify_initial(statuses, target_uuid):
    if set(statuses) != {'mother', 'offshoot-1', 'offshoot-2', 'sprout-4'}:
        raise ValueError('Expected the fixed four-member Windows enrollment lab')
    calls, messages, pairs = {}, {}, []
    for actor, status in statuses.items():
        model = status['model']
        if (not status['ready'] or status['error'] or not model['server_alive'] or not model['weights_verified_inside_vm']
                or model['weights_sha256'] != MODEL_SHA or model['cpu_threads'] != 1 or model['gpu']):
            raise ValueError('Actual pinned guest inference evidence is missing')
        if actor == 'sprout-4':
            native = status['native_windows']
            if (native['uuid'] != target_uuid or native['sid'] != 'S-1-5-19' or native['default_route']
                    or 'Windows Server 2025' not in native['os'] or model['execution_location'] != 'Windows guest'
                    or not model['executable'].lower().endswith('\\garden\\llama\\llama-server.exe')):
                raise ValueError('Windows native OS/account/isolation/model process evidence mismatch')
        else:
            if model['execution_location'] != 'Linux guest':
                raise ValueError('A Linux seed model was relocated outside its VM')
            if any(row.split()[1] == '00000000' for row in status['routes'].splitlines()[1:] if row.strip()):
                raise ValueError('A Linux seed has a default route')
        for row in status['calls']:
            proof, ident = row['proof'], row['id']
            if (row['state'] != 'ready' or ident in calls or proof['call_id'] != ident or proof['completion_tokens'] < 1
                    or json.loads(proof['raw_content']) != {'text': proof['text']}
                    or proof['text_sha256'] != hashlib.sha256(proof['text'].encode()).hexdigest()
                    or proof['prompt_sha256'] != hashlib.sha256(proof['prompt'].encode()).hexdigest()):
                raise ValueError('Missing, duplicated or altered actual model completion')
            calls[ident] = proof
        for pair in status['delivered']:
            hello, reply = pair['hello'], pair['reply']
            peer = hello['to']
            if (hello['from'] != actor or reply['from'] != peer or reply['to'] != actor
                    or reply['reply_to'] != hello['id'] or hello not in statuses[peer]['received']):
                raise ValueError('Actual model exchange delivery/correlation mismatch')
            for body in (hello, reply):
                if body['id'] in messages:
                    raise ValueError('A delivered message was counted twice')
                messages[body['id']] = body
            pairs.append((actor, peer))
    if (set(pairs) != {('mother', 'offshoot-1'), ('mother', 'offshoot-2'), ('mother', 'sprout-4'),
            ('sprout-4', 'offshoot-1'), ('sprout-4', 'offshoot-2')} or len(pairs) != 5
            or len(calls) != 10 or set(calls) != set(messages)):
        raise ValueError('Five actual exchanges and ten correlated completions are required')
    for ident, body in messages.items():
        proof = calls[ident]
        if body['text'] != proof['text'] or body['model']['completion_tokens'] != proof['completion_tokens'] or body['model']['weights_sha256'] != MODEL_SHA:
            raise ValueError('Delivered content differs from native inference evidence')
        if body['kind'] == 'reply':
            source = messages[body['reply_to']]
            if proof['source_message_id'] != source['id'] or json.dumps(source['text']) not in proof['prompt']:
                raise ValueError('Windows-lab model reply did not consume its received input')
    return {'initial_actual_model_completions': 10, 'initial_correlated_exchanges': 5}


def verify_guest(guest, target_uuid):
    initial, final = guest['initial_statuses'], guest['final_statuses']
    result = verify_initial(initial, target_uuid)
    before, after = initial['sprout-4'], final['sprout-4']
    installed = guest['installed']
    if (before['native_boot_id'] == after['native_boot_id'] or before['public_identity'] != after['public_identity']
            or after['native_windows']['uuid'] != target_uuid or after['native_windows']['sid'] != 'S-1-5-19'
            or after['native_windows']['default_route'] or any(installed['initial_absence'].values())
            or not installed['duplicate']['duplicate'] or installed['installed']['process'] != installed['duplicate']['process']
            or installed['installed']['process']['pid'] != before['pid']):
        raise ValueError('Windows native installation, duplicate handling or cold-boot continuity mismatch')
    model = after['model']
    if (not after['ready'] or after['error'] or not model['server_alive'] or not model['weights_verified_inside_vm']
            or model['weights_sha256'] != MODEL_SHA or model['execution_location'] != 'Windows guest'
            or not model['executable'].lower().endswith('\\garden\\llama\\llama-server.exe')):
        raise ValueError('Windows model provenance did not survive the actual cold boot')
    additions = {}
    for actor in initial:
        old = {row['id']: row for row in initial[actor]['calls']}
        new = {row['id']: row for row in final[actor]['calls']}
        if any(new.get(ident) != row for ident, row in old.items()):
            raise ValueError('Windows cold boot altered or replayed a prior model call')
        for ident in new.keys() - old.keys():
            if ident in additions:
                raise ValueError('Post-reboot model call was counted twice')
            additions[ident] = (actor, new[ident])
    challenge = guest['post_reboot_challenge']
    hello, reply = challenge['hello'], challenge['reply']
    if (set(additions) != {hello['id'], reply['id']} or challenge['tls']['version'] != 'TLSv1.3'
            or reply['reply_to'] != hello['id'] or hello not in after['received']):
        raise ValueError('Windows cold boot lacks a fresh authenticated correlated challenge')
    for body, actor in ((hello, 'mother'), (reply, 'sprout-4')):
        observed_actor, row = additions[body['id']]
        proof = row['proof']
        if (observed_actor != actor or row['state'] != 'ready' or proof['call_id'] != body['id']
                or proof['text'] != body['text'] or proof['completion_tokens'] < 1
                or json.loads(proof['raw_content']) != {'text': body['text']}
                or proof['text_sha256'] != hashlib.sha256(body['text'].encode()).hexdigest()
                or proof['prompt_sha256'] != hashlib.sha256(proof['prompt'].encode()).hexdigest()):
            raise ValueError('Fresh Windows model challenge proof is incomplete')
    proof = additions[reply['id']][1]['proof']
    if proof['source_message_id'] != hello['id'] or json.dumps(hello['text']) not in proof['prompt']:
        raise ValueError('Fresh Windows reply did not consume the actual challenge')
    return result | {'native_cold_boots': 2, 'post_reboot_actual_model_completions': 2}


def verify_denial(case, proof, target_uuid):
    native = proof['native_windows']
    if (native['uuid'] != target_uuid or native['sid'] != 'S-1-5-18' or native['default_route']
            or 'Windows Server 2025' not in native['os'] or native['task_state'] != 'absent'
            or set(proof['activation_paths']) != {'peer/windows_agent.py', 'model.gguf', 'identity.key', 'lan-config.json'}
            or any(proof['activation_paths'].values())):
        raise ValueError('Windows refusal did not prove real OS scope and complete activation absence')
    expected = {'bad-hash': 'Application asset SHA256 mismatch', 'wrong-grant': 'HTTP Error 403',
                'bad-bootstrap': 'Windows reviewed bootstrap installer SHA256 mismatch'}
    if case not in expected or expected[case] not in proof['error']:
        raise ValueError('Windows refusal did not observe the intended deliberate fault')


def verify(folder):
    folder = Path(folder).resolve()
    if folder.parent != PARENT:
        raise ValueError('Windows evidence must belong to its owned run directory')
    receipt = validate_receipt(json.loads((folder / 'report.json').read_text()))
    if (not receipt['passed'] or receipt['cleanup_failures'] or receipt['source_changed_during_run']
            or not receipt['all_owned_vms_stopped_and_disks_removed']):
        raise ValueError('Windows case did not pass cleanly at a fixed source revision')
    for name, pin in receipt['source_sha256'].items():
        if digest(ROOT / name) != pin:
            raise ValueError('Accepted Windows source changed: ' + name)
    if (folder / 'private').exists() or (folder / 'target/system.qcow2').exists() or list(folder.glob('*/workspace.ext2')):
        raise ValueError('Windows disposable fixture disks or credentials remain')
    if verify_journal(folder / 'checkpoints.jsonl') != receipt['checkpoints']:
        raise ValueError('Windows checkpoint journal changed')
    for state_path in list(folder.glob('*/ownership.json')) + list(folder.glob('target/ownership-*.json')):
        state = json.loads(state_path.read_text())
        with WindowsProcess(state['pid']) as process:
            if process.alive() and process.created == state['created']:
                raise ValueError('An exact Windows-lab VM is still running')
    if receipt['case'] not in ('happy', 'resume'):
        path = folder / 'denial-proof.json'
        if digest(path) != receipt['denial_proof_sha256']:
            raise ValueError('Windows refusal evidence changed')
        verify_denial(receipt['case'], json.loads(path.read_text()), receipt['target_uuid'])
    else:
        path = folder / 'guest-report.json'
        if digest(path) != receipt['guest_report_sha256']:
            raise ValueError('Windows inference evidence changed')
        verify_guest(json.loads(path.read_text()), receipt['target_uuid'])
        launch = json.loads((folder / 'target/launch-2.json').read_text())
        if launch['installer_media_attached'] or any('media=cdrom' in argument for argument in launch['argv']):
            raise ValueError('Windows cold boot still requires provisioning media')
    return receipt
