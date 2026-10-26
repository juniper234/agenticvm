"""Read-back audit of native provisioning, model provenance and owned cleanup."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

from .enrollment_catalog import validate_receipt
from .lan_lab import ROOT, digest
from .native_enrollment import verify_initial, verify_denial, os_id
from .peers import verify_journal
from .qemu import WindowsProcess


def verify(folder, *, current=True):
    folder = Path(folder).resolve()
    if not folder.is_relative_to(ROOT / 'runtime/native-enrollment-runs'):
        raise ValueError('Native evidence must belong to an owned run')
    receipt = validate_receipt(json.loads((folder / 'report.json').read_text()))
    case = receipt.get('case', 'happy')  # early successful bootstrap revision
    if not receipt['passed'] or receipt.get('source_changed_during_run'):
        raise ValueError('Native receipt did not pass at a fixed source revision')
    if receipt['cleanup_failures'] or (folder / 'private').exists():
        raise ValueError('Native private identity cleanup is incomplete')
    for name in ('mother', 'offshoot-1', 'offshoot-2', 'dhcp'):
        if (folder / name / 'workspace.ext2').exists():
            raise ValueError('Native disposable seed disk remains')
    if (folder / 'target/system.qcow2').exists():
        raise ValueError('Native disposable target disk remains')
    for state_path in list(folder.glob('*/ownership.json')) + list(folder.glob('target/ownership-*.json')):
        state = json.loads(state_path.read_text())
        with WindowsProcess(state['pid']) as process:
            if process.alive() and process.created == state['created']:
                raise ValueError('Native owned VM is still running')
    if verify_journal(folder / 'checkpoints.jsonl') != receipt['checkpoints']:
        raise ValueError('Native checkpoint journal changed')
    if current:
        for name, pin in receipt['source_sha256'].items():
            if digest(ROOT / name) != pin:
                raise ValueError('Native accepted source changed: ' + name)
    kind = receipt.get('native_kind', 'ubuntu' if receipt['route'].startswith('cloud-init') else 'coreos')
    if case not in ('happy', 'resume'):
        proof_path = folder / 'denial-proof.json'
        if digest(proof_path) != receipt['denial_proof_sha256']:
            raise ValueError('Native denial evidence changed')
        verify_denial(case, json.loads(proof_path.read_text()), kind)
        if not receipt['expected_installation_denial'] or receipt['level'] != 'native-bootstrap-tested':
            raise ValueError('A refusal cannot certify successful native enrollment')
        return receipt
    guest_path = folder / 'guest-report.json'
    if digest(guest_path) != receipt['guest_report_sha256']:
        raise ValueError('Native model evidence changed')
    guest = json.loads(guest_path.read_text())
    initial, final = guest['initial_statuses'], guest['final_statuses']
    verify_initial(initial)
    if set(initial) != set(final) or set(initial) != {'mother', 'offshoot-1', 'offshoot-2', 'sprout-4'}:
        raise ValueError('Native membership changed after acceptance')
    before, after = initial['sprout-4'], final['sprout-4']
    if (before['native_boot_id'] == after['native_boot_id'] or before['public_identity'] != after['public_identity']
            or after['uid'] != 1000 or before['uid'] != 1000
            or os_id(after['native_os_release']) != {'ubuntu': 'ubuntu', 'coreos': 'fedora', 'debian': 'debian', 'fedora': 'fedora', 'opensuse': 'opensuse-leap'}[kind]):
        raise ValueError('Native cold boot, platform or identity continuity is missing')
    installed = guest['installed']
    if any(installed['initial_absence'].values()) or installed['ssh_used'] or installed['systemd_enabled'] != 'enabled':
        raise ValueError('Native target was prepopulated or did not install its persistent service')
    if not installed['duplicate']['duplicate'] or installed['duplicate']['process'] != installed['installed']['process']:
        raise ValueError('Duplicate native installation started another process')
    if case == 'resume' and not installed['installed']['downloads'][0]['resumed']:
        raise ValueError('Native interrupted model transfer did not resume')
    challenge = guest['post_reboot_challenge']
    hello, reply = challenge['hello'], challenge['reply']
    if challenge['tls']['version'] != 'TLSv1.3' or reply['reply_to'] != hello['id']:
        raise ValueError('Post-reboot challenge authentication/correlation is missing')
    additions = {}
    for name in initial:
        old = {row['id']: row for row in initial[name]['calls']}
        new = {row['id']: row for row in final[name]['calls']}
        if any(new.get(ident) != row for ident, row in old.items()):
            raise ValueError('Native reboot changed or replayed a previous model call')
        for ident in new.keys() - old.keys():
            if ident in additions:
                raise ValueError('Duplicate post-reboot model call')
            additions[ident] = (name, new[ident])
    if set(additions) != {hello['id'], reply['id']}:
        raise ValueError('Native post-reboot model call count is not exactly two')
    for message, actor in ((hello, 'mother'), (reply, 'sprout-4')):
        name, row = additions[message['id']]
        proof = row['proof']
        if (name != actor or row['state'] != 'ready' or proof['text'] != message['text']
                or proof['call_id'] != message['id'] or proof['completion_tokens'] < 1
                or json.loads(proof['raw_content']) != {'text': message['text']}
                or proof['text_sha256'] != hashlib.sha256(proof['text'].encode()).hexdigest()
                or proof['prompt_sha256'] != hashlib.sha256(proof['prompt'].encode()).hexdigest()):
            raise ValueError('Fresh post-reboot reply is not actual, pinned inference')
    proof = additions[reply['id']][1]['proof']
    if proof['source_message_id'] != hello['id'] or json.dumps(hello['text']) not in proof['prompt']:
        raise ValueError('Fresh model reply did not consume the received challenge')
    if hello not in after['received']:
        raise ValueError('Fresh challenge has no target receipt')
    return receipt
